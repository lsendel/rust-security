//! Async Performance Optimizations
//!
//! Implements high-performance async patterns for the authentication service:
//! - Concurrent request processing with bounded parallelism
//! - Smart batching for database operations
//! - Connection pooling optimization
//! - Memory-efficient stream processing
//! - Request deduplication and caching

use futures::stream::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::shared::error::AppError;

/// Configuration for async optimizations
#[derive(Debug, Clone)]
pub struct AsyncOptimizerConfig {
    /// Maximum concurrent operations
    pub max_concurrent_ops: usize,
    /// Batch size for database operations
    pub batch_size: usize,
    /// Batch timeout
    pub batch_timeout: Duration,
    /// Request deduplication window
    pub deduplication_window: Duration,
    /// Connection pool optimization enabled
    pub connection_pool_optimization: bool,
    /// Stream processing buffer size
    pub stream_buffer_size: usize,
}

impl Default for AsyncOptimizerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_ops: 1000,
            batch_size: 50,
            batch_timeout: Duration::from_millis(10),
            deduplication_window: Duration::from_millis(100),
            connection_pool_optimization: true,
            stream_buffer_size: 1000,
        }
    }
}

/// Async operation optimizer
pub struct AsyncOptimizer {
    config: AsyncOptimizerConfig,
    semaphore: Arc<Semaphore>,
    batch_processor: Arc<BatchProcessor>,
    request_deduplicator: Arc<RequestDeduplicator>,
    metrics: Arc<RwLock<AsyncMetrics>>,
}

#[derive(Debug, Clone, Default)]
pub struct AsyncMetrics {
    pub total_operations: u64,
    pub concurrent_operations: u64,
    pub batched_operations: u64,
    pub deduplicated_requests: u64,
    pub avg_operation_time: Duration,
    pub max_operation_time: Duration,
    pub failed_operations: u64,
}

impl AsyncOptimizer {
    /// Create a new async optimizer
    pub fn new(config: AsyncOptimizerConfig) -> Self {
        info!(
            "Creating async optimizer with max concurrent ops: {}",
            config.max_concurrent_ops
        );

        Self {
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_ops)),
            batch_processor: Arc::new(BatchProcessor::new(config.batch_size, config.batch_timeout)),
            request_deduplicator: Arc::new(RequestDeduplicator::new(config.deduplication_window)),
            metrics: Arc::new(RwLock::new(AsyncMetrics::default())),
            config,
        }
    }

    /// Execute an operation with concurrency control
    pub async fn execute_operation<F, Fut, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>, E: std::convert::From<std::string::String>
    {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| "Failed to acquire semaphore permit".to_string())?;

        let start_time = Instant::now();

        let result = operation().await;

        let operation_time = start_time.elapsed();

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.total_operations += 1;
        metrics.concurrent_operations = metrics
            .concurrent_operations
            .max((self.config.max_concurrent_ops - self.semaphore.available_permits()) as u64);

        if result.is_err() {
            metrics.failed_operations += 1;
        }

        // Update timing metrics
        let avg_nanos_u128 = ((metrics.avg_operation_time.as_nanos()
            * (metrics.total_operations - 1) as u128)
            + operation_time.as_nanos())
            / metrics.total_operations as u128;
        let avg_nanos_u64 = if avg_nanos_u128 > u64::MAX as u128 {
            u64::MAX
        } else {
            avg_nanos_u128 as u64
        };
        metrics.avg_operation_time = Duration::from_nanos(avg_nanos_u64);
        metrics.max_operation_time = metrics.max_operation_time.max(operation_time);

        result
    }

    /// Execute multiple operations concurrently with bounded parallelism
    pub async fn execute_concurrent<F, Fut, T, E>(&self, operations: Vec<F>) -> Vec<Result<T, E>>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T, E>> + Send,
        T: Send + 'static,
        E: Send + 'static + std::convert::From<std::string::String>,
    {
        let semaphore = Arc::clone(&self.semaphore);

        let tasks: Vec<_> = operations
            .into_iter()
            .enumerate()
            .map(|(i, op)| {
                let sem = Arc::clone(&semaphore);
                let metrics = Arc::clone(&self.metrics);

                tokio::spawn(async move {
                    let _permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => {
                            return (i, Err("Semaphore closed".to_string().into()), Duration::from_nanos(0));
                        }
                    };

                    let start_time = Instant::now();
                    let result = op().await;
                    let operation_time = start_time.elapsed();

                    // Update metrics
                    let mut metrics = metrics.write().await;
                    metrics.total_operations += 1;

                    if result.is_err() {
                        metrics.failed_operations += 1;
                    }

                    (i, result, operation_time)
                })
            })
            .collect();

        let mut results = vec![None; tasks.len()];

        for task in tasks {
            match task.await {
                Ok((index, result, _operation_time)) => {
                    results[index] = Some(result);
                }
                Err(e) => {
                    warn!("Task panicked: {}", e);
                    // Insert error for panicked task
                    results.push(Some(Err("Task panicked".to_string().into())));
                }
            }
        }

        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err("Task failed".to_string().into())))
            .collect()
    }

    /// Execute operations in batches for better performance
    pub async fn execute_batched<F, Fut, T, E>(&self, operations: Vec<F>) -> Result<Vec<T>, E>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T, E>> + Send,
        T: Send + 'static,
        E: Send + 'static,
    {
        self.batch_processor.process_batch(operations).await
    }

    /// Deduplicate requests to prevent redundant operations
    pub async fn deduplicate_request<F, Fut, T, E>(&self, key: String, operation: F) -> Result<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>, E: for<'de> <_>::_serde::Deserialize<'de>
    {
        if let Some(result) = self.request_deduplicator.get_cached_result(&key).await {
            let mut metrics = self.metrics.write().await;
            metrics.deduplicated_requests += 1;
            return result;
        }

        let result = self.execute_operation(operation).await?;
        self.request_deduplicator
            .cache_result(key, Ok(result.clone()))
            .await;
        Ok(result)
    }

    /// Process a stream of operations efficiently
    pub async fn process_stream<F, Fut, T, E, S>(&self, stream: S) -> Vec<Result<T, E>>
    where
        S: futures::Stream<Item = F> + Send,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        stream
            .map(|op| self.execute_operation(op))
            .buffered(self.config.stream_buffer_size)
            .collect()
            .await
    }

    /// Get current metrics
    pub async fn metrics(&self) -> AsyncMetrics {
        self.metrics.read().await.clone()
    }

    /// Get current concurrency level
    pub async fn current_concurrency(&self) -> usize {
        self.config.max_concurrent_ops - self.semaphore.available_permits()
    }
}

/// Batch processor for grouping operations
struct BatchProcessor {
    batch_size: usize,
    timeout: Duration,
}

impl BatchProcessor {
    fn new(batch_size: usize, timeout: Duration) -> Self {
        Self {
            batch_size,
            timeout,
        }
    }

    async fn process_batch<F, Fut, T, E>(&self, operations: Vec<F>) -> Result<Vec<T>, E>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<T, E>> + Send,
        T: Send + 'static,
        E: Send + 'static,
    {
        let mut results = Vec::with_capacity(operations.len());

        // Process operations in batches
        for chunk in operations.chunks(self.batch_size) {
            let batch_start = Instant::now();

            // Execute batch concurrently
            let batch_results = futures::future::join_all(chunk.iter().map(|op| op())).await;

            // Process results
            for result in batch_results {
                match result {
                    Ok(value) => results.push(value),
                    Err(e) => return Err(e),
                }
            }

            let batch_time = batch_start.elapsed();
            debug!(
                "Processed batch of {} operations in {:?}",
                chunk.len(),
                batch_time
            );

            // Small delay between batches to prevent overwhelming the system
            if batch_time < self.timeout {
                tokio::time::sleep(self.timeout - batch_time).await;
            }
        }

        Ok(results)
    }
}

/// Request deduplicator to prevent redundant operations
struct RequestDeduplicator {
    cache: Arc<RwLock<HashMap<String, (Instant, serde_json::Value)>>>,
    window: Duration,
}

impl RequestDeduplicator {
    fn new(window: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            window,
        }
    }

    async fn get_cached_result<T, E>(&self, key: &str) -> Option<Result<T, E>>
    where
        T: for<'de> serde::Deserialize<'de>,
        E: for<'de> serde::Deserialize<'de>,
    {
        let cache = self.cache.read().await;

        if let Some((timestamp, value)) = cache.get(key) {
            if timestamp.elapsed() < self.window {
                // Try to deserialize the cached result
                if let Ok(result) = serde_json::from_value(value.clone()) {
                    return Some(result);
                }
            }
        }

        None
    }

    async fn cache_result<T, E>(&self, key: String, result: Result<T, E>)
    where
        T: serde::Serialize,
        E: serde::Serialize,
    {
        let value = serde_json::to_value(&result).unwrap_or(serde_json::Value::Null);

        let mut cache = self.cache.write().await;
        cache.insert(key, (Instant::now(), value));

        // Clean up expired entries
        cache.retain(|_, (timestamp, _)| timestamp.elapsed() < self.window);
    }
}

/// High-performance user authentication service with optimizations
pub struct OptimizedAuthService {
    optimizer: Arc<AsyncOptimizer>,
    user_cache: Arc<RwLock<HashMap<String, (Instant, serde_json::Value)>>>,
}

impl OptimizedAuthService {
    pub fn new(optimizer: Arc<AsyncOptimizer>) -> Self {
        Self {
            optimizer,
            user_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Authenticate user with optimizations
    pub async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<bool, AppError> {
        let cache_key = format!("auth:{}:{}", username, Uuid::new_v4()); // Add nonce to prevent timing attacks

        self.optimizer
            .deduplicate_request(cache_key, || async {
                // Simulate authentication logic
                tokio::time::sleep(Duration::from_millis(10)).await; // Simulate DB lookup
                Ok(username.len() > 3 && password.len() > 6) // Simple validation
            })
            .await
    }

    /// Batch authenticate multiple users
    pub async fn batch_authenticate(
        &self,
        credentials: Vec<(String, String)>,
    ) -> Result<Vec<bool>, AppError> {
        let operations: Vec<_> = credentials
            .into_iter()
            .map(|(username, password)| {
                let optimizer = Arc::clone(&self.optimizer);
                move || {
                    let username = username.clone();
                    let password = password.clone();
                    async move {
                        optimizer
                            .execute_operation(|| async {
                                // Simulate authentication
                                tokio::time::sleep(Duration::from_millis(5)).await;
                                Ok(username.len() > 3 && password.len() > 6)
                            })
                            .await
                    }
                }
            })
            .collect();

        self.optimizer.execute_batched(operations).await
    }

    /// Get service metrics
    pub async fn metrics(&self) -> AsyncMetrics {
        self.optimizer.metrics().await
    }
}

/// Stream processing utilities for high-throughput scenarios
pub mod stream_utils {
    use super::*;
    use futures::stream::Stream;

    /// Process authentication requests as a stream
    pub async fn process_auth_stream(
        optimizer: Arc<AsyncOptimizer>,
        requests: impl Stream<Item = (String, String)> + Send,
    ) -> Vec<Result<bool, AppError>> {
        optimizer
            .process_stream(requests.map(move |(username, password)| {
                let opt = Arc::clone(&optimizer);
                move || {
                    let username = username.clone();
                    let password = password.clone();
                    async move {
                        opt.deduplicate_request(
                            format!("auth_stream:{}:{}", username, Uuid::new_v4()),
                            || async {
                                tokio::time::sleep(Duration::from_millis(5)).await;
                                Ok(username.len() > 3 && password.len() > 6)
                            },
                        )
                        .await
                    }
                }
            }))
            .await
    }

    /// Create a buffered stream processor
    pub fn create_buffered_processor<T, F, Fut>(
        processor: F,
        buffer_size: usize,
    ) -> impl FnMut(T) -> JoinHandle<Fut::Output>
    where
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future + Send + 'static,
        Fut::Output: Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(buffer_size);

        tokio::spawn(async move {
            rx.map(|item| processor(item))
                .buffered(buffer_size)
                .collect::<Vec<_>>()
                .await
        });

        move |item: T| {
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(item).await;
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_optimizer_basic_operation() {
        let config = AsyncOptimizerConfig {
            max_concurrent_ops: 10,
            ..Default::default()
        };

        let optimizer = AsyncOptimizer::new(config);

        let result = optimizer
            .execute_operation(|| async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok::<_, String>("success".to_string())
            })
            .await;

        assert_eq!(result, Ok("success".to_string()));

        let metrics = optimizer.metrics().await;
        assert_eq!(metrics.total_operations, 1);
        assert_eq!(metrics.failed_operations, 0);
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let config = AsyncOptimizerConfig {
            max_concurrent_ops: 5,
            ..Default::default()
        };

        let optimizer = AsyncOptimizer::new(config);

        let operations: Vec<_> = (0..10)
            .map(|i| {
                move || async move {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    Ok::<_, String>(format!("result_{}", i))
                }
            })
            .collect();

        let results = optimizer.execute_concurrent(operations).await;

        assert_eq!(results.len(), 10);
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result, &Ok(format!("result_{}", i)));
        }
    }

    #[tokio::test]
    async fn test_request_deduplication() {
        let config = AsyncOptimizerConfig::default();
        let optimizer = AsyncOptimizer::new(config);

        let key = "test_key".to_string();
        let mut call_count = 0;

        // First call
        let result1 = optimizer
            .deduplicate_request(key.clone(), || async {
                call_count += 1;
                tokio::time::sleep(Duration::from_millis(5)).await;
                Ok::<_, String>("result".to_string())
            })
            .await;

        // Second call (should be deduplicated)
        let result2 = optimizer
            .deduplicate_request(key.clone(), || async {
                call_count += 1;
                Ok::<_, String>("result2".to_string())
            })
            .await;

        assert_eq!(result1, Ok("result".to_string()));
        assert_eq!(result2, Ok("result".to_string()));
        assert_eq!(call_count, 1); // Only one actual call should have been made

        let metrics = optimizer.metrics().await;
        assert_eq!(metrics.deduplicated_requests, 1);
    }

    #[tokio::test]
    async fn test_batch_processing() {
        let config = AsyncOptimizerConfig {
            batch_size: 3,
            ..Default::default()
        };

        let optimizer = AsyncOptimizer::new(config);

        let operations: Vec<_> = (0..9)
            .map(|i| {
                move || async move {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    Ok::<_, String>(format!("batch_result_{}", i))
                }
            })
            .collect();

        let results = optimizer.execute_batched(operations).await.unwrap();

        assert_eq!(results.len(), 9);
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result, &format!("batch_result_{}", i));
        }

        let metrics = optimizer.metrics().await;
        assert_eq!(metrics.batched_operations, 9);
    }

    #[tokio::test]
    async fn test_concurrency_limits() {
        let config = AsyncOptimizerConfig {
            max_concurrent_ops: 2,
            ..Default::default()
        };

        let optimizer = AsyncOptimizer::new(config);

        // Test that concurrency is limited
        let start_time = Instant::now();

        let operations: Vec<_> = (0..4)
            .map(|_| {
                || async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok::<_, String>("done".to_string())
                }
            })
            .collect();

        let _results = optimizer.execute_concurrent(operations).await;

        let total_time = start_time.elapsed();

        // With concurrency limit of 2, this should take at least 100ms (2 batches of 50ms each)
        assert!(total_time >= Duration::from_millis(90));
    }
}
#![deny(clippy::unwrap_used, clippy::expect_used)]
