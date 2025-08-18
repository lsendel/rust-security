use dashmap::DashMap;
use futures::future::{BoxFuture, FutureExt};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::timeout;
use tracing::{debug, error, info, warn, Instrument};

/// Configuration for async operation optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncConfig {
    /// Maximum concurrent security operations
    pub max_concurrent_operations: usize,
    /// Default timeout for security operations
    pub default_timeout: Duration,
    /// Maximum retry attempts for failed operations
    pub max_retry_attempts: u32,
    /// Base delay for exponential backoff
    pub base_retry_delay: Duration,
    /// Maximum delay for exponential backoff
    pub max_retry_delay: Duration,
    /// Enable operation batching
    pub enable_batching: bool,
    /// Batch size for operations
    pub batch_size: usize,
    /// Batch timeout
    pub batch_timeout: Duration,
}

impl Default for AsyncConfig {
    fn default() -> Self {
        Self {
            max_concurrent_operations: 1000,
            default_timeout: Duration::from_secs(30),
            max_retry_attempts: 3,
            base_retry_delay: Duration::from_millis(100),
            max_retry_delay: Duration::from_secs(10),
            enable_batching: true,
            batch_size: 50,
            batch_timeout: Duration::from_millis(100),
        }
    }
}

/// Async operation result with detailed metrics
#[derive(Debug, Clone)]
pub struct AsyncOperationResult<T> {
    pub result: Result<T, AsyncError>,
    pub duration: Duration,
    pub retry_count: u32,
    pub operation_id: String,
}

/// Enhanced error type for async operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum AsyncError {
    #[error("Operation timeout after {duration:?}")]
    Timeout { duration: Duration },
    #[error("Rate limit exceeded")]
    RateLimit,
    #[error("Circuit breaker open")]
    CircuitBreakerOpen,
    #[error("Semaphore acquisition failed")]
    SemaphoreError,
    #[error("Operation failed: {message}")]
    OperationFailed { message: String },
    #[error("Batch operation failed: {message}")]
    BatchFailed { message: String },
}

/// Performance metrics for async operations
#[derive(Debug, Clone, Serialize)]
pub struct AsyncMetrics {
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub timeout_operations: u64,
    pub avg_duration: Duration,
    pub max_duration: Duration,
    pub min_duration: Duration,
    pub operations_per_second: f64,
    pub current_concurrent_operations: usize,
    pub max_concurrent_operations_reached: usize,
}

/// Batch operation for grouping related async calls
#[derive(Debug)]
pub struct BatchOperation<T> {
    pub operation_id: String,
    pub future: BoxFuture<'static, Result<T, AsyncError>>,
    pub created_at: Instant,
}

/// High-performance async executor optimized for security operations
pub struct AsyncSecurityExecutor {
    config: AsyncConfig,
    semaphore: Arc<Semaphore>,
    metrics: Arc<RwLock<AsyncMetrics>>,
    active_operations: Arc<DashMap<String, Instant>>,
    batch_queue: Arc<Mutex<Vec<BatchOperation<String>>>>,
    batch_processor_handle: Option<tokio::task::JoinHandle<()>>,
}

impl AsyncSecurityExecutor {
    /// Create a new async security executor
    pub fn new(config: AsyncConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_operations));
        let metrics = Arc::new(RwLock::new(AsyncMetrics {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            timeout_operations: 0,
            avg_duration: Duration::ZERO,
            max_duration: Duration::ZERO,
            min_duration: Duration::MAX,
            operations_per_second: 0.0,
            current_concurrent_operations: 0,
            max_concurrent_operations_reached: 0,
        }));

        let mut executor = Self {
            config: config.clone(),
            semaphore,
            metrics,
            active_operations: Arc::new(DashMap::new()),
            batch_queue: Arc::new(Mutex::new(Vec::new())),
            batch_processor_handle: None,
        };

        // Start batch processor if batching is enabled
        if config.enable_batching {
            executor.start_batch_processor();
        }

        executor
    }

    /// Execute a security operation with timeout, retry, and concurrency control
    pub async fn execute_operation<F, T>(&self, operation: F) -> AsyncOperationResult<T>
    where
        F: Future<Output = Result<T, AsyncError>> + Send + 'static,
        T: Send + 'static,
    {
        let operation_id = uuid::Uuid::new_v4().to_string();
        let start_time = Instant::now();

        self.active_operations.insert(operation_id.clone(), start_time);

        let result = self.execute_with_retry(operation, &operation_id).await;
        let duration = start_time.elapsed();

        self.active_operations.remove(&operation_id);
        self.update_metrics(duration, result.is_ok()).await;

        AsyncOperationResult {
            result,
            duration,
            retry_count: 0, // This would be tracked in execute_with_retry
            operation_id,
        }
    }

    /// Execute operation with automatic retry and exponential backoff
    async fn execute_with_retry<F, T>(
        &self,
        operation: F,
        operation_id: &str,
    ) -> Result<T, AsyncError>
    where
        F: Future<Output = Result<T, AsyncError>> + Send + 'static,
        T: Send + 'static,
    {
        let mut retry_count = 0;
        let mut delay = self.config.base_retry_delay;

        loop {
            // Acquire semaphore permit for concurrency control
            let _permit = self.semaphore.acquire().await.map_err(|_| AsyncError::SemaphoreError)?;

            // Update concurrent operations metric
            let current_permits =
                self.config.max_concurrent_operations - self.semaphore.available_permits();
            {
                let mut metrics = self.metrics.write().await;
                metrics.current_concurrent_operations = current_permits;
                metrics.max_concurrent_operations_reached =
                    metrics.max_concurrent_operations_reached.max(current_permits);
            }

            // Execute operation with timeout
            let operation_future = operation;
            let timeout_result = timeout(
                self.config.default_timeout,
                operation_future.instrument(tracing::span!(
                    tracing::Level::DEBUG,
                    "security_operation",
                    operation_id
                )),
            )
            .await;

            match timeout_result {
                Ok(Ok(result)) => {
                    debug!("Security operation {} completed successfully", operation_id);
                    return Ok(result);
                }
                Ok(Err(error)) => {
                    warn!("Security operation {} failed: {:?}", operation_id, error);

                    // Check if we should retry
                    if retry_count >= self.config.max_retry_attempts {
                        return Err(error);
                    }

                    // Don't retry certain errors
                    match error {
                        AsyncError::RateLimit | AsyncError::CircuitBreakerOpen => {
                            return Err(error)
                        }
                        _ => {}
                    }

                    retry_count += 1;

                    // Wait with exponential backoff
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(self.config.max_retry_delay);

                    debug!(
                        "Retrying security operation {} (attempt {})",
                        operation_id, retry_count
                    );
                }
                Err(_) => {
                    error!(
                        "Security operation {} timed out after {:?}",
                        operation_id, self.config.default_timeout
                    );
                    return Err(AsyncError::Timeout { duration: self.config.default_timeout });
                }
            }
        }
    }

    /// Execute multiple operations concurrently with optimal batching
    pub async fn execute_batch<F, T>(&self, operations: Vec<F>) -> Vec<AsyncOperationResult<T>>
    where
        F: Future<Output = Result<T, AsyncError>> + Send + 'static,
        T: Send + 'static,
    {
        let start_time = Instant::now();
        info!("Executing batch of {} security operations", operations.len());

        // Split operations into optimal batch sizes
        let mut results = Vec::with_capacity(operations.len());
        let chunk_size = self.config.batch_size.min(operations.len());

        for chunk in operations.chunks(chunk_size) {
            let mut batch_futures = Vec::new();

            for operation in chunk {
                let executor = self.clone();
                let future =
                    tokio::spawn(async move { executor.execute_operation(operation).await });
                batch_futures.push(future);
            }

            // Wait for batch completion
            for future in batch_futures {
                match future.await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        results.push(AsyncOperationResult {
                            result: Err(AsyncError::OperationFailed {
                                message: format!("Task join error: {}", e),
                            }),
                            duration: Duration::ZERO,
                            retry_count: 0,
                            operation_id: "failed_batch_operation".to_string(),
                        });
                    }
                }
            }
        }

        let total_duration = start_time.elapsed();
        info!("Batch execution completed in {:?}", total_duration);

        results
    }

    /// Execute operations with streaming results for better memory efficiency
    pub async fn execute_streaming<F, T, I>(
        &self,
        operations: I,
    ) -> impl futures::Stream<Item = AsyncOperationResult<T>>
    where
        F: Future<Output = Result<T, AsyncError>> + Send + 'static,
        T: Send + 'static,
        I: IntoIterator<Item = F>,
    {
        use futures::stream::{self, StreamExt};

        let operations_vec: Vec<_> = operations.into_iter().collect();
        let stream = stream::iter(operations_vec)
            .map(|operation| {
                let executor = self.clone();
                async move { executor.execute_operation(operation).await }
            })
            .buffer_unordered(self.config.max_concurrent_operations);

        stream
    }

    /// Execute operation with custom timeout
    pub async fn execute_with_timeout<F, T>(
        &self,
        operation: F,
        custom_timeout: Duration,
    ) -> AsyncOperationResult<T>
    where
        F: Future<Output = Result<T, AsyncError>> + Send + 'static,
        T: Send + 'static,
    {
        let operation_id = uuid::Uuid::new_v4().to_string();
        let start_time = Instant::now();

        self.active_operations.insert(operation_id.clone(), start_time);

        let _permit = match self.semaphore.acquire().await {
            Ok(permit) => permit,
            Err(_) => {
                let duration = start_time.elapsed();
                self.active_operations.remove(&operation_id);
                return AsyncOperationResult {
                    result: Err(AsyncError::SemaphoreError),
                    duration,
                    retry_count: 0,
                    operation_id,
                };
            }
        };

        let result = match timeout(custom_timeout, operation).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(AsyncError::Timeout { duration: custom_timeout }),
        };

        let duration = start_time.elapsed();
        self.active_operations.remove(&operation_id);
        self.update_metrics(duration, result.is_ok()).await;

        AsyncOperationResult { result, duration, retry_count: 0, operation_id }
    }

    /// Add operation to batch queue for processing
    pub async fn queue_batch_operation<F>(&self, operation: F) -> Result<String, AsyncError>
    where
        F: Future<Output = Result<String, AsyncError>> + Send + 'static,
    {
        if !self.config.enable_batching {
            return Err(AsyncError::OperationFailed {
                message: "Batching is disabled".to_string(),
            });
        }

        let operation_id = uuid::Uuid::new_v4().to_string();
        let batch_op = BatchOperation {
            operation_id: operation_id.clone(),
            future: operation.boxed(),
            created_at: Instant::now(),
        };

        {
            let mut queue = self.batch_queue.lock().await;
            queue.push(batch_op);
        }

        Ok(operation_id)
    }

    /// Start the batch processor for handling queued operations
    fn start_batch_processor(&mut self) {
        let batch_queue = self.batch_queue.clone();
        let config = self.config.clone();
        let metrics = self.metrics.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.batch_timeout);

            loop {
                interval.tick().await;

                let mut queue = batch_queue.lock().await;
                if queue.is_empty() {
                    continue;
                }

                // Process batch
                let batch: Vec<_> = queue.drain(..).collect();
                drop(queue); // Release lock early

                if batch.len() >= config.batch_size
                    || batch.iter().any(|op| op.created_at.elapsed() > config.batch_timeout)
                {
                    info!("Processing batch of {} operations", batch.len());

                    let futures: Vec<_> = batch.into_iter().map(|op| op.future).collect();

                    let results = futures::future::join_all(futures).await;

                    // Update metrics
                    let mut metrics_guard = metrics.write().await;
                    for result in results {
                        metrics_guard.total_operations += 1;
                        match result {
                            Ok(_) => metrics_guard.successful_operations += 1,
                            Err(_) => metrics_guard.failed_operations += 1,
                        }
                    }
                }
            }
        });

        self.batch_processor_handle = Some(handle);
    }

    /// Get current async operation metrics
    pub async fn get_metrics(&self) -> AsyncMetrics {
        let metrics = self.metrics.read().await;
        let mut result = metrics.clone();

        // Update real-time metrics
        result.current_concurrent_operations =
            self.config.max_concurrent_operations - self.semaphore.available_permits();

        // Calculate operations per second
        if result.avg_duration.as_secs_f64() > 0.0 {
            result.operations_per_second = 1.0 / result.avg_duration.as_secs_f64();
        }

        result
    }

    /// Get list of currently active operations
    pub async fn get_active_operations(&self) -> Vec<(String, Duration)> {
        let now = Instant::now();
        self.active_operations
            .iter()
            .map(|entry| (entry.key().clone(), now.duration_since(*entry.value())))
            .collect()
    }

    /// Cancel all active operations (graceful shutdown)
    pub async fn shutdown(&self) {
        info!("Shutting down async security executor");

        // Wait for active operations to complete or timeout
        let shutdown_timeout = Duration::from_secs(30);
        let start = Instant::now();

        while !self.active_operations.is_empty() && start.elapsed() < shutdown_timeout {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if let Some(handle) = &self.batch_processor_handle {
            handle.abort();
        }

        info!("Async security executor shutdown completed");
    }

    /// Update performance metrics
    async fn update_metrics(&self, duration: Duration, success: bool) {
        let mut metrics = self.metrics.write().await;

        metrics.total_operations += 1;
        if success {
            metrics.successful_operations += 1;
        } else {
            metrics.failed_operations += 1;
        }

        // Update duration statistics
        if duration > metrics.max_duration {
            metrics.max_duration = duration;
        }
        if duration < metrics.min_duration {
            metrics.min_duration = duration;
        }

        // Calculate new average duration
        let total_ops = metrics.total_operations;
        if total_ops > 0 {
            let current_avg_nanos = metrics.avg_duration.as_nanos() as u64;
            let new_avg_nanos =
                ((current_avg_nanos * (total_ops - 1)) + duration.as_nanos() as u64) / total_ops;
            metrics.avg_duration = Duration::from_nanos(new_avg_nanos);
        }
    }
}

impl Clone for AsyncSecurityExecutor {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            semaphore: self.semaphore.clone(),
            metrics: self.metrics.clone(),
            active_operations: self.active_operations.clone(),
            batch_queue: self.batch_queue.clone(),
            batch_processor_handle: None, // Don't clone the processor handle
        }
    }
}

/// Utility functions for common async security patterns

/// Execute security validation pipeline with fail-fast behavior
pub async fn execute_security_pipeline<T>(
    operations: Vec<Pin<Box<dyn Future<Output = Result<T, AsyncError>> + Send>>>,
) -> Result<Vec<T>, AsyncError> {
    let mut results = Vec::with_capacity(operations.len());

    for operation in operations {
        match operation.await {
            Ok(result) => results.push(result),
            Err(error) => return Err(error), // Fail fast on first error
        }
    }

    Ok(results)
}

/// Execute security operations with circuit breaker pattern
pub async fn execute_with_circuit_breaker<F, T>(
    operation: F,
    failure_threshold: u32,
    reset_timeout: Duration,
) -> Result<T, AsyncError>
where
    F: Future<Output = Result<T, AsyncError>>,
{
    // Simplified circuit breaker implementation
    // In production, you'd want to maintain state across calls

    match timeout(reset_timeout, operation).await {
        Ok(result) => result,
        Err(_) => Err(AsyncError::Timeout { duration: reset_timeout }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_executor_basic_operation() {
        let config = AsyncConfig::default();
        let executor = AsyncSecurityExecutor::new(config);

        let result = executor
            .execute_operation(async {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok::<String, AsyncError>("test_result".to_string())
            })
            .await;

        assert!(result.result.is_ok());
        assert_eq!(result.result.unwrap(), "test_result");
    }

    #[tokio::test]
    async fn test_async_executor_timeout() {
        let mut config = AsyncConfig::default();
        config.default_timeout = Duration::from_millis(50);
        let executor = AsyncSecurityExecutor::new(config);

        let result = executor
            .execute_operation(async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok::<String, AsyncError>("should_timeout".to_string())
            })
            .await;

        assert!(result.result.is_err());
        matches!(result.result.unwrap_err(), AsyncError::Timeout { .. });
    }

    #[tokio::test]
    async fn test_batch_execution() {
        let config = AsyncConfig::default();
        let executor = AsyncSecurityExecutor::new(config);

        let operations = vec![
            async { Ok::<String, AsyncError>("result1".to_string()) },
            async { Ok::<String, AsyncError>("result2".to_string()) },
            async { Ok::<String, AsyncError>("result3".to_string()) },
        ];

        let results = executor.execute_batch(operations).await;
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.result.is_ok()));
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let config = AsyncConfig::default();
        let executor = AsyncSecurityExecutor::new(config);

        // Execute some operations
        for _ in 0..5 {
            let _ = executor
                .execute_operation(async { Ok::<String, AsyncError>("test".to_string()) })
                .await;
        }

        let metrics = executor.get_metrics().await;
        assert_eq!(metrics.total_operations, 5);
        assert_eq!(metrics.successful_operations, 5);
        assert_eq!(metrics.failed_operations, 0);
    }
}
