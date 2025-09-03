//! Performance Optimization Module
//!
//! This module provides comprehensive performance optimization utilities
//! and patterns for the Rust Security Platform, focusing on high-throughput
//! scenarios while maintaining security guarantees.
//!
//! ## Optimization Strategies
//!
//! ### 1. Memory Pool Management
//! - Object pooling for frequently allocated structures
//! - Custom allocators for security-critical paths
//! - Memory layout optimization for cache efficiency
//!
//! ### 2. Lock Contention Reduction
//! - Read-write lock optimization
//! - Lock-free data structures where appropriate
//! - Granular locking strategies
//!
//! ### 3. Async Optimization
//! - Task scheduling optimization
//! - Connection pooling and reuse
//! - Streaming processing for large datasets
//!
//! ### 4. Algorithm Optimization
//! - Efficient data structures (HashMap vs BTreeMap)
//! - Optimized string operations
//! - Cryptographic operation batching

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info, warn};

// Re-export optimization utilities
pub mod memory_pool;
pub mod async_optimization;
pub mod lock_optimization;

/// Memory pool for frequently allocated objects
pub mod memory_pool {
    use super::*;

    /// Generic object pool for expensive-to-create objects
    pub struct ObjectPool<T, F>
    where
        T: Send + Sync,
        F: Fn() -> T + Send + Sync,
    {
        pool: Arc<RwLock<VecDeque<T>>>,
        factory: F,
        max_size: usize,
        created_count: std::sync::atomic::AtomicUsize,
    }

    impl<T, F> ObjectPool<T, F>
    where
        T: Send + Sync,
        F: Fn() -> T + Send + Sync,
    {
        /// Create a new object pool
        pub fn new(factory: F, initial_size: usize, max_size: usize) -> Self {
            let mut pool = VecDeque::with_capacity(initial_size);

            // Pre-populate the pool
            for _ in 0..initial_size {
                pool.push_back(factory());
            }

            Self {
                pool: Arc::new(RwLock::new(pool)),
                factory,
                max_size,
                created_count: std::sync::atomic::AtomicUsize::new(initial_size),
            }
        }

        /// Acquire an object from the pool
        pub async fn acquire(&self) -> PooledObject<T> {
            let mut pool = self.pool.write().await;

            if let Some(obj) = pool.pop_front() {
                PooledObject {
                    object: Some(obj),
                    pool: self.pool.clone(),
                }
            } else {
                // Pool is empty, create new object if under limit
                let created = self.created_count.load(std::sync::atomic::Ordering::SeqCst);
                if created < self.max_size {
                    self.created_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let obj = (self.factory)();
                    PooledObject {
                        object: Some(obj),
                        pool: self.pool.clone(),
                    }
                } else {
                    // Pool is at max capacity, wait for an object to be returned
                    drop(pool);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    self.acquire().await
                }
            }
        }

        /// Get pool statistics
        pub async fn stats(&self) -> PoolStats {
            let pool = self.pool.read().await;
            PoolStats {
                available: pool.len(),
                created: self.created_count.load(std::sync::atomic::Ordering::SeqCst),
                max_size: self.max_size,
            }
        }
    }

    /// RAII wrapper for pooled objects
    pub struct PooledObject<T> {
        object: Option<T>,
        pool: Arc<RwLock<VecDeque<T>>>,
    }

    impl<T> PooledObject<T> {
        /// Get mutable reference to the pooled object
        pub fn as_mut(&mut self) -> &mut T {
            self.object.as_mut().expect("Pooled object should be available")
        }

        /// Get immutable reference to the pooled object
        pub fn as_ref(&self) -> &T {
            self.object.as_ref().expect("Pooled object should be available")
        }
    }

    impl<T> Drop for PooledObject<T> {
        fn drop(&mut self) {
            if let Some(obj) = self.object.take() {
                let pool = self.pool.clone();
                tokio::spawn(async move {
                    let mut pool = pool.write().await;
                    pool.push_back(obj);
                });
            }
        }
    }

    /// Pool statistics
    #[derive(Debug, Clone)]
    pub struct PoolStats {
        pub available: usize,
        pub created: usize,
        pub max_size: usize,
    }

    /// Specialized pool for database connections
    pub type DbConnectionPool = ObjectPool<tokio_postgres::Client, Box<dyn Fn() -> tokio_postgres::Client + Send + Sync>>;

    /// Specialized pool for Redis connections
    pub type RedisConnectionPool = ObjectPool<redis::aio::Connection, Box<dyn Fn() -> redis::aio::Connection + Send + Sync>>;
}

/// Async optimization utilities
pub mod async_optimization {
    use super::*;

    /// Adaptive batch processor for optimizing throughput
    pub struct AdaptiveBatchProcessor<T, F, Fut>
    where
        T: Send + Sync,
        F: Fn(Vec<T>) -> Fut + Send + Sync + Clone,
        Fut: std::future::Future<Output = Result<(), String>> + Send,
    {
        buffer: Arc<RwLock<Vec<T>>>,
        processor: F,
        max_batch_size: usize,
        max_wait_time: Duration,
        semaphore: Arc<Semaphore>,
    }

    impl<T, F, Fut> AdaptiveBatchProcessor<T, F, Fut>
    where
        T: Send + Sync,
        F: Fn(Vec<T>) -> Fut + Send + Sync + Clone,
        Fut: std::future::Future<Output = Result<(), String>> + Send,
    {
        /// Create a new adaptive batch processor
        pub fn new(
            processor: F,
            max_batch_size: usize,
            max_wait_time: Duration,
            max_concurrent_batches: usize,
        ) -> Self {
            Self {
                buffer: Arc::new(RwLock::new(Vec::with_capacity(max_batch_size))),
                processor,
                max_batch_size,
                max_wait_time,
                semaphore: Arc::new(Semaphore::new(max_concurrent_batches)),
            }
        }

        /// Add an item to the batch
        pub async fn add_item(&self, item: T) -> Result<(), String> {
            let mut buffer = self.buffer.write().await;
            buffer.push(item);

            if buffer.len() >= self.max_batch_size {
                let batch = buffer.drain(..).collect::<Vec<_>>();
                drop(buffer); // Release the lock before processing
                self.process_batch(batch).await
            } else {
                Ok(())
            }
        }

        /// Force processing of current batch
        pub async fn flush(&self) -> Result<(), String> {
            let mut buffer = self.buffer.write().await;
            if !buffer.is_empty() {
                let batch = buffer.drain(..).collect::<Vec<_>>();
                drop(buffer);
                self.process_batch(batch).await
            } else {
                Ok(())
            }
        }

        async fn process_batch(&self, batch: Vec<T>) -> Result<(), String> {
            let _permit = self.semaphore.acquire().await
                .map_err(|e| format!("Failed to acquire processing permit: {}", e))?;

            let processor = self.processor.clone();
            tokio::spawn(async move {
                if let Err(e) = processor(batch).await {
                    warn!("Batch processing failed: {}", e);
                }
            });

            Ok(())
        }
    }

    /// Streaming processor for large datasets
    pub struct StreamingProcessor<T, F>
    where
        T: Send + Sync,
        F: Fn(T) -> Result<(), String> + Send + Sync,
    {
        processor: F,
        buffer_size: usize,
        _phantom: std::marker::PhantomData<T>,
    }

    impl<T, F> StreamingProcessor<T, F>
    where
        T: Send + Sync,
        F: Fn(T) -> Result<(), String> + Send + Sync,
    {
        pub fn new(processor: F, buffer_size: usize) -> Self {
            Self {
                processor,
                buffer_size,
                _phantom: std::marker::PhantomData,
            }
        }

        pub async fn process_stream<I>(&self, items: I) -> Result<ProcessingStats, String>
        where
            I: IntoIterator<Item = T>,
            I::IntoIter: Send + 'static,
        {
            let start_time = Instant::now();
            let mut processed = 0;
            let mut errors = 0;

            let processor = &self.processor;
            let buffer_size = self.buffer_size;

            // Process items in chunks to avoid overwhelming the system
            let items: Vec<_> = items.into_iter().collect();
            let chunks = items.chunks(buffer_size);

            for chunk in chunks {
                let mut tasks = Vec::new();

                for item in chunk {
                    let processor = processor.clone();
                    let task = tokio::spawn(async move {
                        processor(item)
                    });
                    tasks.push(task);
                }

                // Wait for all tasks in this chunk to complete
                for task in tasks {
                    match task.await {
                        Ok(Ok(())) => processed += 1,
                        Ok(Err(e)) => {
                            warn!("Item processing failed: {}", e);
                            errors += 1;
                        }
                        Err(e) => {
                            warn!("Task join failed: {}", e);
                            errors += 1;
                        }
                    }
                }
            }

            let duration = start_time.elapsed();

            Ok(ProcessingStats {
                total_processed: processed,
                errors,
                duration,
                throughput: processed as f64 / duration.as_secs_f64(),
            })
        }
    }

    /// Processing statistics
    #[derive(Debug, Clone)]
    pub struct ProcessingStats {
        pub total_processed: usize,
        pub errors: usize,
        pub duration: Duration,
        pub throughput: f64,
    }
}

/// Lock contention optimization utilities
pub mod lock_optimization {
    use super::*;

    /// Read-optimized concurrent hash map
    pub struct ReadOptimizedMap<K, V>
    where
        K: Eq + std::hash::Hash + Clone + Send + Sync,
        V: Clone + Send + Sync,
    {
        shards: Vec<Arc<RwLock<HashMap<K, V>>>>,
        shard_count: usize,
    }

    impl<K, V> ReadOptimizedMap<K, V>
    where
        K: Eq + std::hash::Hash + Clone + Send + Sync,
        V: Clone + Send + Sync,
    {
        /// Create a new read-optimized map
        pub fn new(shard_count: usize) -> Self {
            let mut shards = Vec::with_capacity(shard_count);
            for _ in 0..shard_count {
                shards.push(Arc::new(RwLock::new(HashMap::new())));
            }

            Self {
                shards,
                shard_count,
            }
        }

        /// Get the shard index for a key
        fn get_shard_index(&self, key: &K) -> usize {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            key.hash(&mut hasher);
            (hasher.finish() % self.shard_count as u64) as usize
        }

        /// Get a value by key
        pub async fn get(&self, key: &K) -> Option<V> {
            let shard_index = self.get_shard_index(key);
            let shard = &self.shards[shard_index];
            let map = shard.read().await;
            map.get(key).cloned()
        }

        /// Insert a key-value pair
        pub async fn insert(&self, key: K, value: V) -> Option<V> {
            let shard_index = self.get_shard_index(&key);
            let shard = &self.shards[shard_index];
            let mut map = shard.write().await;
            map.insert(key, value)
        }

        /// Remove a key-value pair
        pub async fn remove(&self, key: &K) -> Option<V> {
            let shard_index = self.get_shard_index(key);
            let shard = &self.shards[shard_index];
            let mut map = shard.write().await;
            map.remove(key)
        }

        /// Get approximate size (not thread-safe for precision)
        pub async fn approximate_size(&self) -> usize {
            let mut total = 0;
            for shard in &self.shards {
                let map = shard.read().await;
                total += map.len();
            }
            total
        }
    }

    /// Lock-free statistics accumulator
    pub struct LockFreeStats {
        hits: std::sync::atomic::AtomicU64,
        misses: std::sync::atomic::AtomicU64,
        total_requests: std::sync::atomic::AtomicU64,
    }

    impl LockFreeStats {
        pub fn new() -> Self {
            Self {
                hits: std::sync::atomic::AtomicU64::new(0),
                misses: std::sync::atomic::AtomicU64::new(0),
                total_requests: std::sync::atomic::AtomicU64::new(0),
            }
        }

        pub fn record_hit(&self) {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        pub fn record_miss(&self) {
            self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        pub fn get_stats(&self) -> StatsSnapshot {
            StatsSnapshot {
                hits: self.hits.load(std::sync::atomic::Ordering::Relaxed),
                misses: self.misses.load(std::sync::atomic::Ordering::Relaxed),
                total_requests: self.total_requests.load(std::sync::atomic::Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct StatsSnapshot {
        pub hits: u64,
        pub misses: u64,
        pub total_requests: u64,
    }

    impl StatsSnapshot {
        pub fn hit_rate(&self) -> f64 {
            if self.total_requests == 0 {
                0.0
            } else {
                self.hits as f64 / self.total_requests as f64
            }
        }
    }
}

/// Performance monitoring and profiling utilities
pub mod profiling {
    use super::*;

    /// Performance profiler for measuring operation latency
    pub struct PerformanceProfiler {
        measurements: Arc<RwLock<HashMap<String, Vec<Duration>>>>,
        max_samples: usize,
    }

    impl PerformanceProfiler {
        pub fn new(max_samples: usize) -> Self {
            Self {
                measurements: Arc::new(RwLock::new(HashMap::new())),
                max_samples,
            }
        }

        pub async fn measure<F, Fut, T>(&self, operation_name: &str, operation: F) -> Result<T, String>
        where
            F: FnOnce() -> Fut,
            Fut: std::future::Future<Output = Result<T, String>>,
        {
            let start = Instant::now();
            let result = operation().await;
            let duration = start.elapsed();

            // Record the measurement
            let mut measurements = self.measurements.write().await;
            let samples = measurements.entry(operation_name.to_string())
                .or_insert_with(Vec::new);

            samples.push(duration);

            // Keep only the most recent samples
            if samples.len() > self.max_samples {
                samples.remove(0);
            }

            result
        }

        pub async fn get_stats(&self, operation_name: &str) -> Option<OperationStats> {
            let measurements = self.measurements.read().await;
            let samples = measurements.get(operation_name)?;

            if samples.is_empty() {
                return None;
            }

            let mut sorted_samples = samples.clone();
            sorted_samples.sort();

            let total: Duration = samples.iter().sum();
            let avg = total / samples.len() as u32;

            let p50_idx = (samples.len() as f64 * 0.5) as usize;
            let p95_idx = (samples.len() as f64 * 0.95) as usize;
            let p99_idx = (samples.len() as f64 * 0.99) as usize;

            Some(OperationStats {
                operation_name: operation_name.to_string(),
                sample_count: samples.len(),
                average: avg,
                p50: sorted_samples.get(p50_idx).copied().unwrap_or(Duration::default()),
                p95: sorted_samples.get(p95_idx).copied().unwrap_or(Duration::default()),
                p99: sorted_samples.get(p99_idx).copied().unwrap_or(Duration::default()),
                min: *sorted_samples.first().unwrap_or(&Duration::default()),
                max: *sorted_samples.last().unwrap_or(&Duration::default()),
            })
        }

        pub async fn get_all_stats(&self) -> HashMap<String, OperationStats> {
            let measurements = self.measurements.read().await;
            let mut stats = HashMap::new();

            for operation_name in measurements.keys() {
                if let Some(operation_stats) = self.get_stats(operation_name).await {
                    stats.insert(operation_name.clone(), operation_stats);
                }
            }

            stats
        }
    }

    #[derive(Debug, Clone)]
    pub struct OperationStats {
        pub operation_name: String,
        pub sample_count: usize,
        pub average: Duration,
        pub p50: Duration,
        pub p95: Duration,
        pub p99: Duration,
        pub min: Duration,
        pub max: Duration,
    }
}

/// Comprehensive performance optimization configuration
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Memory pool settings
    pub memory_pool: MemoryPoolConfig,
    /// Async optimization settings
    pub async_optimization: AsyncOptimizationConfig,
    /// Lock optimization settings
    pub lock_optimization: LockOptimizationConfig,
    /// Profiling settings
    pub profiling: ProfilingConfig,
}

#[derive(Debug, Clone)]
pub struct MemoryPoolConfig {
    pub enable_pools: bool,
    pub db_connection_pool_size: usize,
    pub redis_connection_pool_size: usize,
    pub object_pool_initial_size: usize,
    pub object_pool_max_size: usize,
}

#[derive(Debug, Clone)]
pub struct AsyncOptimizationConfig {
    pub enable_batch_processing: bool,
    pub max_batch_size: usize,
    pub max_wait_time_ms: u64,
    pub max_concurrent_batches: usize,
    pub enable_streaming: bool,
    pub streaming_buffer_size: usize,
}

#[derive(Debug, Clone)]
pub struct LockOptimizationConfig {
    pub enable_read_optimized_maps: bool,
    pub shard_count: usize,
    pub enable_lock_free_stats: bool,
}

#[derive(Debug, Clone)]
pub struct ProfilingConfig {
    pub enable_profiling: bool,
    pub max_samples_per_operation: usize,
    pub enable_continuous_monitoring: bool,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            memory_pool: MemoryPoolConfig {
                enable_pools: true,
                db_connection_pool_size: 10,
                redis_connection_pool_size: 20,
                object_pool_initial_size: 100,
                object_pool_max_size: 1000,
            },
            async_optimization: AsyncOptimizationConfig {
                enable_batch_processing: true,
                max_batch_size: 100,
                max_wait_time_ms: 100,
                max_concurrent_batches: 10,
                enable_streaming: true,
                streaming_buffer_size: 1000,
            },
            lock_optimization: LockOptimizationConfig {
                enable_read_optimized_maps: true,
                shard_count: 16,
                enable_lock_free_stats: true,
            },
            profiling: ProfilingConfig {
                enable_profiling: true,
                max_samples_per_operation: 1000,
                enable_continuous_monitoring: true,
            },
        }
    }
}

/// Performance optimizer with comprehensive optimization strategies
pub struct PerformanceOptimizer {
    config: PerformanceConfig,
    profiler: profiling::PerformanceProfiler,
}

impl PerformanceOptimizer {
    pub fn new(config: PerformanceConfig) -> Self {
        Self {
            profiler: profiling::PerformanceProfiler::new(config.profiling.max_samples_per_operation),
            config,
        }
    }

    pub fn default() -> Self {
        Self::new(PerformanceConfig::default())
    }

    /// Optimize an async operation with profiling
    pub async fn optimize_operation<F, Fut, T>(
        &self,
        operation_name: &str,
        operation: F,
    ) -> Result<T, String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, String>>,
    {
        if self.config.profiling.enable_profiling {
            self.profiler.measure(operation_name, operation).await
        } else {
            operation().await
        }
    }

    /// Get performance statistics
    pub async fn get_performance_stats(&self) -> HashMap<String, profiling::OperationStats> {
        self.profiler.get_all_stats().await
    }

    /// Get optimization recommendations based on current performance
    pub async fn get_optimization_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();
        let stats = self.get_performance_stats().await;

        for (operation_name, operation_stats) in stats {
            // Check for performance issues
            if operation_stats.average > Duration::from_millis(100) {
                recommendations.push(format!(
                    "Consider optimizing {}: average latency {:.2}ms",
                    operation_name,
                    operation_stats.average.as_millis()
                ));
            }

            if operation_stats.p95 > Duration::from_millis(500) {
                recommendations.push(format!(
                    "High P95 latency for {}: {:.2}ms - consider optimization",
                    operation_name,
                    operation_stats.p95.as_millis()
                ));
            }
        }

        if recommendations.is_empty() {
            recommendations.push("Performance looks good! No optimization recommendations at this time.".to_string());
        }

        recommendations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_optimizer() {
        let optimizer = PerformanceOptimizer::default();

        // Test operation optimization
        let result = optimizer
            .optimize_operation("test_operation", || async { Ok(42) })
            .await;

        assert_eq!(result.unwrap(), 42);

        // Test recommendations
        let recommendations = optimizer.get_optimization_recommendations().await;
        assert!(!recommendations.is_empty());
    }

    #[tokio::test]
    async fn test_object_pool() {
        let pool = memory_pool::ObjectPool::new(|| "test_object".to_string(), 5, 10);

        let stats = pool.stats().await;
        assert_eq!(stats.available, 5);
        assert_eq!(stats.created, 5);

        // Acquire and return an object
        let obj = pool.acquire().await;
        assert_eq!(obj.as_ref(), "test_object");

        drop(obj);

        // Check that object was returned
        tokio::time::sleep(Duration::from_millis(10)).await;
        let stats = pool.stats().await;
        assert_eq!(stats.available, 5); // Should be back to 5
    }

    #[tokio::test]
    async fn test_read_optimized_map() {
        let map = lock_optimization::ReadOptimizedMap::new(4);

        // Test basic operations
        map.insert("key1".to_string(), "value1".to_string()).await;
        map.insert("key2".to_string(), "value2".to_string()).await;

        let value1 = map.get("key1").await;
        let value2 = map.get("key2").await;

        assert_eq!(value1, Some("value1".to_string()));
        assert_eq!(value2, Some("value2".to_string()));

        let removed = map.remove("key1").await;
        assert_eq!(removed, Some("value1".to_string()));

        let value1_after_remove = map.get("key1").await;
        assert_eq!(value1_after_remove, None);
    }

    #[test]
    fn test_lock_free_stats() {
        let stats = lock_optimization::LockFreeStats::new();

        // Record some hits and misses
        stats.record_hit();
        stats.record_hit();
        stats.record_miss();
        stats.record_hit();

        let snapshot = stats.get_stats();
        assert_eq!(snapshot.hits, 3);
        assert_eq!(snapshot.misses, 1);
        assert_eq!(snapshot.total_requests, 4);
        assert_eq!(snapshot.hit_rate(), 0.75);
    }
}
