//! Performance optimization utilities
//!
//! This module provides utilities and patterns for optimizing performance
//! across the auth service, focusing on reducing allocations and improving
//! hot path efficiency.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// String interning pool to reduce string allocations
pub struct StringPool {
    pool: Arc<RwLock<HashMap<String, Arc<str>>>>,
}

impl StringPool {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pool: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Intern a string, returning a shared reference
    pub async fn intern(&self, s: &str) -> Arc<str> {
        // First, try to get existing string
        {
            let pool = self.pool.read().await;
            if let Some(interned) = pool.get(s) {
                return Arc::clone(interned);
            }
        }

        // Not found, create new entry
        let mut pool = self.pool.write().await;
        // Double-check in case another thread added it
        if let Some(interned) = pool.get(s) {
            Arc::clone(interned)
        } else {
            let interned: Arc<str> = Arc::from(s);
            pool.insert(s.to_string(), Arc::clone(&interned));
            interned
        }
    }

    /// Clear the pool (for memory management)
    pub async fn clear(&self) {
        self.pool.write().await.clear();
    }

    /// Get pool statistics
    pub async fn stats(&self) -> (usize, usize) {
        let pool = self.pool.read().await;
        let entry_count = pool.len();
        let total_bytes: usize = pool.keys().map(String::len).sum();
        (entry_count, total_bytes)
    }
}

impl Default for StringPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-allocated buffer pool for reducing allocations
pub struct BufferPool<T> {
    buffers: Arc<RwLock<Vec<Vec<T>>>>,
    max_size: usize,
    max_capacity: usize,
}

impl<T: Send + Sync> BufferPool<T> {
    #[must_use]
    pub fn new(max_size: usize, max_capacity: usize) -> Self {
        Self {
            buffers: Arc::new(RwLock::new(Vec::new())),
            max_size,
            max_capacity,
        }
    }

    /// Get a buffer from the pool or create a new one
    pub async fn get(&self) -> Vec<T> {
        let mut buffers = self.buffers.write().await;
        buffers.pop().unwrap_or_else(Vec::new)
    }

    /// Return a buffer to the pool
    pub async fn put(&self, mut buffer: Vec<T>) {
        if buffer.capacity() <= self.max_capacity {
            buffer.clear(); // Clear contents but keep capacity
            let mut buffers = self.buffers.write().await;
            if buffers.len() < self.max_size {
                buffers.push(buffer);
            }
        }
        // If buffer is too large or pool is full, just drop it
    }

    /// Get pool statistics
    pub async fn stats(&self) -> (usize, usize) {
        let buffers = self.buffers.read().await;
        let count = buffers.len();
        let total_capacity: usize = buffers.iter().map(Vec::capacity).sum();
        (count, total_capacity)
    }
}

/// Optimized string operations
pub mod string_ops {
    use std::borrow::Cow;

    /// Efficiently concatenate strings with minimal allocations
    #[must_use]
    pub fn concat_strings<'a>(parts: &[&'a str]) -> Cow<'a, str> {
        match parts.len() {
            0 => Cow::Borrowed(""),
            1 => Cow::Borrowed(parts[0]),
            _ => {
                let total_len = parts.iter().map(|s| s.len()).sum();
                let mut result = String::with_capacity(total_len);
                for part in parts {
                    result.push_str(part);
                }
                Cow::Owned(result)
            }
        }
    }

    /// Efficiently build a string with known capacity
    pub fn build_string_with_capacity<F>(capacity: usize, builder: F) -> String
    where
        F: FnOnce(&mut String),
    {
        let mut string = String::with_capacity(capacity);
        builder(&mut string);
        string
    }

    /// Check if a string is likely to be worth interning
    #[must_use]
    pub const fn should_intern(s: &str) -> bool {
        s.len() > 10 && s.len() < 1000 // Reasonable size for interning
    }

    /// Fast case-insensitive string comparison for ASCII
    #[must_use]
    pub fn ascii_eq_ignore_case(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }

        a.eq_ignore_ascii_case(b)
    }
}

/// Memory usage optimizations (safe implementation)
pub mod memory {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Simple memory usage tracker (without global allocator)
    pub struct MemoryTracker {
        allocated: AtomicUsize,
        peak_usage: AtomicUsize,
    }

    impl MemoryTracker {
        #[must_use]
        pub const fn new() -> Self {
            Self {
                allocated: AtomicUsize::new(0),
                peak_usage: AtomicUsize::new(0),
            }
        }

        pub fn record_allocation(&self, size: usize) {
            let new_total = self.allocated.fetch_add(size, Ordering::Relaxed) + size;

            // Update peak usage
            let mut current_peak = self.peak_usage.load(Ordering::Relaxed);
            while new_total > current_peak {
                match self.peak_usage.compare_exchange_weak(
                    current_peak,
                    new_total,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(x) => current_peak = x,
                }
            }
        }

        pub fn record_deallocation(&self, size: usize) {
            self.allocated.fetch_sub(size, Ordering::Relaxed);
        }

        pub fn current_usage(&self) -> usize {
            self.allocated.load(Ordering::Relaxed)
        }

        pub fn peak_usage(&self) -> usize {
            self.peak_usage.load(Ordering::Relaxed)
        }

        pub fn reset_peak(&self) {
            self.peak_usage
                .store(self.current_usage(), Ordering::Relaxed);
        }
    }

    impl Default for MemoryTracker {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Global memory tracker instance
    static GLOBAL_TRACKER: MemoryTracker = MemoryTracker::new();

    /// Record memory allocation globally
    pub fn record_allocation(size: usize) {
        GLOBAL_TRACKER.record_allocation(size);
    }

    /// Record memory deallocation globally
    pub fn record_deallocation(size: usize) {
        GLOBAL_TRACKER.record_deallocation(size);
    }

    /// Get current memory usage statistics
    pub fn memory_stats() -> (usize, usize) {
        (GLOBAL_TRACKER.current_usage(), GLOBAL_TRACKER.peak_usage())
    }

    /// Reset peak memory usage counter
    pub fn reset_peak_usage() {
        GLOBAL_TRACKER.reset_peak();
    }
}

/// Performance monitoring utilities
pub mod monitoring {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::RwLock;

    /// Simple performance metrics collector
    #[derive(Debug, Clone)]
    pub struct PerformanceMetrics {
        pub operation: String,
        pub duration: Duration,
        pub timestamp: Instant,
        pub success: bool,
        pub memory_used: usize,
    }

    /// Performance monitor
    pub struct PerformanceMonitor {
        metrics: Arc<RwLock<VecDeque<PerformanceMetrics>>>,
        max_entries: usize,
    }

    impl PerformanceMonitor {
        #[must_use]
        pub fn new(max_entries: usize) -> Self {
            Self {
                metrics: Arc::new(RwLock::new(VecDeque::new())),
                max_entries,
            }
        }

        /// Record a performance measurement
        pub async fn record(&self, metric: PerformanceMetrics) {
            let mut metrics = self.metrics.write().await;
            metrics.push_back(metric);

            if metrics.len() > self.max_entries {
                metrics.pop_front();
            }
        }

        /// Get performance statistics
        pub async fn stats(&self) -> PerformanceStats {
            let metrics = self.metrics.read().await;

            if metrics.is_empty() {
                return PerformanceStats::default();
            }

            let total_operations = metrics.len();
            let successful_operations = metrics.iter().filter(|m| m.success).count();

            let durations: Vec<Duration> = metrics.iter().map(|m| m.duration).collect();
            let total_duration: Duration = durations.iter().sum();
            let avg_duration = total_duration / total_operations as u32;

            let mut sorted_durations = durations;
            sorted_durations.sort();

            let median_duration = sorted_durations[sorted_durations.len() / 2];
            let p95_index = (sorted_durations.len() as f64 * 0.95) as usize;
            let p95_duration = sorted_durations[p95_index.min(sorted_durations.len() - 1)];

            PerformanceStats {
                total_operations,
                successful_operations,
                success_rate: successful_operations as f64 / total_operations as f64,
                avg_duration,
                median_duration,
                p95_duration,
                min_duration: sorted_durations[0],
                max_duration: sorted_durations[sorted_durations.len() - 1],
            }
        }

        /// Clear all metrics
        pub async fn clear(&self) {
            self.metrics.write().await.clear();
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct PerformanceStats {
        pub total_operations: usize,
        pub successful_operations: usize,
        pub success_rate: f64,
        pub avg_duration: Duration,
        pub median_duration: Duration,
        pub p95_duration: Duration,
        pub min_duration: Duration,
        pub max_duration: Duration,
    }
}

/// Efficient caching utilities
pub mod caching {
    use std::collections::HashMap;
    use std::hash::Hash;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::RwLock;

    /// LRU Cache entry
    #[derive(Debug, Clone)]
    struct CacheEntry<V> {
        value: V,
        last_accessed: Instant,
        access_count: u64,
    }

    /// Simple LRU cache with TTL support
    pub struct LruCache<K, V> {
        cache: Arc<RwLock<HashMap<K, CacheEntry<V>>>>,
        max_size: usize,
        ttl: Duration,
    }

    impl<K, V> LruCache<K, V>
    where
        K: Clone + Eq + Hash + Send + Sync,
        V: Clone + Send + Sync,
    {
        #[must_use]
        pub fn new(max_size: usize, ttl: Duration) -> Self {
            Self {
                cache: Arc::new(RwLock::new(HashMap::new())),
                max_size,
                ttl,
            }
        }

        /// Get a value from the cache
        pub async fn get(&self, key: &K) -> Option<V> {
            let mut cache = self.cache.write().await;

            if let Some(entry) = cache.get_mut(key) {
                // Check if entry is expired
                if entry.last_accessed.elapsed() > self.ttl {
                    cache.remove(key);
                    return None;
                }

                // Update access information
                entry.last_accessed = Instant::now();
                entry.access_count += 1;

                Some(entry.value.clone())
            } else {
                None
            }
        }

        /// Put a value in the cache
        pub async fn put(&self, key: K, value: V) {
            let mut cache = self.cache.write().await;

            // If at capacity, remove least recently used item
            if cache.len() >= self.max_size && !cache.contains_key(&key) {
                if let Some(lru_key) = self.find_lru_key(&cache) {
                    cache.remove(&lru_key);
                }
            }

            let entry = CacheEntry {
                value,
                last_accessed: Instant::now(),
                access_count: 1,
            };

            cache.insert(key, entry);
        }

        /// Find the least recently used key
        fn find_lru_key(&self, cache: &HashMap<K, CacheEntry<V>>) -> Option<K> {
            cache
                .iter()
                .min_by_key(|(_, entry)| (entry.last_accessed, entry.access_count))
                .map(|(k, _)| k.clone())
        }

        /// Clear expired entries
        pub async fn cleanup_expired(&self) {
            let mut cache = self.cache.write().await;
            let now = Instant::now();

            cache.retain(|_, entry| now.duration_since(entry.last_accessed) <= self.ttl);
        }

        /// Get cache statistics
        pub async fn stats(&self) -> (usize, usize, f64) {
            let cache = self.cache.read().await;
            let size = cache.len();
            let total_accesses: u64 = cache.values().map(|e| e.access_count).sum();
            let avg_accesses = if size > 0 {
                total_accesses as f64 / size as f64
            } else {
                0.0
            };
            (size, self.max_size, avg_accesses)
        }
    }
}
