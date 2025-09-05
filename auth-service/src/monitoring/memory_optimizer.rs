//! Memory optimization utilities for MVP Auth Service
//!
//! Provides intelligent memory management and optimization strategies:
//! - Automatic cache cleanup and optimization
//! - Memory pool management for frequent allocations
//! - Smart object lifecycle management
//! - Garbage collection hints and optimization

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::time::interval;

/// Memory optimization configuration
#[derive(Debug, Clone)]
pub struct MemoryOptimizerConfig {
    pub cleanup_interval: Duration,
    pub cache_max_size: usize,
    pub object_pool_size: usize,
    pub gc_trigger_threshold_mb: u64,
    pub aggressive_optimization: bool,
}

impl Default for MemoryOptimizerConfig {
    fn default() -> Self {
        Self {
            cleanup_interval: Duration::from_secs(60),
            cache_max_size: 10000,
            object_pool_size: 1000,
            gc_trigger_threshold_mb: 256,
            aggressive_optimization: false,
        }
    }
}

/// Memory optimization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationStats {
    pub cleanup_cycles: u64,
    pub objects_freed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub pool_allocations: u64,
    pub gc_triggers: u64,
    pub memory_saved_bytes: u64,
    pub last_optimization: chrono::DateTime<chrono::Utc>,
}

/// Object pool for frequent allocations
pub struct ObjectPool<T> {
    pool: Arc<Mutex<Vec<T>>>,
    factory: Box<dyn Fn() -> T + Send + Sync>,
    max_size: usize,
}

impl<T> ObjectPool<T> {
    pub fn new<F>(factory: F, max_size: usize) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        Self {
            pool: Arc::new(Mutex::new(Vec::new())),
            factory: Box::new(factory),
            max_size,
        }
    }

    pub fn acquire(&self) -> T {
        let mut pool = self.pool.lock().unwrap();
        if let Some(object) = pool.pop() {
            object
        } else {
            (self.factory)()
        }
    }

    pub fn release(&self, _object: T)
    where
        T: Default,
    {
        // Reset object to default state
        let object = T::default();

        let mut pool = self.pool.lock().unwrap();
        if pool.len() < self.max_size {
            pool.push(object);
        }
        // Otherwise drop the object to free memory
    }

    pub fn pool_size(&self) -> usize {
        self.pool.lock().unwrap().len()
    }
}

/// Cache entry with expiration and access tracking
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    created_at: Instant,
    last_accessed: Instant,
    access_count: u64,
    expiry: Option<Instant>,
}

impl<T> CacheEntry<T> {
    fn new(value: T, ttl: Option<Duration>) -> Self {
        let now = Instant::now();
        Self {
            value,
            created_at: now,
            last_accessed: now,
            access_count: 1,
            expiry: ttl.map(|ttl| now + ttl),
        }
    }

    fn is_expired(&self) -> bool {
        self.expiry.is_some_and(|exp| Instant::now() > exp)
    }

    fn access(&mut self) -> &T {
        self.last_accessed = Instant::now();
        self.access_count += 1;
        &self.value
    }
}

/// Intelligent cache with automatic cleanup
#[derive(Clone)]
pub struct SmartCache<K, V>
where
    K: Clone + std::hash::Hash + Eq,
    V: Clone,
{
    cache: Arc<RwLock<HashMap<K, CacheEntry<V>>>>,
    config: MemoryOptimizerConfig,
    stats: Arc<Mutex<OptimizationStats>>,
}

impl<K, V> SmartCache<K, V>
where
    K: Clone + std::hash::Hash + Eq,
    V: Clone,
{
    pub fn new(config: MemoryOptimizerConfig) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(Mutex::new(OptimizationStats {
                cleanup_cycles: 0,
                objects_freed: 0,
                cache_hits: 0,
                cache_misses: 0,
                pool_allocations: 0,
                gc_triggers: 0,
                memory_saved_bytes: 0,
                last_optimization: chrono::Utc::now(),
            })),
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let mut cache = self.cache.write().unwrap();
        if let Some(entry) = cache.get_mut(key) {
            if entry.is_expired() {
                cache.remove(key);
                self.stats.lock().unwrap().cache_misses += 1;
                None
            } else {
                self.stats.lock().unwrap().cache_hits += 1;
                Some(entry.access().clone())
            }
        } else {
            self.stats.lock().unwrap().cache_misses += 1;
            None
        }
    }

    pub fn insert(&self, key: K, value: V, ttl: Option<Duration>) {
        let mut cache = self.cache.write().unwrap();

        // Check if cache is full and needs cleanup
        if cache.len() >= self.config.cache_max_size {
            self.cleanup_cache(&mut cache);
        }

        cache.insert(key, CacheEntry::new(value, ttl));
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        self.cache
            .write()
            .unwrap()
            .remove(key)
            .map(|entry| entry.value)
    }

    pub fn cleanup_expired(&self) -> usize {
        let mut cache = self.cache.write().unwrap();
        self.cleanup_cache(&mut cache)
    }

    fn cleanup_cache(&self, cache: &mut HashMap<K, CacheEntry<V>>) -> usize {
        let initial_size = cache.len();
        let _now = Instant::now();

        // Remove expired entries
        cache.retain(|_, entry| !entry.is_expired());

        // If still over limit, remove least recently used entries
        if cache.len() >= self.config.cache_max_size {
            let mut entries: Vec<_> = cache
                .iter()
                .map(|(k, v)| (k.clone(), v.last_accessed))
                .collect();
            entries.sort_by_key(|(_, last_accessed)| *last_accessed);

            let remove_count = cache.len() - (self.config.cache_max_size * 3 / 4); // Remove 25%
            let keys_to_remove: Vec<_> = entries
                .into_iter()
                .take(remove_count)
                .map(|(k, _)| k)
                .collect();
            for key in keys_to_remove {
                cache.remove(&key);
            }
        }

        let freed_count = initial_size - cache.len();
        self.stats.lock().unwrap().objects_freed += freed_count as u64;

        freed_count
    }

    pub fn get_stats(&self) -> OptimizationStats {
        self.stats.lock().unwrap().clone()
    }

    pub fn cache_size(&self) -> usize {
        self.cache.read().unwrap().len()
    }
}

/// Main memory optimizer
pub struct MemoryOptimizer {
    config: MemoryOptimizerConfig,
    token_cache: SmartCache<String, common::TokenRecord>,
    session_cache: SmartCache<String, String>, // Simplified session cache
    string_pool: ObjectPool<String>,
    stats: Arc<Mutex<OptimizationStats>>,
    is_running: Arc<Mutex<bool>>,
}

impl MemoryOptimizer {
    pub fn new(config: MemoryOptimizerConfig) -> Self {
        let string_pool = ObjectPool::new(String::new, config.object_pool_size);

        Self {
            token_cache: SmartCache::new(config.clone()),
            session_cache: SmartCache::new(config.clone()),
            string_pool,
            config,
            stats: Arc::new(Mutex::new(OptimizationStats {
                cleanup_cycles: 0,
                objects_freed: 0,
                cache_hits: 0,
                cache_misses: 0,
                pool_allocations: 0,
                gc_triggers: 0,
                memory_saved_bytes: 0,
                last_optimization: chrono::Utc::now(),
            })),
            is_running: Arc::new(Mutex::new(false)),
        }
    }

    /// Start automatic memory optimization
    pub async fn start_optimization(&self) -> Result<(), Box<dyn std::error::Error>> {
        {
            let mut running = self.is_running.lock().unwrap();
            if *running {
                return Err("Memory optimizer is already running".into());
            }
            *running = true;
        }

        let token_cache = self.token_cache.clone();
        let session_cache = self.session_cache.clone();
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();
        let is_running = Arc::clone(&self.is_running);

        tokio::spawn(async move {
            let mut interval = interval(config.cleanup_interval);

            while *is_running.lock().unwrap() {
                interval.tick().await;

                let start_time = Instant::now();

                // Clean up expired cache entries
                let token_freed = token_cache.cleanup_expired();
                let session_freed = session_cache.cleanup_expired();

                // Update statistics
                {
                    let mut stats = stats.lock().unwrap();
                    stats.cleanup_cycles += 1;
                    stats.objects_freed += (token_freed + session_freed) as u64;
                    stats.last_optimization = chrono::Utc::now();

                    // Merge cache stats
                    let token_stats = token_cache.get_stats();
                    let session_stats = session_cache.get_stats();
                    stats.cache_hits += token_stats.cache_hits + session_stats.cache_hits;
                    stats.cache_misses += token_stats.cache_misses + session_stats.cache_misses;
                }

                let cleanup_duration = start_time.elapsed();

                // Log cleanup results
                if token_freed + session_freed > 0 {
                    tracing::info!(
                        "🧹 Memory cleanup: freed {} objects in {:?}",
                        token_freed + session_freed,
                        cleanup_duration
                    );
                }

                // Trigger garbage collection hint if memory usage is high
                if config.aggressive_optimization {
                    Self::trigger_gc_hint();
                }
            }
        });

        tracing::info!(
            "🔄 Memory optimizer started with {}s cleanup interval",
            self.config.cleanup_interval.as_secs()
        );
        Ok(())
    }

    /// Stop automatic memory optimization
    pub fn stop_optimization(&self) {
        *self.is_running.lock().unwrap() = false;
        tracing::info!("🛑 Memory optimizer stopped");
    }

    /// Cache a token with TTL
    pub fn cache_token(&self, token_id: String, record: common::TokenRecord, ttl: Duration) {
        self.token_cache.insert(token_id, record, Some(ttl));
    }

    /// Get cached token
    pub fn get_cached_token(&self, token_id: &str) -> Option<common::TokenRecord> {
        self.token_cache.get(&token_id.to_string())
    }

    /// Cache session data
    pub fn cache_session(&self, session_id: String, data: String, ttl: Duration) {
        self.session_cache.insert(session_id, data, Some(ttl));
    }

    /// Get cached session
    pub fn get_cached_session(&self, session_id: &str) -> Option<String> {
        self.session_cache.get(&session_id.to_string())
    }

    /// Acquire a string from the pool
    pub fn acquire_string(&self) -> String {
        self.stats.lock().unwrap().pool_allocations += 1;
        self.string_pool.acquire()
    }

    /// Return a string to the pool
    pub fn release_string(&self, string: String) {
        self.string_pool.release(string);
    }

    /// Force cleanup of all caches
    pub fn force_cleanup(&self) -> CleanupResult {
        let start_time = Instant::now();

        let tokens_freed = self.token_cache.cleanup_expired();
        let sessions_freed = self.session_cache.cleanup_expired();

        let total_freed = tokens_freed + sessions_freed;
        let cleanup_duration = start_time.elapsed();

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.cleanup_cycles += 1;
            stats.objects_freed += total_freed as u64;
            stats.last_optimization = chrono::Utc::now();
        }

        CleanupResult {
            objects_freed: total_freed,
            cleanup_duration,
            tokens_freed,
            sessions_freed,
        }
    }

    /// Get memory optimization statistics
    pub fn get_stats(&self) -> MemoryOptimizerStats {
        let base_stats = self.stats.lock().unwrap().clone();

        MemoryOptimizerStats {
            base_stats,
            token_cache_size: self.token_cache.cache_size(),
            session_cache_size: self.session_cache.cache_size(),
            string_pool_size: self.string_pool.pool_size(),
        }
    }

    /// Trigger garbage collection hint (platform-specific)
    fn trigger_gc_hint() {
        // On systems that support it, hint to the runtime that GC would be beneficial
        // This is mainly useful for managed runtimes, but we can drop unused data

        #[cfg(target_os = "linux")]
        {
            // On Linux, we can hint to the kernel to drop caches
            use std::fs::OpenOptions;
            use std::io::Write;

            if let Ok(mut file) = OpenOptions::new()
                .write(true)
                .open("/proc/sys/vm/drop_caches")
            {
                let _ = file.write_all(b"1"); // Drop page cache
            }
        }

        // For Rust, we can't force GC but we can drop large allocations
        // This is handled by our cleanup routines above
    }
}

#[derive(Debug, Clone)]
pub struct CleanupResult {
    pub objects_freed: usize,
    pub cleanup_duration: Duration,
    pub tokens_freed: usize,
    pub sessions_freed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryOptimizerStats {
    #[serde(flatten)]
    pub base_stats: OptimizationStats,
    pub token_cache_size: usize,
    pub session_cache_size: usize,
    pub string_pool_size: usize,
}
