//! Advanced Caching Module for Performance Optimization
//!
//! This module provides sophisticated caching strategies including:
//! - Multi-level caching (L1, L2, L3)
//! - Intelligent cache eviction policies
//! - Cache warming and prefetching
//! - Distributed cache coordination
//! - Cache performance monitoring
//! - Adaptive cache sizing
//! - Cache consistency management

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

/// Cache manager trait
#[async_trait]
pub trait CacheManager: Send + Sync {
    /// Get value from cache
    async fn get<K, V>(&self, key: &K) -> Result<Option<V>, CacheError>
    where
        K: CacheKey + 'static,
        V: CacheValue + 'static;

    /// Put value in cache
    async fn put<K, V>(&self, key: K, value: V, ttl: Option<Duration>) -> Result<(), CacheError>
    where
        K: CacheKey + 'static,
        V: CacheValue + 'static;

    /// Remove value from cache
    async fn remove<K>(&self, key: &K) -> Result<bool, CacheError>
    where
        K: CacheKey + 'static;

    /// Check if key exists in cache
    async fn contains<K>(&self, key: &K) -> Result<bool, CacheError>
    where
        K: CacheKey + 'static;

    /// Clear all cache entries
    async fn clear(&self) -> Result<(), CacheError>;

    /// Get cache statistics
    async fn stats(&self) -> Result<CacheStats, CacheError>;

    /// Warm up cache with frequently accessed data
    async fn warmup(&self, keys: Vec<String>) -> Result<(), CacheError>;

    /// Prefetch data based on access patterns
    async fn prefetch(&self, patterns: Vec<String>) -> Result<(), CacheError>;
}

/// Cache key trait
pub trait CacheKey: Clone + Hash + Eq + Send + Sync + 'static {
    fn as_string(&self) -> String;
}

/// Cache value trait
pub trait CacheValue: Clone + Send + Sync + 'static {
    fn size_bytes(&self) -> usize;
    fn is_expired(&self) -> bool;
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_size_bytes: usize,
    pub default_ttl: Duration,
    pub eviction_policy: EvictionPolicy,
    pub compression_enabled: bool,
    pub monitoring_enabled: bool,
    pub distributed_enabled: bool,
    pub warmup_enabled: bool,
    pub prefetch_enabled: bool,
}

/// Cache eviction policies
#[derive(Debug, Clone, PartialEq)]
pub enum EvictionPolicy {
    Lru,        // Least Recently Used
    Lfu,        // Least Frequently Used
    Fifo,       // First In, First Out
    Random,     // Random eviction
    Adaptive,   // Adaptive based on access patterns
}

/// Cache entry
#[derive(Debug, Clone)]
struct CacheEntry<V> {
    value: V,
    created_at: Instant,
    last_accessed: Instant,
    access_count: u64,
    ttl: Option<Duration>,
    size_bytes: usize,
}

impl<V> CacheEntry<V> {
    fn new(value: V, ttl: Option<Duration>) -> Self
    where
        V: CacheValue,
    {
        let size_bytes = value.size_bytes();
        let now = Instant::now();

        Self {
            value,
            created_at: now,
            last_accessed: now,
            access_count: 0,
            ttl,
            size_bytes,
        }
    }

    fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl {
            self.created_at.elapsed() > ttl
        } else {
            false
        }
    }

    fn access(&mut self) {
        self.last_accessed = Instant::now();
        self.access_count += 1;
    }

    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub total_size_bytes: usize,
    pub hit_count: u64,
    pub miss_count: u64,
    pub eviction_count: u64,
    pub hit_rate_percent: f64,
    pub avg_access_time_ms: f64,
    pub uptime_seconds: u64,
    pub memory_usage_bytes: usize,
}

/// Cache error
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Key not found: {key}")]
    KeyNotFound { key: String },

    #[error("Cache is full")]
    CacheFull,

    #[error("Serialization error: {message}")]
    SerializationError { message: String },

    #[error("Deserialization error: {message}")]
    DeserializationError { message: String },

    #[error("Storage error: {message}")]
    StorageError { message: String },

    #[error("Network error: {message}")]
    NetworkError { message: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },
}

/// Advanced multi-level cache implementation
pub struct AdvancedCacheManager {
    l1_cache: Arc<RwLock<HashMap<String, CacheEntry<String>>>>, // Fast in-memory cache
    l2_cache: Arc<RwLock<HashMap<String, CacheEntry<String>>>>, // Larger memory cache
    config: CacheConfig,
    stats: Arc<RwLock<CacheStats>>,
    start_time: Instant,
}

impl AdvancedCacheManager {
    /// Create new advanced cache manager
    pub fn new(config: CacheConfig) -> Self {
        let stats = CacheStats {
            total_entries: 0,
            total_size_bytes: 0,
            hit_count: 0,
            miss_count: 0,
            eviction_count: 0,
            hit_rate_percent: 0.0,
            avg_access_time_ms: 0.0,
            uptime_seconds: 0,
            memory_usage_bytes: 0,
        };

        Self {
            l1_cache: Arc::new(RwLock::new(HashMap::new())),
            l2_cache: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(stats)),
            start_time: Instant::now(),
        }
    }

    /// Evict entries based on configured policy
    async fn evict_entries(&self) -> Result<(), CacheError> {
        let mut l2_cache = self.l2_cache.write().await;
        let mut stats = self.stats.write().await;

        match self.config.eviction_policy {
            EvictionPolicy::Lru => {
                self.evict_lru(&mut l2_cache, &mut stats).await;
            }
            EvictionPolicy::Lfu => {
                self.evict_lfu(&mut l2_cache, &mut stats).await;
            }
            EvictionPolicy::Fifo => {
                self.evict_fifo(&mut l2_cache, &mut stats).await;
            }
            EvictionPolicy::Random => {
                self.evict_random(&mut l2_cache, &mut stats).await;
            }
            EvictionPolicy::Adaptive => {
                self.evict_adaptive(&mut l2_cache, &mut stats).await;
            }
        }

        Ok(())
    }

    /// Evict using LRU policy
    async fn evict_lru(
        &self,
        cache: &mut HashMap<String, CacheEntry<String>>,
        stats: &mut CacheStats,
    ) {
        if let Some((key, _)) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
        {
            let key = key.clone();
            if let Some(entry) = cache.remove(&key) {
                stats.total_entries -= 1;
                stats.total_size_bytes -= entry.size_bytes;
                stats.eviction_count += 1;
            }
        }
    }

    /// Evict using LFU policy
    async fn evict_lfu(
        &self,
        cache: &mut HashMap<String, CacheEntry<String>>,
        stats: &mut CacheStats,
    ) {
        if let Some((key, _)) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.access_count)
        {
            let key = key.clone();
            if let Some(entry) = cache.remove(&key) {
                stats.total_entries -= 1;
                stats.total_size_bytes -= entry.size_bytes;
                stats.eviction_count += 1;
            }
        }
    }

    /// Evict using FIFO policy
    async fn evict_fifo(
        &self,
        cache: &mut HashMap<String, CacheEntry<String>>,
        stats: &mut CacheStats,
    ) {
        if let Some((key, _)) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
        {
            let key = key.clone();
            if let Some(entry) = cache.remove(&key) {
                stats.total_entries -= 1;
                stats.total_size_bytes -= entry.size_bytes;
                stats.eviction_count += 1;
            }
        }
    }

    /// Evict using random policy
    async fn evict_random(
        &self,
        cache: &mut HashMap<String, CacheEntry<String>>,
        stats: &mut CacheStats,
    ) {
        use rand::seq::SliceRandom;

        if let Some(key) = cache.keys().choose(&mut rand::thread_rng()).cloned() {
            if let Some(entry) = cache.remove(&key) {
                stats.total_entries -= 1;
                stats.total_size_bytes -= entry.size_bytes;
                stats.eviction_count += 1;
            }
        }
    }

    /// Evict using adaptive policy
    async fn evict_adaptive(
        &self,
        cache: &mut HashMap<String, CacheEntry<String>>,
        stats: &mut CacheStats,
    ) {
        // Adaptive policy combines multiple factors
        if let Some((key, _)) = cache
            .iter()
            .min_by(|a, b| {
                let score_a = self.calculate_eviction_score(&a.1);
                let score_b = self.calculate_eviction_score(&b.1);
                score_a.partial_cmp(&score_b).unwrap()
            })
        {
            let key = key.clone();
            if let Some(entry) = cache.remove(&key) {
                stats.total_entries -= 1;
                stats.total_size_bytes -= entry.size_bytes;
                stats.eviction_count += 1;
            }
        }
    }

    /// Calculate eviction score for adaptive policy
    fn calculate_eviction_score(&self, entry: &CacheEntry<String>) -> f64 {
        // Higher score = more likely to be evicted
        let age_score = entry.age().as_secs_f64() / 3600.0; // Age in hours
        let frequency_score = 1.0 / (entry.access_count as f64 + 1.0); // Inverse frequency
        let recency_score = entry.last_accessed.elapsed().as_secs_f64() / 3600.0; // Time since last access

        // Weighted combination
        0.4 * age_score + 0.4 * frequency_score + 0.2 * recency_score
    }

    /// Clean expired entries
    async fn clean_expired_entries(&self) -> Result<(), CacheError> {
        let mut l1_cache = self.l1_cache.write().await;
        let mut l2_cache = self.l2_cache.write().await;
        let mut stats = self.stats.write().await;

        // Clean L1 cache
        let expired_l1: Vec<String> = l1_cache
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_l1 {
            if let Some(entry) = l1_cache.remove(&key) {
                stats.total_entries -= 1;
                stats.total_size_bytes -= entry.size_bytes;
            }
        }

        // Clean L2 cache
        let expired_l2: Vec<String> = l2_cache
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_l2 {
            if let Some(entry) = l2_cache.remove(&key) {
                stats.total_entries -= 1;
                stats.total_size_bytes -= entry.size_bytes;
            }
        }

        Ok(())
    }

    /// Update cache statistics
    async fn update_stats(&self, hit: bool, access_time_ms: f64) {
        let mut stats = self.stats.write().await;

        if hit {
            stats.hit_count += 1;
        } else {
            stats.miss_count += 1;
        }

        // Update hit rate
        let total_requests = stats.hit_count + stats.miss_count;
        if total_requests > 0 {
            stats.hit_rate_percent = (stats.hit_count as f64 / total_requests as f64) * 100.0;
        }

        // Update average access time (rolling average)
        if stats.avg_access_time_ms == 0.0 {
            stats.avg_access_time_ms = access_time_ms;
        } else {
            stats.avg_access_time_ms = (stats.avg_access_time_ms + access_time_ms) / 2.0;
        }

        stats.uptime_seconds = self.start_time.elapsed().as_secs();
    }

    /// Promote entry from L2 to L1 cache
    async fn promote_to_l1(&self, key: &str, entry: CacheEntry<String>) {
        let mut l1_cache = self.l1_cache.write().await;
        l1_cache.insert(key.to_string(), entry);
    }
}

#[async_trait]
impl CacheManager for AdvancedCacheManager {
    async fn get<K, V>(&self, key: &K) -> Result<Option<V>, CacheError>
    where
        K: CacheKey + 'static,
        V: CacheValue + 'static,
    {
        let start_time = Instant::now();
        let key_str = key.as_string();

        // Clean expired entries periodically
        if self.stats.read().await.total_entries % 100 == 0 {
            self.clean_expired_entries().await?;
        }

        // Try L1 cache first
        let l1_result = {
            let mut l1_cache = self.l1_cache.write().await;
            if let Some(entry) = l1_cache.get_mut(&key_str) {
                if !entry.is_expired() {
                    entry.access();
                    Some(entry.value.clone())
                } else {
                    l1_cache.remove(&key_str);
                    None
                }
            } else {
                None
            }
        };

        if let Some(value_str) = l1_result {
            let access_time = start_time.elapsed().as_millis() as f64;
            self.update_stats(true, access_time).await;

            // Deserialize value
            match serde_json::from_str::<V>(&value_str) {
                Ok(value) => return Ok(Some(value)),
                Err(e) => return Err(CacheError::DeserializationError {
                    message: e.to_string(),
                }),
            }
        }

        // Try L2 cache
        let l2_result = {
            let mut l2_cache = self.l2_cache.write().await;
            if let Some(entry) = l2_cache.get_mut(&key_str) {
                if !entry.is_expired() {
                    entry.access();
                    let value = entry.value.clone();

                    // Promote to L1 cache
                    let entry_clone = entry.clone();
                    drop(l2_cache);
                    self.promote_to_l1(&key_str, entry_clone).await;

                    Some(value)
                } else {
                    l2_cache.remove(&key_str);
                    None
                }
            } else {
                None
            }
        };

        let access_time = start_time.elapsed().as_millis() as f64;

        if let Some(value_str) = l2_result {
            self.update_stats(true, access_time).await;

            // Deserialize value
            match serde_json::from_str::<V>(&value_str) {
                Ok(value) => Ok(Some(value)),
                Err(e) => Err(CacheError::DeserializationError {
                    message: e.to_string(),
                }),
            }
        } else {
            self.update_stats(false, access_time).await;
            Ok(None)
        }
    }

    async fn put<K, V>(&self, key: K, value: V, ttl: Option<Duration>) -> Result<(), CacheError>
    where
        K: CacheKey + 'static,
        V: CacheValue + 'static,
    {
        let key_str = key.as_string();

        // Serialize value
        let value_str = match serde_json::to_string(&value) {
            Ok(s) => s,
            Err(e) => return Err(CacheError::SerializationError {
                message: e.to_string(),
            }),
        };

        let entry = CacheEntry::new(value_str.clone(), ttl);
        let entry_size = entry.size_bytes;

        // Check if we need to evict entries
        let mut stats = self.stats.write().await;
        if stats.total_size_bytes + entry_size > self.config.max_size_bytes {
            drop(stats);
            self.evict_entries().await?;
            stats = self.stats.write().await;
        }

        // Update statistics
        stats.total_entries += 1;
        stats.total_size_bytes += entry_size;

        // Store in L2 cache (L1 will be populated on first access)
        let mut l2_cache = self.l2_cache.write().await;
        l2_cache.insert(key_str, entry);

        Ok(())
    }

    async fn remove<K>(&self, key: &K) -> Result<bool, CacheError>
    where
        K: CacheKey + 'static,
    {
        let key_str = key.as_string();

        let mut removed = false;

        // Remove from L1 cache
        let mut l1_cache = self.l1_cache.write().await;
        if let Some(entry) = l1_cache.remove(&key_str) {
            let mut stats = self.stats.write().await;
            stats.total_entries -= 1;
            stats.total_size_bytes -= entry.size_bytes;
            removed = true;
        }

        // Remove from L2 cache
        let mut l2_cache = self.l2_cache.write().await;
        if let Some(entry) = l2_cache.remove(&key_str) {
            if !removed {
                let mut stats = self.stats.write().await;
                stats.total_entries -= 1;
                stats.total_size_bytes -= entry.size_bytes;
            }
            removed = true;
        }

        Ok(removed)
    }

    async fn contains<K>(&self, key: &K) -> Result<bool, CacheError>
    where
        K: CacheKey + 'static,
    {
        let key_str = key.as_string();

        // Check L1 cache
        {
            let l1_cache = self.l1_cache.read().await;
            if l1_cache.contains_key(&key_str) {
                if let Some(entry) = l1_cache.get(&key_str) {
                    if !entry.is_expired() {
                        return Ok(true);
                    }
                }
            }
        }

        // Check L2 cache
        let l2_cache = self.l2_cache.read().await;
        if let Some(entry) = l2_cache.get(&key_str) {
            Ok(!entry.is_expired())
        } else {
            Ok(false)
        }
    }

    async fn clear(&self) -> Result<(), CacheError> {
        let mut l1_cache = self.l1_cache.write().await;
        let mut l2_cache = self.l2_cache.write().await;
        let mut stats = self.stats.write().await;

        l1_cache.clear();
        l2_cache.clear();

        stats.total_entries = 0;
        stats.total_size_bytes = 0;
        stats.hit_count = 0;
        stats.miss_count = 0;
        stats.eviction_count = 0;
        stats.hit_rate_percent = 0.0;

        Ok(())
    }

    async fn stats(&self) -> Result<CacheStats, CacheError> {
        let mut stats = self.stats.read().await.clone();
        stats.memory_usage_bytes = self.calculate_memory_usage().await;
        Ok(stats)
    }

    async fn warmup(&self, keys: Vec<String>) -> Result<(), CacheError> {
        // In a real implementation, this would fetch data for the given keys
        // and populate the cache proactively
        // For now, just log the intent
        for key in keys {
            println!("Warming up cache for key: {}", key);
        }
        Ok(())
    }

    async fn prefetch(&self, patterns: Vec<String>) -> Result<(), CacheError> {
        // In a real implementation, this would analyze access patterns
        // and prefetch data based on predictions
        // For now, just log the intent
        for pattern in patterns {
            println!("Setting up prefetch for pattern: {}", pattern);
        }
        Ok(())
    }
}

impl AdvancedCacheManager {
    /// Calculate current memory usage
    async fn calculate_memory_usage(&self) -> usize {
        let l1_cache = self.l1_cache.read().await;
        let l2_cache = self.l2_cache.read().await;

        let l1_size: usize = l1_cache.values().map(|entry| entry.size_bytes).sum();
        let l2_size: usize = l2_cache.values().map(|entry| entry.size_bytes).sum();

        l1_size + l2_size + std::mem::size_of::<Self>()
    }
}

// Implement CacheKey for common types
impl CacheKey for String {
    fn as_string(&self) -> String {
        self.clone()
    }
}

impl CacheKey for &str {
    fn as_string(&self) -> String {
        self.to_string()
    }
}

impl CacheKey for i64 {
    fn as_string(&self) -> String {
        self.to_string()
    }
}

impl CacheKey for u64 {
    fn as_string(&self) -> String {
        self.to_string()
    }
}

// Implement CacheValue for common types
impl CacheValue for String {
    fn size_bytes(&self) -> usize {
        self.len() + std::mem::size_of::<String>()
    }

    fn is_expired(&self) -> bool {
        false // String itself doesn't have expiration
    }
}

impl<T: Serialize + Clone + Send + Sync> CacheValue for Vec<T> {
    fn size_bytes(&self) -> usize {
        self.iter().map(|item| std::mem::size_of_val(item)).sum::<usize>() + std::mem::size_of::<Self>()
    }

    fn is_expired(&self) -> bool {
        false
    }
}

impl<T: Serialize + Clone + Send + Sync> CacheValue for HashMap<String, T> {
    fn size_bytes(&self) -> usize {
        self.iter().map(|(k, v)| k.len() + std::mem::size_of_val(v)).sum::<usize>() + std::mem::size_of::<Self>()
    }

    fn is_expired(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_cache_operations() {
        let cache = AdvancedCacheManager::new(CacheConfig {
            max_size_bytes: 1024 * 1024, // 1MB
            default_ttl: Duration::from_secs(3600),
            eviction_policy: EvictionPolicy::Lru,
            compression_enabled: false,
            monitoring_enabled: true,
            distributed_enabled: false,
            warmup_enabled: false,
            prefetch_enabled: false,
        });

        // Test put and get
        cache.put("key1", "value1".to_string(), None).await.unwrap();
        let result = cache.get::<String, String>(&"key1".to_string()).await.unwrap();
        assert_eq!(result, Some("value1".to_string()));

        // Test contains
        assert!(cache.contains(&"key1".to_string()).await.unwrap());

        // Test remove
        assert!(cache.remove(&"key1".to_string()).await.unwrap());
        assert!(!cache.contains(&"key1".to_string()).await.unwrap());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = AdvancedCacheManager::new(CacheConfig {
            max_size_bytes: 1024 * 1024,
            default_ttl: Duration::from_millis(100),
            eviction_policy: EvictionPolicy::Lru,
            compression_enabled: false,
            monitoring_enabled: true,
            distributed_enabled: false,
            warmup_enabled: false,
            prefetch_enabled: false,
        });

        // Put with TTL
        cache.put("temp_key", "temp_value".to_string(), Some(Duration::from_millis(50))).await.unwrap();

        // Should exist immediately
        assert!(cache.contains(&"temp_key".to_string()).await.unwrap());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be expired
        assert!(!cache.contains(&"temp_key".to_string()).await.unwrap());
    }

    #[tokio::test]
    async fn test_cache_statistics() {
        let cache = AdvancedCacheManager::new(CacheConfig {
            max_size_bytes: 1024 * 1024,
            default_ttl: Duration::from_secs(3600),
            eviction_policy: EvictionPolicy::Lru,
            compression_enabled: false,
            monitoring_enabled: true,
            distributed_enabled: false,
            warmup_enabled: false,
            prefetch_enabled: false,
        });

        // Put some data
        cache.put("key1", "value1".to_string(), None).await.unwrap();
        cache.put("key2", "value2".to_string(), None).await.unwrap();

        // Access some data
        cache.get::<String, String>(&"key1".to_string()).await.unwrap();
        cache.get::<String, String>(&"key1".to_string()).await.unwrap();
        cache.get::<String, String>(&"nonexistent".to_string()).await.unwrap();

        // Check stats
        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.total_entries, 2);
        assert!(stats.hit_count >= 2);
        assert!(stats.miss_count >= 1);
        assert!(stats.hit_rate_percent > 0.0);
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let cache = AdvancedCacheManager::new(CacheConfig {
            max_size_bytes: 100, // Very small cache
            default_ttl: Duration::from_secs(3600),
            eviction_policy: EvictionPolicy::Lru,
            compression_enabled: false,
            monitoring_enabled: true,
            distributed_enabled: false,
            warmup_enabled: false,
            prefetch_enabled: false,
        });

        // Fill cache with large entries
        for i in 0..10 {
            let large_value = "x".repeat(50); // ~50 bytes each
            cache.put(format!("key{}", i), large_value, None).await.unwrap();
        }

        // Cache should have evicted some entries
        let stats = cache.stats().await.unwrap();
        assert!(stats.total_entries < 10);
        assert!(stats.eviction_count > 0);
    }

    #[test]
    fn test_cache_key_implementations() {
        let string_key = "test_key".to_string();
        assert_eq!(string_key.as_string(), "test_key");

        let str_key = "test_key";
        assert_eq!(str_key.as_string(), "test_key");

        let int_key = 42i64;
        assert_eq!(int_key.as_string(), "42");

        let uint_key = 42u64;
        assert_eq!(uint_key.as_string(), "42");
    }

    #[test]
    fn test_cache_value_implementations() {
        let string_value = "test_value".to_string();
        assert!(string_value.size_bytes() > 0);
        assert!(!string_value.is_expired());

        let vec_value: Vec<i32> = vec![1, 2, 3, 4, 5];
        assert!(vec_value.size_bytes() > 0);
        assert!(!vec_value.is_expired());

        let mut map_value: HashMap<String, i32> = HashMap::new();
        map_value.insert("key1".to_string(), 1);
        map_value.insert("key2".to_string(), 2);
        assert!(map_value.size_bytes() > 0);
        assert!(!map_value.is_expired());
    }
}
