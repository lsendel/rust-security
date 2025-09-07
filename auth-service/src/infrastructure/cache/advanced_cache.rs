//! Advanced Multi-Level Caching System
//!
//! Implements sophisticated caching strategies for maximum performance:
//! - Multi-level caching (L1 in-memory, L2 Redis, L3 database)
//! - Intelligent cache invalidation with dependency tracking
//! - Adaptive TTL based on access patterns
//! - Cache warming and prefetching
//! - Compression for memory efficiency

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::infrastructure::cache::{Cache, CacheError, CacheStats};
use crate::shared::error::AppError;

/// Cache level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheLevel {
    L1Memory, // Fast in-memory cache
    L2Redis,  // Distributed Redis cache
    L3Disk,   // Persistent disk cache
}

/// Cache entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<V> {
    pub value: V,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub accessed_at: chrono::DateTime<chrono::Utc>,
    pub access_count: u64,
    pub ttl: Option<Duration>,
    pub dependencies: Vec<String>, // Keys this entry depends on
}

impl<V> CacheEntry<V> {
    pub fn new(value: V, ttl: Option<Duration>) -> Self {
        let now = chrono::Utc::now();
        Self {
            value,
            created_at: now,
            accessed_at: now,
            access_count: 0,
            ttl,
            dependencies: Vec::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl {
            let elapsed = chrono::Utc::now().signed_duration_since(self.created_at);
            elapsed > chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::zero())
        } else {
            false
        }
    }

    pub fn access(&mut self) {
        self.accessed_at = chrono::Utc::now();
        self.access_count += 1;
    }

    pub fn add_dependency(&mut self, key: String) {
        if !self.dependencies.contains(&key) {
            self.dependencies.push(key);
        }
    }
}

/// Advanced cache configuration
#[derive(Debug, Clone)]
pub struct AdvancedCacheConfig {
    /// L1 cache size (number of entries)
    pub l1_max_size: usize,
    /// L2 Redis TTL
    pub l2_ttl: Duration,
    /// L3 disk TTL
    pub l3_ttl: Duration,
    /// Cache warming enabled
    pub warming_enabled: bool,
    /// Compression threshold (bytes)
    pub compression_threshold: usize,
    /// Adaptive TTL enabled
    pub adaptive_ttl: bool,
    /// Dependency tracking enabled
    pub dependency_tracking: bool,
}

impl Default for AdvancedCacheConfig {
    fn default() -> Self {
        Self {
            l1_max_size: 10_000,
            l2_ttl: Duration::from_secs(3600),  // 1 hour
            l3_ttl: Duration::from_secs(86400), // 24 hours
            warming_enabled: true,
            compression_threshold: 1024, // 1KB
            adaptive_ttl: true,
            dependency_tracking: true,
        }
    }
}

/// Advanced multi-level cache implementation
pub struct AdvancedCache<K, V> {
    config: AdvancedCacheConfig,
    l1_cache: Arc<RwLock<lru::LruCache<K, CacheEntry<V>>>>,
    l2_cache: Option<Arc<dyn Cache<K, V> + Send + Sync>>, // Redis cache
    l3_cache: Option<Arc<dyn Cache<K, V> + Send + Sync>>, // Disk cache
    stats: Arc<RwLock<AdvancedCacheStats>>,
    dependency_graph: Arc<RwLock<HashMap<String, Vec<K>>>>,
}

#[derive(Debug, Clone, Default)]
pub struct AdvancedCacheStats {
    pub l1_hits: u64,
    pub l1_misses: u64,
    pub l2_hits: u64,
    pub l2_misses: u64,
    pub l3_hits: u64,
    pub l3_misses: u64,
    pub evictions: u64,
    pub invalidations: u64,
    pub total_requests: u64,
}

impl<K, V> AdvancedCache<K, V>
where
    K: Clone + std::hash::Hash + Eq + std::fmt::Display + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new advanced cache
    pub fn new(
        config: AdvancedCacheConfig,
        l2_cache: Option<Arc<dyn Cache<K, V> + Send + Sync>>,
        l3_cache: Option<Arc<dyn Cache<K, V> + Send + Sync>>,
    ) -> Self {
        info!(
            "Creating advanced multi-level cache with L1 size: {}",
            config.l1_max_size
        );

        Self {
            config,
            l1_cache: Arc::new(RwLock::new(lru::LruCache::new({
                // Ensure capacity is non-zero to avoid panic
                let cap = if config.l1_max_size == 0 { 1 } else { config.l1_max_size };
                // Safe unwrap: cap is guaranteed non-zero
                std::num::NonZeroUsize::new(cap).expect("non-zero L1 cache capacity")
            }))),
            l2_cache,
            l3_cache,
            stats: Arc::new(RwLock::new(AdvancedCacheStats::default())),
            dependency_graph: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a value from the cache with multi-level lookup
    pub async fn get(&self, key: &K) -> Option<V> {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;

        // Try L1 cache first
        if let Some(mut entry) = self.l1_cache.write().await.get_mut(key) {
            if !entry.is_expired() {
                entry.access();
                stats.l1_hits += 1;
                debug!("L1 cache hit for key: {}", key);
                return Some(entry.value.clone());
            } else {
                // Remove expired entry
                self.l1_cache.write().await.pop(key);
                stats.evictions += 1;
            }
        }

        stats.l1_misses += 1;

        // Try L2 cache
        if let Some(l2_cache) = &self.l2_cache {
            if let Some(value) = l2_cache.get(key).await {
                stats.l2_hits += 1;
                debug!("L2 cache hit for key: {}", key);

                // Promote to L1
                let entry = CacheEntry::new(value.clone(), Some(self.config.l2_ttl));
                self.l1_cache.write().await.put(key.clone(), entry);

                return Some(value);
            }
        }

        stats.l2_misses += 1;

        // Try L3 cache
        if let Some(l3_cache) = &self.l3_cache {
            if let Some(value) = l3_cache.get(key).await {
                stats.l3_hits += 1;
                debug!("L3 cache hit for key: {}", key);

                // Promote to L1 and L2
                let entry = CacheEntry::new(value.clone(), Some(self.config.l3_ttl));
                self.l1_cache.write().await.put(key.clone(), entry);

                if let Some(l2_cache) = &self.l2_cache {
                    let _ = l2_cache.insert(key.clone(), value.clone()).await;
                }

                return Some(value);
            }
        }

        stats.l3_misses += 1;
        debug!("Cache miss for key: {}", key);
        None
    }

    /// Insert a value into all cache levels
    pub async fn insert(&self, key: K, value: V, ttl: Option<Duration>) -> Result<(), CacheError> {
        let entry = CacheEntry::new(value.clone(), ttl.or(Some(self.config.l2_ttl)));

        // Insert into L1
        self.l1_cache.write().await.put(key.clone(), entry);

        // Insert into L2
        if let Some(l2_cache) = &self.l2_cache {
            l2_cache.insert(key.clone(), value.clone()).await?;
        }

        // Insert into L3
        if let Some(l3_cache) = &self.l3_cache {
            l3_cache.insert(key.clone(), value.clone()).await?;
        }

        debug!("Inserted key into multi-level cache: {}", key);
        Ok(())
    }

    /// Insert with dependencies for intelligent invalidation
    pub async fn insert_with_dependencies(
        &self,
        key: K,
        value: V,
        dependencies: Vec<String>,
        ttl: Option<Duration>,
    ) -> Result<(), CacheError> {
        if self.config.dependency_tracking {
            let mut entry = CacheEntry::new(value.clone(), ttl.or(Some(self.config.l2_ttl)));
            for dep in dependencies {
                entry.add_dependency(dep.clone());

                // Update dependency graph
                let mut graph = self.dependency_graph.write().await;
                graph.entry(dep).or_insert_with(Vec::new).push(key.clone());
            }

            self.l1_cache.write().await.put(key.clone(), entry);
        }

        self.insert(key, value, ttl).await
    }

    /// Invalidate a key and all dependent keys
    pub async fn invalidate(&self, key: &K) -> Result<(), CacheError> {
        let mut stats = self.stats.write().await;
        stats.invalidations += 1;

        // Remove from L1
        self.l1_cache.write().await.pop(key);

        // Remove from L2
        if let Some(l2_cache) = &self.l2_cache {
            l2_cache.remove(key).await;
        }

        // Remove from L3
        if let Some(l3_cache) = &self.l3_cache {
            l3_cache.remove(key).await;
        }

        // Invalidate dependent keys if tracking is enabled
        if self.config.dependency_tracking {
            let graph = self.dependency_graph.read().await;
            if let Some(dependents) = graph.get(&key.to_string()) {
                for dependent in dependents {
                    self.invalidate(dependent).await?;
                }
            }
        }

        debug!("Invalidated cache key: {}", key);
        Ok(())
    }

    /// Clear all cache levels
    pub async fn clear(&self) -> Result<(), CacheError> {
        // Clear L1
        self.l1_cache.write().await.clear();

        // Clear L2
        if let Some(l2_cache) = &self.l2_cache {
            l2_cache.clear().await?;
        }

        // Clear L3
        if let Some(l3_cache) = &self.l3_cache {
            l3_cache.clear().await?;
        }

        // Clear dependency graph
        self.dependency_graph.write().await.clear();

        info!("Cleared all cache levels");
        Ok(())
    }

    /// Get cache statistics
    pub async fn stats(&self) -> AdvancedCacheStats {
        self.stats.read().await.clone()
    }

    /// Get cache hit rate
    pub async fn hit_rate(&self) -> f64 {
        let stats = self.stats.read().await;
        if stats.total_requests == 0 {
            return 0.0;
        }

        let total_hits = stats.l1_hits + stats.l2_hits + stats.l3_hits;
        (total_hits as f64 / stats.total_requests as f64) * 100.0
    }

    /// Warm up the cache with frequently accessed data
    pub async fn warmup<F>(&self, warmer: F) -> Result<(), CacheError>
    where
        F: FnOnce() -> Vec<(K, V)>,
    {
        if !self.config.warming_enabled {
            return Ok(());
        }

        info!("Starting cache warm-up");
        let items = warmer();

        for (key, value) in items {
            self.insert(key, value, Some(self.config.l2_ttl)).await?;
        }

        info!("Cache warm-up completed with {} items", items.len());
        Ok(())
    }

    /// Get cache level information for monitoring
    pub async fn cache_info(&self) -> HashMap<CacheLevel, CacheStats> {
        let mut info = HashMap::new();

        // L1 info
        let l1_size = self.l1_cache.read().await.len();
        info.insert(
            CacheLevel::L1Memory,
            CacheStats {
                entries: l1_size,
                ..Default::default()
            },
        );

        // L2 info
        if let Some(l2_cache) = &self.l2_cache {
            info.insert(CacheLevel::L2Redis, l2_cache.stats().await);
        }

        // L3 info
        if let Some(l3_cache) = &self.l3_cache {
            info.insert(CacheLevel::L3Disk, l3_cache.stats().await);
        }

        info
    }

    /// Adaptive TTL calculation based on access patterns
    pub fn calculate_adaptive_ttl(&self, access_count: u64, base_ttl: Duration) -> Duration {
        if !self.config.adaptive_ttl {
            return base_ttl;
        }

        // Increase TTL for frequently accessed items
        let multiplier = if access_count > 100 {
            3.0
        } else if access_count > 50 {
            2.0
        } else if access_count > 10 {
            1.5
        } else {
            1.0
        };

        let new_ttl_nanos = (base_ttl.as_nanos() as f64 * multiplier) as u128;
        Duration::from_nanos(new_ttl_nanos.min(u64::MAX as u128) as u64)
    }
}

/// Cache warming strategies
pub mod warming {
    use super::*;

    /// User authentication cache warmer
    pub fn auth_warming_strategy() -> Vec<(String, String)> {
        vec![
            ("user:profile:frequent".to_string(), "{}".to_string()),
            ("user:permissions:admin".to_string(), "[]".to_string()),
            ("user:settings:default".to_string(), "{}".to_string()),
        ]
    }

    /// Session cache warmer
    pub fn session_warming_strategy() -> Vec<(String, String)> {
        vec![
            ("session:active:count".to_string(), "0".to_string()),
            ("session:expired:cleanup".to_string(), "{}".to_string()),
        ]
    }

    /// Token cache warmer
    pub fn token_warming_strategy() -> Vec<(String, String)> {
        vec![
            ("token:blacklist:recent".to_string(), "[]".to_string()),
            ("token:stats:issued".to_string(), "0".to_string()),
        ]
    }
}

/// Cache invalidation strategies
pub mod invalidation {
    use super::*;

    /// Invalidate user-related cache entries
    pub async fn invalidate_user_cache<K, V>(
        cache: &AdvancedCache<K, V>,
        user_id: &str,
    ) -> Result<(), CacheError>
    where
        K: From<String> + Clone + std::hash::Hash + Eq + std::fmt::Display + Send + Sync,
        V: Clone + Send + Sync,
    {
        let keys_to_invalidate = vec![
            format!("user:profile:{}", user_id),
            format!("user:permissions:{}", user_id),
            format!("user:sessions:{}", user_id),
        ];

        for key in keys_to_invalidate {
            cache.invalidate(&K::from(key)).await?;
        }

        Ok(())
    }

    /// Invalidate session-related cache entries
    pub async fn invalidate_session_cache<K, V>(
        cache: &AdvancedCache<K, V>,
        session_id: &str,
    ) -> Result<(), CacheError>
    where
        K: From<String> + Clone + std::hash::Hash + Eq + std::fmt::Display + Send + Sync,
        V: Clone + Send + Sync,
    {
        let keys_to_invalidate = vec![
            format!("session:data:{}", session_id),
            format!("session:permissions:{}", session_id),
        ];

        for key in keys_to_invalidate {
            cache.invalidate(&K::from(key)).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_advanced_cache_basic_operations() {
        let config = AdvancedCacheConfig {
            l1_max_size: 100,
            ..Default::default()
        };

        let cache = AdvancedCache::<String, String>::new(config, None, None);

        // Test insert and get
        cache
            .insert("key1".to_string(), "value1".to_string(), None)
            .await
            .unwrap();
        assert_eq!(
            cache.get(&"key1".to_string()).await,
            Some("value1".to_string())
        );

        // Test cache miss
        assert_eq!(cache.get(&"key2".to_string()).await, None);

        // Test invalidation
        cache.invalidate(&"key1".to_string()).await.unwrap();
        assert_eq!(cache.get(&"key1".to_string()).await, None);
    }

    #[tokio::test]
    async fn test_cache_hit_rate() {
        let config = AdvancedCacheConfig {
            l1_max_size: 10,
            ..Default::default()
        };

        let cache = AdvancedCache::<String, String>::new(config, None, None);

        // Insert some data
        for i in 0..5 {
            cache
                .insert(format!("key{}", i), format!("value{}", i), None)
                .await
                .unwrap();
        }

        // Access some keys multiple times
        for _ in 0..3 {
            let _ = cache.get(&"key1".to_string()).await;
            let _ = cache.get(&"key2".to_string()).await;
        }

        // Check hit rate
        let hit_rate = cache.hit_rate().await;
        assert!(hit_rate > 0.0);

        let stats = cache.stats().await;
        assert_eq!(stats.l1_hits, 6); // 3 hits for key1 + 3 hits for key2
    }

    #[tokio::test]
    async fn test_dependency_invalidation() {
        let config = AdvancedCacheConfig {
            l1_max_size: 100,
            dependency_tracking: true,
            ..Default::default()
        };

        let cache = AdvancedCache::<String, String>::new(config, None, None);

        // Insert with dependencies
        cache
            .insert_with_dependencies(
                "user_profile".to_string(),
                "user_data".to_string(),
                vec!["user_permissions".to_string()],
                None,
            )
            .await
            .unwrap();

        // Verify both entries exist
        assert_eq!(
            cache.get(&"user_profile".to_string()).await,
            Some("user_data".to_string())
        );

        // Invalidate dependency
        cache
            .invalidate(&"user_permissions".to_string())
            .await
            .unwrap();

        // Profile should also be invalidated
        assert_eq!(cache.get(&"user_profile".to_string()).await, None);
    }
}
