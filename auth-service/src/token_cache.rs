//! LRU Token Cache for efficient memory management
//!
//! Provides bounded caches for JWT tokens, sessions, and other authentication data
//! to prevent unbounded memory growth and improve performance.

use common::TokenRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Configuration for LRU token cache
#[derive(Debug, Clone)]
pub struct TokenCacheConfig {
    /// Maximum number of tokens to cache
    pub max_tokens: usize,
    /// Maximum age of cached tokens
    pub max_age: Duration,
    /// Cleanup interval for expired tokens
    pub cleanup_interval: Duration,
}

impl Default for TokenCacheConfig {
    fn default() -> Self {
        Self {
            max_tokens: 10_000,
            max_age: Duration::from_secs(3600),         // 1 hour
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Cache entry with access tracking for LRU eviction
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    last_accessed: Instant,
    created_at: Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T) -> Self {
        let now = Instant::now();
        Self {
            value,
            last_accessed: now,
            created_at: now,
        }
    }

    fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }

    fn is_expired(&self, max_age: Duration) -> bool {
        self.created_at.elapsed() > max_age
    }
}

/// LRU cache for tokens with automatic cleanup
pub struct LruTokenCache {
    cache: Arc<RwLock<HashMap<String, CacheEntry<TokenRecord>>>>,
    config: TokenCacheConfig,
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
}

impl LruTokenCache {
    /// Create a new LRU token cache with default configuration
    pub fn new() -> Self {
        Self::with_config(TokenCacheConfig::default())
    }

    /// Create a new LRU token cache with custom configuration
    pub fn with_config(config: TokenCacheConfig) -> Self {
        let cache = Arc::new(RwLock::new(HashMap::new()));
        let mut instance = Self {
            cache,
            config,
            cleanup_task: None,
        };

        instance.start_cleanup_task();
        instance
    }

    /// Start the background cleanup task
    fn start_cleanup_task(&mut self) {
        let cache: Arc<RwLock<HashMap<String, CacheEntry<TokenRecord>>>> = Arc::clone(&self.cache);
        let config = self.config.clone();

        self.cleanup_task = Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.cleanup_interval);

            loop {
                interval.tick().await;

                let mut cache_guard = cache.write().await;
                let initial_size = cache_guard.len();

                // Remove expired entries
                cache_guard.retain(|_, entry| !entry.is_expired(config.max_age));

                // If still over capacity, remove least recently used
                if cache_guard.len() > config.max_tokens {
                    let mut entries: Vec<_> = cache_guard.iter()
                        .map(|(k, v)| (k.clone(), v.last_accessed))
                        .collect();
                    entries.sort_by_key(|(_, last_accessed)| *last_accessed);

                    let to_remove = cache_guard.len() - config.max_tokens;
                    for (key, _) in entries.into_iter().take(to_remove) {
                        cache_guard.remove(&key);
                    }
                }

                let final_size = cache_guard.len();
                if final_size != initial_size {
                    info!(
                        "Token cache cleanup: {} -> {} entries (removed {})",
                        initial_size,
                        final_size,
                        initial_size - final_size
                    );
                }
            }
        }));
    }

    /// Get a token from the cache
    pub async fn get(&self, key: &str) -> Option<TokenRecord> {
        let mut cache = self.cache.write().await;

        if let Some(entry) = cache.get_mut(key) {
            if entry.is_expired(self.config.max_age) {
                cache.remove(key);
                None
            } else {
                entry.touch();
                Some(entry.value.clone())
            }
        } else {
            None
        }
    }

    /// Insert a token into the cache
    pub async fn insert(&self, key: String, token: TokenRecord) {
        let mut cache = self.cache.write().await;

        // If at capacity, remove least recently used
        if cache.len() >= self.config.max_tokens {
            if let Some((lru_key, _)) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.last_accessed)
                .map(|(k, v)| (k.clone(), v.clone()))
            {
                cache.remove(&lru_key);
                warn!("Evicted LRU token from cache: capacity reached");
            }
        }

        cache.insert(key, CacheEntry::new(token));
    }

    /// Remove a token from the cache
    pub async fn remove(&self, key: &str) -> Option<TokenRecord> {
        let mut cache = self.cache.write().await;
        cache.remove(key).map(|entry| entry.value)
    }

    /// Check if a token exists in the cache
    pub async fn contains(&self, key: &str) -> bool {
        let cache = self.cache.read().await;
        cache.contains_key(key) && !cache.get(key).unwrap().is_expired(self.config.max_age)
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let total_entries = cache.len();
        let expired_count = cache
            .values()
            .filter(|entry| entry.is_expired(self.config.max_age))
            .count();

        CacheStats {
            total_entries,
            expired_entries: expired_count,
            active_entries: total_entries - expired_count,
            max_capacity: self.config.max_tokens,
            hit_rate: 0.0, // Would need separate tracking for this
        }
    }

    /// Clear all entries from the cache
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("Token cache cleared");
    }
}

impl Drop for LruTokenCache {
    fn drop(&mut self) {
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
        }
    }
}

/// Cache performance statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub active_entries: usize,
    pub max_capacity: usize,
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_lru_cache_basic_operations() {
        let cache = LruTokenCache::new();
        let token = TokenRecord {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("test_client".to_string()),
            exp: Some(1234567890),
            iat: Some(1234567800),
            sub: Some("test_user".to_string()),
            token_binding: None,
            mfa_verified: false,
        };

        // Test insert and get
        cache.insert("key1".to_string(), token.clone()).await;
        let retrieved = cache.get("key1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().sub, Some("test_user".to_string()));

        // Test contains
        assert!(cache.contains("key1").await);
        assert!(!cache.contains("nonexistent").await);

        // Test remove
        let removed = cache.remove("key1").await;
        assert!(removed.is_some());
        assert!(!cache.contains("key1").await);
    }

    #[tokio::test]
    async fn test_lru_cache_capacity_limit() {
        let config = TokenCacheConfig {
            max_tokens: 2,
            ..Default::default()
        };
        let cache = LruTokenCache::with_config(config);

        let token = TokenRecord {
            active: true,
            scope: None,
            client_id: Some("test_client".to_string()),
            exp: Some(1234567890),
            iat: Some(1234567800),
            sub: Some("test_user".to_string()),
            token_binding: None,
            mfa_verified: false,
        };

        // Fill cache to capacity
        cache.insert("key1".to_string(), token.clone()).await;
        cache.insert("key2".to_string(), token.clone()).await;

        // Access key1 to make it more recently used
        cache.get("key1").await;

        // Insert third item, should evict key2 (LRU)
        cache.insert("key3".to_string(), token.clone()).await;

        assert!(cache.contains("key1").await);
        assert!(!cache.contains("key2").await);
        assert!(cache.contains("key3").await);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let config = TokenCacheConfig {
            max_age: Duration::from_millis(100),
            ..Default::default()
        };
        let cache = LruTokenCache::with_config(config);

        let token = TokenRecord {
            active: true,
            scope: None,
            client_id: Some("test_client".to_string()),
            exp: Some(1234567890),
            iat: Some(1234567800),
            sub: Some("test_user".to_string()),
            token_binding: None,
            mfa_verified: false,
        };

        cache.insert("key1".to_string(), token).await;
        assert!(cache.contains("key1").await);

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be expired
        assert!(!cache.contains("key1").await);
        assert!(cache.get("key1").await.is_none());
    }
}
