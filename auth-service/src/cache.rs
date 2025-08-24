use redis::{AsyncCommands, Client};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[cfg(feature = "monitoring")]
#[cfg(feature = "monitoring")]
use crate::metrics::{MetricsHelper, METRICS};

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Redis connection URL
    pub redis_url: Option<String>,
    /// Default TTL for cached items (in seconds)
    pub default_ttl: u64,
    /// Maximum size for in-memory cache
    pub max_memory_cache_size: usize,
    /// Whether to use Redis for distributed caching
    pub use_redis: bool,
    /// Cache key prefix
    pub key_prefix: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            redis_url: None,
            default_ttl: 300, // 5 minutes
            max_memory_cache_size: 1000,
            use_redis: false,
            key_prefix: "rust_security:".to_string(),
        }
    }
}

/// Cached item with expiration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedItem<T> {
    data: T,
    expires_at: u64,
}

impl<T> CachedItem<T> {
    fn new(data: T, ttl_seconds: u64) -> Self {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + ttl_seconds;

        Self { data, expires_at }
    }

    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }
}

/// Multi-tier cache implementation with Redis and in-memory fallback
pub struct Cache {
    config: CacheConfig,
    redis_client: Option<Client>,
    memory_cache: Arc<RwLock<HashMap<String, CachedItem<Vec<u8>>>>>,
}

impl Cache {
    /// Create a new cache instance
    pub async fn new(config: CacheConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let redis_client = if config.use_redis && config.redis_url.is_some() {
            match Client::open(config.redis_url.as_ref().unwrap().as_str()) {
                Ok(client) => {
                    // Test the connection
                    match client.get_async_connection().await {
                        Ok(mut conn) => {
                            let _: String = conn.ping().await?;
                            info!("Redis cache connection established");
                            Some(client)
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to connect to Redis, falling back to memory cache");
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to create Redis client, using memory cache only");
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            config,
            redis_client,
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get an item from cache
    pub async fn get<T>(&self, key: &str) -> Option<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let start_time = Instant::now();
        let full_key = format!("{}{}", self.config.key_prefix, key);

        // Try Redis first if available
        if let Some(ref client) = self.redis_client {
            match self.get_from_redis(&full_key).await {
                Ok(Some(data)) => {
                    debug!(key = %key, "Cache hit (Redis)");
                    let duration = start_time.elapsed();
                    MetricsHelper::record_cache_operation("redis", "get", "hit", duration);
                    return Some(data);
                }
                Ok(None) => {
                    debug!(key = %key, "Cache miss (Redis)");
                }
                Err(e) => {
                    warn!(key = %key, error = %e, "Redis cache error, falling back to memory");
                    let duration = start_time.elapsed();
                    MetricsHelper::record_cache_operation("redis", "get", "error", duration);
                }
            }
        }

        // Fall back to memory cache
        match self.get_from_memory(&full_key).await {
            Some(data) => {
                debug!(key = %key, "Cache hit (Memory)");
                let duration = start_time.elapsed();
                MetricsHelper::record_cache_operation("memory", "get", "hit", duration);
                Some(data)
            }
            None => {
                debug!(key = %key, "Cache miss (Memory)");
                let duration = start_time.elapsed();
                MetricsHelper::record_cache_operation("memory", "get", "miss", duration);
                None
            }
        }
    }

    /// Set an item in cache
    pub async fn set<T>(&self, key: &str, value: &T, ttl: Option<Duration>) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        T: Serialize,
    {
        let start_time = Instant::now();
        let full_key = format!("{}{}", self.config.key_prefix, key);
        let ttl_seconds = ttl.unwrap_or(Duration::from_secs(self.config.default_ttl)).as_secs();

        let serialized = serde_json::to_vec(value)?;

        // Set in Redis if available
        if let Some(ref client) = self.redis_client {
            if let Err(e) = self.set_in_redis(&full_key, &serialized, ttl_seconds).await {
                warn!(key = %key, error = %e, "Failed to set in Redis cache");
            } else {
                debug!(key = %key, ttl = ttl_seconds, "Set in Redis cache");
            }
        }

        // Always set in memory cache as fallback
        self.set_in_memory(&full_key, serialized, ttl_seconds).await;
        debug!(key = %key, ttl = ttl_seconds, "Set in memory cache");
        
        // Record cache set operation
        let duration = start_time.elapsed();
        MetricsHelper::record_cache_operation("memory", "set", "success", duration);

        Ok(())
    }

    /// Delete an item from cache
    pub async fn delete(&self, key: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let full_key = format!("{}{}", self.config.key_prefix, key);

        // Delete from Redis if available
        if let Some(ref client) = self.redis_client {
            if let Err(e) = self.delete_from_redis(&full_key).await {
                warn!(key = %key, error = %e, "Failed to delete from Redis cache");
            }
        }

        // Delete from memory cache
        self.delete_from_memory(&full_key).await;
        debug!(key = %key, "Deleted from cache");

        Ok(())
    }

    /// Clear all cached items
    pub async fn clear(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Clear Redis if available
        if let Some(ref client) = self.redis_client {
            if let Err(e) = self.clear_redis().await {
                warn!(error = %e, "Failed to clear Redis cache");
            }
        }

        // Clear memory cache
        self.clear_memory().await;
        info!("Cache cleared");

        Ok(())
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let memory_size = self.memory_cache.read().await.len();

        CacheStats {
            memory_cache_size: memory_size,
            redis_available: self.redis_client.is_some(),
            max_memory_cache_size: self.config.max_memory_cache_size,
        }
    }

    // Redis operations
    async fn get_from_redis<T>(&self, key: &str) -> Result<Option<T>, Box<dyn std::error::Error + Send + Sync>>
    where
        T: for<'de> Deserialize<'de>,
    {
        if let Some(ref client) = self.redis_client {
            let mut conn = client.get_async_connection().await?;
            let data: Option<Vec<u8>> = conn.get(key).await?;

            if let Some(bytes) = data {
                let deserialized: T = serde_json::from_slice(&bytes)?;
                return Ok(Some(deserialized));
            }
        }
        Ok(None)
    }

    async fn set_in_redis(&self, key: &str, data: &[u8], ttl_seconds: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref client) = self.redis_client {
            let mut conn = client.get_async_connection().await?;
            conn.set_ex(key, data, ttl_seconds).await?;
        }
        Ok(())
    }

    async fn delete_from_redis(&self, key: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref client) = self.redis_client {
            let mut conn = client.get_async_connection().await?;
            let _: i32 = conn.del(key).await?;
        }
        Ok(())
    }

    async fn clear_redis(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ref client) = self.redis_client {
            let mut conn = client.get_async_connection().await?;
            let pattern = format!("{}*", self.config.key_prefix);
            let keys: Vec<String> = conn.keys(pattern).await?;

            if !keys.is_empty() {
                let _: i32 = conn.del(keys).await?;
            }
        }
        Ok(())
    }

    // Memory cache operations
    async fn get_from_memory<T>(&self, key: &str) -> Option<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let cache = self.memory_cache.read().await;

        if let Some(cached_item) = cache.get(key) {
            if !cached_item.is_expired() {
                if let Ok(deserialized) = serde_json::from_slice(&cached_item.data) {
                    return Some(deserialized);
                }
            }
        }
        None
    }

    async fn set_in_memory(&self, key: &str, data: Vec<u8>, ttl_seconds: u64) {
        let mut cache = self.memory_cache.write().await;

        // Clean up expired items if cache is getting full
        if cache.len() >= self.config.max_memory_cache_size {
            self.cleanup_expired_memory_items(&mut cache).await;
        }

        // If still full, remove oldest items
        if cache.len() >= self.config.max_memory_cache_size {
            // Simple LRU: remove some items (in a real implementation, you'd track access times)
            let keys_to_remove: Vec<String> = cache.keys().take(cache.len() / 4).cloned().collect();
            for key in keys_to_remove {
                cache.remove(&key);
            }
        }

        let cached_item = CachedItem::new(data, ttl_seconds);
        cache.insert(key.to_string(), cached_item);
    }

    async fn delete_from_memory(&self, key: &str) {
        let mut cache = self.memory_cache.write().await;
        cache.remove(key);
    }

    async fn clear_memory(&self) {
        let mut cache = self.memory_cache.write().await;
        cache.clear();
    }

    async fn cleanup_expired_memory_items(&self, cache: &mut HashMap<String, CachedItem<Vec<u8>>>) {
        let expired_keys: Vec<String> = cache
            .iter()
            .filter(|(_, item)| item.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            cache.remove(&key);
        }
    }
}

/// Cache statistics
#[derive(Debug, Serialize)]
pub struct CacheStats {
    pub memory_cache_size: usize,
    pub redis_available: bool,
    pub max_memory_cache_size: usize,
}

/// Cached token introspection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTokenInfo {
    pub active: bool,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub exp: Option<u64>,
}

/// Cache middleware for token introspection
pub async fn cached_token_introspection(
    cache: &Cache,
    token: &str,
    introspect_fn: impl std::future::Future<Output = Result<CachedTokenInfo, Box<dyn std::error::Error + Send + Sync>>>,
) -> Result<CachedTokenInfo, Box<dyn std::error::Error + Send + Sync>> {
    let cache_key = format!("token_introspect:{}", token);

    // Try to get from cache first
    if let Some(cached_info) = cache.get::<CachedTokenInfo>(&cache_key).await {
        debug!("Token introspection cache hit");
        return Ok(cached_info);
    }

    // Not in cache, perform introspection
    debug!("Token introspection cache miss, performing lookup");
    let token_info = introspect_fn.await?;

    // Cache the result with appropriate TTL
    let ttl = if token_info.active {
        // Cache active tokens for shorter time
        Duration::from_secs(60)
    } else {
        // Cache inactive tokens for longer (they won't become active again)
        Duration::from_secs(300)
    };

    if let Err(e) = cache.set(&cache_key, &token_info, Some(ttl)).await {
        warn!(error = %e, "Failed to cache token introspection result");
    }

    Ok(token_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_memory_cache_basic_operations() {
        let config = CacheConfig {
            use_redis: false,
            ..Default::default()
        };

        let cache = Cache::new(config).await.unwrap();

        // Test set and get
        let test_data = json!({"test": "value"});
        cache.set("test_key", &test_data, None).await.unwrap();

        let retrieved: serde_json::Value = cache.get("test_key").await.unwrap();
        assert_eq!(retrieved, test_data);

        // Test delete
        cache.delete("test_key").await.unwrap();
        let deleted: Option<serde_json::Value> = cache.get("test_key").await;
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let config = CacheConfig {
            use_redis: false,
            default_ttl: 1, // 1 second
            ..Default::default()
        };

        let cache = Cache::new(config).await.unwrap();

        let test_data = json!({"test": "value"});
        cache.set("test_key", &test_data, Some(Duration::from_millis(100))).await.unwrap();

        // Should be available immediately
        let retrieved: Option<serde_json::Value> = cache.get("test_key").await;
        assert!(retrieved.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Should be expired now
        let expired: Option<serde_json::Value> = cache.get("test_key").await;
        assert!(expired.is_none());
    }

    #[test]
    fn test_cached_item_expiration() {
        let item = CachedItem::new("test".to_string(), 0); // Expires immediately
        assert!(item.is_expired());

        let item = CachedItem::new("test".to_string(), 3600); // Expires in 1 hour
        assert!(!item.is_expired());
    }
}
