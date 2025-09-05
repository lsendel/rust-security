use crate::mfa::errors::{MfaError, MfaResult};
use crate::mfa::totp_enhanced::EnhancedTotpConfig;
#[cfg(feature = "redis-sessions")]
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    pub value: T,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub access_count: u64,
    pub last_accessed: u64,
}

impl<T> CacheEntry<T> {
    pub fn new(value: T, ttl: Option<Duration>) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Self {
            value,
            created_at: now,
            expires_at: ttl.map(|d| now + d.as_secs()),
            access_count: 0,
            last_accessed: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            now > expires_at
        } else {
            false
        }
    }

    pub fn access(&mut self) -> &T {
        self.access_count += 1;
        self.last_accessed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        &self.value
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCacheData {
    pub secret: Vec<u8>,
    pub config: EnhancedTotpConfig,
    pub user_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSessionCache {
    pub user_id: String,
    pub mfa_verified: bool,
    pub verification_time: u64,
    pub session_timeout: Duration,
    pub risk_score: f64,
    pub device_trusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitCache {
    pub attempts: u32,
    pub window_start: u64,
    pub blocked_until: Option<u64>,
}

pub struct MultiLayerMfaCache {
    // L1: In-memory cache (fastest)
    l1_totp_cache: Arc<RwLock<HashMap<String, CacheEntry<TotpCacheData>>>>,
    l1_session_cache: Arc<RwLock<HashMap<String, CacheEntry<UserSessionCache>>>>,
    l1_rate_limit_cache: Arc<RwLock<HashMap<String, CacheEntry<RateLimitCache>>>>,

    // L2: Redis cache (distributed)
    redis: Option<ConnectionManager>,

    // Cache configuration
    config: CacheConfig,

    // Cache statistics
    stats: Arc<RwLock<CacheStats>>,
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub l1_max_entries: usize,
    pub l1_ttl: Duration,
    pub l2_ttl: Duration,
    pub totp_cache_ttl: Duration,
    pub session_cache_ttl: Duration,
    pub rate_limit_cache_ttl: Duration,
    pub enable_compression: bool,
    pub enable_encryption: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            l1_max_entries: 10000,
            l1_ttl: Duration::from_secs(300), // 5 minutes
            l2_ttl: Duration::from_secs(3600), // 1 hour
            totp_cache_ttl: Duration::from_secs(300), // 5 minutes
            session_cache_ttl: Duration::from_secs(1800), // 30 minutes
            rate_limit_cache_ttl: Duration::from_secs(300), // 5 minutes
            enable_compression: true,
            enable_encryption: false, // Secrets are already encrypted
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub l1_hits: u64,
    pub l1_misses: u64,
    pub l2_hits: u64,
    pub l2_misses: u64,
    pub evictions: u64,
    pub errors: u64,
}

impl CacheStats {
    pub fn hit_ratio(&self) -> f64 {
        let total_requests = self.l1_hits + self.l1_misses + self.l2_hits + self.l2_misses;
        if total_requests == 0 {
            0.0
        } else {
            (self.l1_hits + self.l2_hits) as f64 / total_requests as f64
        }
    }

    pub fn l1_hit_ratio(&self) -> f64 {
        let l1_total = self.l1_hits + self.l1_misses;
        if l1_total == 0 {
            0.0
        } else {
            self.l1_hits as f64 / l1_total as f64
        }
    }
}

impl MultiLayerMfaCache {
    pub async fn new(config: CacheConfig) -> Self {
        let redis = Self::create_redis_connection().await;

        Self {
            l1_totp_cache: Arc::new(RwLock::new(HashMap::new())),
            l1_session_cache: Arc::new(RwLock::new(HashMap::new())),
            l1_rate_limit_cache: Arc::new(RwLock::new(HashMap::new())),
            redis,
            config,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    pub async fn with_default_config() -> Self {
        Self::new(CacheConfig::default()).await
    }

    async fn create_redis_connection() -> Option<ConnectionManager> {
        let url = std::env::var("REDIS_URL").ok()?;
        let client = redis::Client::open(url).ok()?;
        client.get_connection_manager().await.ok()
    }

    // TOTP Data Caching
    pub async fn get_totp_data(&self, user_id: &str) -> MfaResult<Option<TotpCacheData>> {
        // L1 Cache check
        {
            let mut l1_cache = self.l1_totp_cache.write().await;
            if let Some(entry) = l1_cache.get_mut(user_id) {
                if !entry.is_expired() {
                    self.record_l1_hit().await;
                    return Ok(Some(entry.access().clone()));
                } else {
                    l1_cache.remove(user_id);
                }
            }
        }

        self.record_l1_miss().await;

        // L2 Cache check (Redis)
        if let Some(data) = self.get_from_l2_cache(&format!("mfa:totp:{}", user_id)).await? {
            let totp_data: TotpCacheData = serde_json::from_str(&data)?;

            // Populate L1 cache
            self.set_l1_totp_cache(user_id, &totp_data).await?;

            self.record_l2_hit().await;
            return Ok(Some(totp_data));
        }

        self.record_l2_miss().await;
        Ok(None)
    }

    pub async fn set_totp_data(&self, user_id: &str, data: &TotpCacheData) -> MfaResult<()> {
        // Set in L1 cache
        self.set_l1_totp_cache(user_id, data).await?;

        // Set in L2 cache (Redis)
        if let Some(mut conn) = self.redis.clone() {
            let key = format!("mfa:totp:{}", user_id);
            let serialized = serde_json::to_string(data)?;
            let compressed = if self.config.enable_compression {
                self.compress_data(&serialized)?
            } else {
                serialized.into_bytes()
            };

            conn.set_ex(&key, compressed, self.config.totp_cache_ttl.as_secs())
                .await
                .map_err(|e| MfaError::Internal)?;
        }

        Ok(())
    }

    async fn set_l1_totp_cache(&self, user_id: &str, data: &TotpCacheData) -> MfaResult<()> {
        let mut l1_cache = self.l1_totp_cache.write().await;

        // LRU eviction if cache is full
        if l1_cache.len() >= self.config.l1_max_entries {
            self.evict_lru_totp_entry(&mut l1_cache).await;
        }

        let entry = CacheEntry::new(data.clone(), Some(self.config.l1_ttl));
        l1_cache.insert(user_id.to_string(), entry);

        Ok(())
    }

    // Session Caching
    pub async fn get_session_data(&self, session_id: &str) -> MfaResult<Option<UserSessionCache>> {
        // L1 Cache check
        {
            let mut l1_cache = self.l1_session_cache.write().await;
            if let Some(entry) = l1_cache.get_mut(session_id) {
                if !entry.is_expired() {
                    self.record_l1_hit().await;
                    return Ok(Some(entry.access().clone()));
                } else {
                    l1_cache.remove(session_id);
                }
            }
        }

        self.record_l1_miss().await;

        // L2 Cache check
        if let Some(data) = self.get_from_l2_cache(&format!("mfa:session:{}", session_id)).await? {
            let session_data: UserSessionCache = serde_json::from_str(&data)?;

            // Populate L1 cache
            self.set_l1_session_cache(session_id, &session_data).await?;

            self.record_l2_hit().await;
            return Ok(Some(session_data));
        }

        self.record_l2_miss().await;
        Ok(None)
    }

    pub async fn set_session_data(&self, session_id: &str, data: &UserSessionCache) -> MfaResult<()> {
        // Set in L1 cache
        self.set_l1_session_cache(session_id, data).await?;

        // Set in L2 cache
        if let Some(mut conn) = self.redis.clone() {
            let key = format!("mfa:session:{}", session_id);
            let serialized = serde_json::to_string(data)?;
            let compressed = if self.config.enable_compression {
                self.compress_data(&serialized)?
            } else {
                serialized.into_bytes()
            };

            conn.set_ex(&key, compressed, self.config.session_cache_ttl.as_secs())
                .await
                .map_err(|e| MfaError::Internal)?;
        }

        Ok(())
    }

    async fn set_l1_session_cache(&self, session_id: &str, data: &UserSessionCache) -> MfaResult<()> {
        let mut l1_cache = self.l1_session_cache.write().await;

        if l1_cache.len() >= self.config.l1_max_entries {
            self.evict_lru_session_entry(&mut l1_cache).await;
        }

        let entry = CacheEntry::new(data.clone(), Some(self.config.l1_ttl));
        l1_cache.insert(session_id.to_string(), entry);

        Ok(())
    }

    // Rate Limit Caching
    pub async fn get_rate_limit_data(&self, key: &str) -> MfaResult<Option<RateLimitCache>> {
        // Check L1 cache first for rate limiting (critical for performance)
        {
            let mut l1_cache = self.l1_rate_limit_cache.write().await;
            if let Some(entry) = l1_cache.get_mut(key) {
                if !entry.is_expired() {
                    self.record_l1_hit().await;
                    return Ok(Some(entry.access().clone()));
                } else {
                    l1_cache.remove(key);
                }
            }
        }

        // For rate limiting, we generally don't check L2 cache to avoid latency
        // Rate limiting data is often better fresh from Redis directly
        Ok(None)
    }

    pub async fn set_rate_limit_data(&self, key: &str, data: &RateLimitCache) -> MfaResult<()> {
        // Set in L1 cache for fast access
        let mut l1_cache = self.l1_rate_limit_cache.write().await;

        if l1_cache.len() >= self.config.l1_max_entries {
            self.evict_lru_rate_limit_entry(&mut l1_cache).await;
        }

        let entry = CacheEntry::new(data.clone(), Some(self.config.rate_limit_cache_ttl));
        l1_cache.insert(key.to_string(), entry);

        Ok(())
    }

    // Generic L2 cache operations
    async fn get_from_l2_cache(&self, key: &str) -> MfaResult<Option<String>> {
        let Some(mut conn) = self.redis.clone() else {
            return Ok(None);
        };

        let data: Option<Vec<u8>> = conn.get(key).await.map_err(|e| {
            self.record_error();
            MfaError::Internal
        })?;

        match data {
            Some(compressed_data) => {
                let decompressed = if self.config.enable_compression {
                    self.decompress_data(&compressed_data)?
                } else {
                    String::from_utf8(compressed_data).map_err(|_| MfaError::Internal)?
                };
                Ok(Some(decompressed))
            }
            None => Ok(None),
        }
    }

    // Cache invalidation
    pub async fn invalidate_user_caches(&self, user_id: &str) -> MfaResult<()> {
        // Invalidate L1 caches
        {
            let mut totp_cache = self.l1_totp_cache.write().await;
            totp_cache.remove(user_id);
        }

        // Find and remove session caches for this user
        {
            let mut session_cache = self.l1_session_cache.write().await;
            let keys_to_remove: Vec<String> = session_cache
                .iter()
                .filter(|(_, entry)| entry.value.user_id == user_id)
                .map(|(key, _)| key.clone())
                .collect();

            for key in keys_to_remove {
                session_cache.remove(&key);
            }
        }

        // Invalidate L2 caches
        if let Some(mut conn) = self.redis.clone() {
            let patterns = vec![
                format!("mfa:totp:{}", user_id),
                "mfa:session:*".to_string(), // Would need more specific pattern in real implementation
            ];

            for pattern in patterns {
                if pattern.contains('*') {
                    let keys: Vec<String> = conn.keys(&pattern).await.unwrap_or_default();
                    if !keys.is_empty() {
                        let _: u64 = conn.del(&keys).await.unwrap_or_default();
                    }
                } else {
                    let _: u64 = conn.del(&pattern).await.unwrap_or_default();
                }
            }
        }

        Ok(())
    }

    // Cache warming
    pub async fn warm_cache(&self, user_ids: &[String]) -> MfaResult<u32> {
        let mut warmed = 0;

        for user_id in user_ids {
            // Pre-load frequently accessed data
            if let Ok(Some(_)) = self.get_totp_data(user_id).await {
                warmed += 1;
            }
        }

        tracing::info!("Cache warming completed: {} entries warmed", warmed);
        Ok(warmed)
    }

    // LRU Eviction
    async fn evict_lru_totp_entry(&self, cache: &mut HashMap<String, CacheEntry<TotpCacheData>>) {
        if let Some(lru_key) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&lru_key);
            self.record_eviction().await;
        }
    }

    async fn evict_lru_session_entry(&self, cache: &mut HashMap<String, CacheEntry<UserSessionCache>>) {
        if let Some(lru_key) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&lru_key);
            self.record_eviction().await;
        }
    }

    async fn evict_lru_rate_limit_entry(&self, cache: &mut HashMap<String, CacheEntry<RateLimitCache>>) {
        if let Some(lru_key) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&lru_key);
            self.record_eviction().await;
        }
    }

    // Compression utilities
    fn compress_data(&self, data: &str) -> MfaResult<Vec<u8>> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data.as_bytes()).map_err(|_| MfaError::Internal)?;
        encoder.finish().map_err(|_| MfaError::Internal)
    }

    fn decompress_data(&self, data: &[u8]) -> MfaResult<String> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).map_err(|_| MfaError::Internal)?;
        Ok(decompressed)
    }

    // Statistics tracking
    async fn record_l1_hit(&self) {
        let mut stats = self.stats.write().await;
        stats.l1_hits += 1;
    }

    async fn record_l1_miss(&self) {
        let mut stats = self.stats.write().await;
        stats.l1_misses += 1;
    }

    async fn record_l2_hit(&self) {
        let mut stats = self.stats.write().await;
        stats.l2_hits += 1;
    }

    async fn record_l2_miss(&self) {
        let mut stats = self.stats.write().await;
        stats.l2_misses += 1;
    }

    async fn record_eviction(&self) {
        let mut stats = self.stats.write().await;
        stats.evictions += 1;
    }

    fn record_error(&self) {
        // Record error asynchronously to avoid blocking
        let stats = self.stats.clone();
        tokio::spawn(async move {
            let mut stats = stats.write().await;
            stats.errors += 1;
        });
    }

    // Cache statistics and monitoring
    pub async fn get_stats(&self) -> CacheStats {
        self.stats.read().await.clone()
    }

    pub async fn get_cache_sizes(&self) -> CacheSizes {
        let totp_size = self.l1_totp_cache.read().await.len();
        let session_size = self.l1_session_cache.read().await.len();
        let rate_limit_size = self.l1_rate_limit_cache.read().await.len();

        CacheSizes {
            l1_totp_entries: totp_size,
            l1_session_entries: session_size,
            l1_rate_limit_entries: rate_limit_size,
            total_l1_entries: totp_size + session_size + rate_limit_size,
        }
    }

    // Cache maintenance
    pub async fn cleanup_expired_entries(&self) -> MfaResult<u32> {
        let mut cleaned = 0;

        // Clean L1 totp cache
        {
            let mut cache = self.l1_totp_cache.write().await;
            let expired_keys: Vec<String> = cache
                .iter()
                .filter(|(_, entry)| entry.is_expired())
                .map(|(key, _)| key.clone())
                .collect();

            for key in expired_keys {
                cache.remove(&key);
                cleaned += 1;
            }
        }

        // Clean L1 session cache
        {
            let mut cache = self.l1_session_cache.write().await;
            let expired_keys: Vec<String> = cache
                .iter()
                .filter(|(_, entry)| entry.is_expired())
                .map(|(key, _)| key.clone())
                .collect();

            for key in expired_keys {
                cache.remove(&key);
                cleaned += 1;
            }
        }

        // Clean L1 rate limit cache
        {
            let mut cache = self.l1_rate_limit_cache.write().await;
            let expired_keys: Vec<String> = cache
                .iter()
                .filter(|(_, entry)| entry.is_expired())
                .map(|(key, _)| key.clone())
                .collect();

            for key in expired_keys {
                cache.remove(&key);
                cleaned += 1;
            }
        }

        if cleaned > 0 {
            tracing::debug!("Cleaned up {} expired cache entries", cleaned);
        }

        Ok(cleaned)
    }

    pub async fn health_check(&self) -> CacheHealthStatus {
        let stats = self.get_stats().await;
        let sizes = self.get_cache_sizes().await;
        let redis_available = self.redis.is_some();

        CacheHealthStatus {
            l1_cache_healthy: sizes.total_l1_entries < self.config.l1_max_entries,
            l2_cache_healthy: redis_available,
            hit_ratio: stats.hit_ratio(),
            total_entries: sizes.total_l1_entries,
            error_rate: if stats.l1_hits + stats.l1_misses + stats.l2_hits + stats.l2_misses > 0 {
                stats.errors as f64 / (stats.l1_hits + stats.l1_misses + stats.l2_hits + stats.l2_misses) as f64
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CacheSizes {
    pub l1_totp_entries: usize,
    pub l1_session_entries: usize,
    pub l1_rate_limit_entries: usize,
    pub total_l1_entries: usize,
}

#[derive(Debug, Serialize)]
pub struct CacheHealthStatus {
    pub l1_cache_healthy: bool,
    pub l2_cache_healthy: bool,
    pub hit_ratio: f64,
    pub total_entries: usize,
    pub error_rate: f64,
}

// Background task for cache maintenance
pub async fn start_cache_maintenance_task(cache: Arc<MultiLayerMfaCache>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60)); // Run every minute

    loop {
        interval.tick().await;

        if let Err(e) = cache.cleanup_expired_entries().await {
            tracing::error!("Cache maintenance error: {}", e);
        }

        // Log cache statistics periodically
        let stats = cache.get_stats().await;
        let sizes = cache.get_cache_sizes().await;

        tracing::info!(
            "Cache stats - Hit ratio: {:.2}%, L1 entries: {}, L2 available: {}",
            stats.hit_ratio() * 100.0,
            sizes.total_l1_entries,
            cache.redis.is_some()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_entry_expiration() {
        let entry = CacheEntry::new("test_data".to_string(), Some(Duration::from_millis(100)));
        assert!(!entry.is_expired());

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(entry.is_expired());
    }

    #[tokio::test]
    async fn test_l1_cache_operations() {
        let cache = MultiLayerMfaCache::with_default_config().await;

        let totp_data = TotpCacheData {
            secret: vec![1, 2, 3, 4],
            config: EnhancedTotpConfig::default(),
            user_verified: true,
        };

        // Test set and get
        cache.set_totp_data("user1", &totp_data).await.unwrap();
        let retrieved = cache.get_totp_data("user1").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().secret, totp_data.secret);

        // Test cache miss
        let missing = cache.get_totp_data("nonexistent").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let cache = MultiLayerMfaCache::with_default_config().await;

        let totp_data = TotpCacheData {
            secret: vec![1, 2, 3, 4],
            config: EnhancedTotpConfig::default(),
            user_verified: true,
        };

        cache.set_totp_data("user1", &totp_data).await.unwrap();
        assert!(cache.get_totp_data("user1").await.unwrap().is_some());

        cache.invalidate_user_caches("user1").await.unwrap();
        assert!(cache.get_totp_data("user1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_compression() {
        let cache = MultiLayerMfaCache::new(CacheConfig {
            enable_compression: true,
            ..CacheConfig::default()
        }).await;

        let test_data = "This is a test string that should be compressed";
        let compressed = cache.compress_data(test_data).unwrap();
        let decompressed = cache.decompress_data(&compressed).unwrap();

        assert_eq!(test_data, decompressed);
        assert!(compressed.len() < test_data.len()); // Should be compressed
    }

    #[tokio::test]
    async fn test_lru_eviction() {
        let cache = MultiLayerMfaCache::new(CacheConfig {
            l1_max_entries: 2, // Very small cache for testing
            ..CacheConfig::default()
        }).await;

        let totp_data1 = TotpCacheData {
            secret: vec![1, 2, 3, 4],
            config: EnhancedTotpConfig::default(),
            user_verified: true,
        };
        let totp_data2 = totp_data1.clone();
        let totp_data3 = totp_data1.clone();

        // Fill cache to capacity
        cache.set_totp_data("user1", &totp_data1).await.unwrap();
        cache.set_totp_data("user2", &totp_data2).await.unwrap();

        // Access user1 to make it more recently used
        let _ = cache.get_totp_data("user1").await.unwrap();

        // Add third entry - should evict user2 (least recently used)
        cache.set_totp_data("user3", &totp_data3).await.unwrap();

        assert!(cache.get_totp_data("user1").await.unwrap().is_some());
        assert!(cache.get_totp_data("user2").await.unwrap().is_none());
        assert!(cache.get_totp_data("user3").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_cache_statistics() {
        let cache = MultiLayerMfaCache::with_default_config().await;

        let totp_data = TotpCacheData {
            secret: vec![1, 2, 3, 4],
            config: EnhancedTotpConfig::default(),
            user_verified: true,
        };

        // Generate some cache activity
        cache.set_totp_data("user1", &totp_data).await.unwrap();
        let _ = cache.get_totp_data("user1").await.unwrap(); // Hit
        let _ = cache.get_totp_data("user2").await.unwrap(); // Miss

        let stats = cache.get_stats().await;
        assert!(stats.l1_hits > 0);
        assert!(stats.l1_misses > 0);
        assert!(stats.hit_ratio() > 0.0);
    }
}