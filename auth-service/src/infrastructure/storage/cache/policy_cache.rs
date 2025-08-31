#![allow(clippy::significant_drop_tightening)]

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};

use crate::shared::error::AppError;
#[cfg(feature = "monitoring")]
use crate::metrics::METRICS;

/// Configuration for policy caching
#[derive(Debug, Clone)]
pub struct PolicyCacheConfig {
    /// Default TTL for cache entries
    pub default_ttl: Duration,
    /// Maximum number of entries in cache
    pub max_entries: usize,
    /// Enable/disable caching
    pub enabled: bool,
    /// TTL for deny decisions (usually shorter than allow)
    pub deny_ttl: Duration,
    /// TTL for error responses (very short)
    pub error_ttl: Duration,
    /// Cache cleanup interval
    pub cleanup_interval: Duration,
}

impl Default for PolicyCacheConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(300), // 5 minutes
            max_entries: 10000,
            enabled: true,
            deny_ttl: Duration::from_secs(60), // 1 minute for deny decisions
            error_ttl: Duration::from_secs(10), // 10 seconds for errors
            cleanup_interval: Duration::from_secs(60), // Clean up every minute
        }
    }
}

/// Policy evaluation request for caching
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct PolicyRequest {
    pub principal: Value,
    pub action: String,
    pub resource: Value,
    pub context: Value,
}

/// Policy evaluation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub decision: String,
    pub cached_at: u64,
    pub ttl_seconds: u64,
}

/// Cache entry with metadata
#[derive(Debug, Clone)]
struct CacheEntry {
    response: PolicyResponse,
    expires_at: Instant,
    hit_count: u64,
    created_at: Instant,
}

/// Cache statistics for monitoring
#[derive(Debug, Clone, Default)]
pub struct PolicyCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: usize,
    pub evictions: u64,
    pub errors: u64,
    pub avg_response_time_ms: f64,
    pub last_cleanup_time: Option<u64>,
}

/// Thread-safe policy cache with TTL and metrics
pub struct PolicyCache {
    /// Cache storage using `DashMap` for better concurrency
    cache: DashMap<String, CacheEntry>,
    /// Configuration
    config: PolicyCacheConfig,
    /// Statistics
    stats: Arc<RwLock<PolicyCacheStats>>,
    /// Last cleanup time
    last_cleanup: Arc<RwLock<Instant>>,
}

impl PolicyCache {
    /// Create new policy cache with configuration
    #[must_use]
    pub fn new(config: PolicyCacheConfig) -> Self {
        Self {
            cache: DashMap::new(),
            config,
            stats: Arc::new(RwLock::new(PolicyCacheStats::default())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Generate cache key from policy request
    fn generate_cache_key(request: &PolicyRequest) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        request.hash(&mut hasher);
        format!("policy:{:x}", hasher.finish())
    }

    /// Get policy decision from cache
    #[instrument(skip(self))]
    pub async fn get(&self, request: &PolicyRequest) -> Option<PolicyResponse> {
        let start_time = Instant::now();

        if !self.config.enabled {
            return None;
        }

        let key = Self::generate_cache_key(request);
        let _policy_type = &request.action; // Used in metrics collection

        if let Some(mut entry) = self.cache.get_mut(&key) {
            // Check if entry is still valid
            if Instant::now() < entry.expires_at {
                // Update hit count and stats atomically
                let response = entry.response.clone();
                let hit_count = entry.hit_count + 1;
                entry.hit_count = hit_count;

                // Acquire stats lock once for both updates
                let mut stats = self.stats.write().await;
                stats.hits += 1;

                info!(
                    cache_key = %key,
                    decision = %response.decision,
                    hit_count = hit_count,
                    age_seconds = entry.created_at.elapsed().as_secs(),
                    "Policy cache hit"
                );

                // Record cache hit metrics
                let _duration = start_time.elapsed();
                #[cfg(feature = "monitoring")]
                METRICS
                    .policy_cache_operations
                    .with_label_values(&["get", "hit", _policy_type])
                    .inc();
                #[cfg(feature = "monitoring")]
                METRICS
                    .cache_operation_duration
                    .with_label_values(&["policy", "get"])
                    .observe(_duration.as_secs_f64());

                return Some(response);
            }

            // Entry expired, remove it
            drop(entry);
            self.cache.remove(&key);

            let mut stats = self.stats.write().await;
            stats.evictions += 1;

            warn!(
                cache_key = %key,
                "Policy cache entry expired and removed"
            );
        }

        // Cache miss
        let mut stats = self.stats.write().await;
        stats.misses += 1;

        // Record cache miss metrics
        let _duration = start_time.elapsed();
        #[cfg(feature = "monitoring")]
        METRICS
            .policy_cache_operations
            .with_label_values(&["get", "miss", _policy_type])
            .inc();

        None
    }

    /// Store policy decision in cache
    ///
    /// # Errors
    ///
    /// Returns an error if cache storage fails or serialization fails
    #[instrument(skip(self))]
    pub async fn put(
        &self,
        request: &PolicyRequest,
        response: PolicyResponse,
    ) -> Result<(), crate::shared::error::AppError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check cache size limit before insertion
        if self.cache.len() > self.config.max_entries {
            self.evict_lru().await;
        }

        let key = Self::generate_cache_key(request);

        // Determine TTL based on decision type
        let ttl = match response.decision.as_str() {
            "Deny" => self.config.deny_ttl,
            "Allow" => self.config.default_ttl,
            _ => self.config.error_ttl, // Treat unknown decisions as errors
        };

        let entry = CacheEntry {
            response: response.clone(),
            expires_at: Instant::now() + ttl,
            hit_count: 0,
            created_at: Instant::now(),
        };

        self.cache.insert(key.clone(), entry);

        // Update stats
        let mut stats = self.stats.write().await;
        stats.entries = self.cache.len();

        info!(
            cache_key = %key,
            decision = %response.decision,
            ttl_seconds = ttl.as_secs(),
            "Policy cached"
        );

        Ok(())
    }

    /// Invalidate cache entries by pattern
    #[instrument(skip(self))]
    pub async fn invalidate(&self, pattern: &str) -> usize {
        let mut removed = 0;

        // For now, implement simple prefix matching
        // In production, could support more sophisticated patterns
        self.cache.retain(|key, _| {
            if key.contains(pattern) {
                removed += 1;
                false
            } else {
                true
            }
        });

        if removed > 0 {
            let mut stats = self.stats.write().await;
            stats.entries = self.cache.len();
            stats.evictions += u64::try_from(removed).unwrap_or(0);

            info!(
                pattern = %pattern,
                removed = removed,
                remaining = self.cache.len(),
                "Policy cache invalidated by pattern"
            );
        }

        removed
    }

    /// Clear entire cache
    #[instrument(skip(self))]
    pub async fn clear(&self) -> usize {
        let cache_size = self.cache.len();
        self.cache.clear();

        let mut stats = self.stats.write().await;
        stats.entries = 0;
        stats.evictions += cache_size as u64;

        info!(cleared = cache_size, "Policy cache cleared");
        cache_size
    }

    /// Evict least recently used entries when cache is full
    async fn evict_lru(&self) {
        // Simple LRU: remove entries with lowest hit count and oldest creation time
        let mut to_remove = Vec::new();
        let target_remove = std::cmp::max(1, self.config.max_entries / 10); // Remove 10% when full

        // Collect candidates for eviction
        for entry in &self.cache {
            let (key, cache_entry) = (entry.key().clone(), entry.value().clone());
            to_remove.push((key, cache_entry.hit_count, cache_entry.created_at));
        }

        // Sort by hit count (ascending) then by age (oldest first)
        to_remove.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2)));

        // Remove the least valuable entries
        let mut removed = 0;
        for (key, _, _) in to_remove.iter().take(target_remove) {
            if self.cache.remove(key).is_some() {
                removed += 1;
            }
        }

        let mut stats = self.stats.write().await;
        stats.evictions += u64::try_from(removed).unwrap_or(0);
        stats.entries = self.cache.len();

        warn!(
            removed = removed,
            remaining = self.cache.len(),
            "Evicted LRU entries from policy cache"
        );
    }

    /// Clean up expired entries
    #[instrument(skip(self))]
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut removed = 0;

        self.cache.retain(|_key, entry| {
            if now >= entry.expires_at {
                removed += 1;
                false
            } else {
                true
            }
        });

        if removed > 0 {
            let mut stats = self.stats.write().await;
            stats.entries = self.cache.len();
            stats.evictions += u64::try_from(removed).unwrap_or(0);

            info!(
                removed = removed,
                remaining = self.cache.len(),
                "Cleaned up expired policy cache entries"
            );
        }

        // Update last cleanup time
        let mut last_cleanup = self.last_cleanup.write().await;
        *last_cleanup = now;

        let mut stats = self.stats.write().await;
        stats.last_cleanup_time = Some(Self::current_timestamp());
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> PolicyCacheStats {
        let mut stats = self.stats.read().await.clone();
        stats.entries = self.cache.len();

        // Calculate hit ratio
        let total_requests = stats.hits + stats.misses;
        if total_requests > 0 {
            // This could be enhanced with actual response time tracking
            stats.avg_response_time_ms = 0.1; // Placeholder
        }

        stats
    }

    /// Check if cleanup is needed
    pub async fn needs_cleanup(&self) -> bool {
        let last_cleanup = self.last_cleanup.read().await;
        last_cleanup.elapsed() >= self.config.cleanup_interval
    }

    /// Get current Unix timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Background task for periodic cache cleanup
pub async fn start_cache_cleanup_task(cache: Arc<PolicyCache>) {
    let mut interval = tokio::time::interval(cache.config.cleanup_interval);

    loop {
        interval.tick().await;

        if cache.needs_cleanup().await {
            if let Err(e) =
                tokio::time::timeout(Duration::from_secs(30), cache.cleanup_expired()).await
            {
                error!(error = %e, "Policy cache cleanup timeout");
            }
        }
    }
}

/// Normalize policy request for consistent caching
#[must_use]
pub fn normalize_policy_request(
    principal: Value,
    action: String,
    resource: Value,
    context: Value,
) -> PolicyRequest {
    // Remove volatile context fields that shouldn't affect caching
    let mut normalized_context = context;
    if let Value::Object(ref mut obj) = normalized_context {
        // Remove request-specific fields that change but don't affect policy
        obj.remove("request_id");
        obj.remove("timestamp");
        obj.remove("request_time");
        // Keep mfa_required, mfa_verified as they affect policy decisions
    }

    PolicyRequest {
        principal,
        action,
        resource,
        context: normalized_context,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_cache_basic_operations() {
        let config = PolicyCacheConfig {
            default_ttl: Duration::from_millis(100),
            max_entries: 2,
            enabled: true,
            ..Default::default()
        };
        let cache = PolicyCache::new(config);

        let request = PolicyRequest {
            principal: serde_json::json!({"id": "user1"}),
            action: "read".to_string(),
            resource: serde_json::json!({"type": "document"}),
            context: serde_json::json!({}),
        };

        // Cache miss initially
        assert!(cache.get(&request).await.is_none());

        // Store response
        let response = PolicyResponse {
            decision: "Allow".to_string(),
            cached_at: PolicyCache::current_timestamp(),
            ttl_seconds: 300,
        };
        cache.put(&request, response.clone()).await.unwrap();

        // Cache hit
        let cached = cache.get(&request).await.unwrap();
        assert_eq!(cached.decision, "Allow");

        // Wait for expiry
        sleep(Duration::from_millis(150)).await;
        assert!(cache.get(&request).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let config = PolicyCacheConfig {
            default_ttl: Duration::from_secs(10),
            max_entries: 2,
            enabled: true,
            ..Default::default()
        };
        let cache = PolicyCache::new(config);

        // Fill cache to capacity
        for i in 0..3 {
            let request = PolicyRequest {
                principal: serde_json::json!({"id": format!("user{i}")}),
                action: "read".to_string(),
                resource: serde_json::json!({"type": "document"}),
                context: serde_json::json!({}),
            };

            let response = PolicyResponse {
                decision: "Allow".to_string(),
                cached_at: PolicyCache::current_timestamp(),
                ttl_seconds: 300,
            };

            cache.put(&request, response).await.unwrap();
        }

        // Cache should not exceed max cache_size
        let stats = cache.get_stats().await;
        assert!(stats.entries <= 2);
        assert!(stats.evictions > 0);
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let cache = PolicyCache::new(PolicyCacheConfig::default());

        let request = PolicyRequest {
            principal: serde_json::json!({"id": "user1"}),
            action: "read".to_string(),
            resource: serde_json::json!({"type": "document"}),
            context: serde_json::json!({}),
        };

        let response = PolicyResponse {
            decision: "Allow".to_string(),
            cached_at: PolicyCache::current_timestamp(),
            ttl_seconds: 300,
        };

        cache.put(&request, response).await.unwrap();
        assert!(cache.get(&request).await.is_some());

        // Invalidate and verify removal
        let removed = cache.invalidate("policy:").await;
        assert!(removed > 0);
        assert!(cache.get(&request).await.is_none());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = PolicyCache::new(PolicyCacheConfig::default());

        let request = PolicyRequest {
            principal: serde_json::json!({"id": "user1"}),
            action: "read".to_string(),
            resource: serde_json::json!({"type": "document"}),
            context: serde_json::json!({}),
        };

        // Generate some misses
        cache.get(&request).await;
        cache.get(&request).await;

        let response = PolicyResponse {
            decision: "Allow".to_string(),
            cached_at: PolicyCache::current_timestamp(),
            ttl_seconds: 300,
        };

        cache.put(&request, response).await.unwrap();

        // Generate some hits
        cache.get(&request).await;
        cache.get(&request).await;

        let stats = cache.get_stats().await;
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.entries, 1);
    }

    #[tokio::test]
    async fn test_normalize_request() {
        let request = normalize_policy_request(
            serde_json::json!({"id": "user1"}),
            "read".to_string(),
            serde_json::json!({"type": "document"}),
            serde_json::json!({
                "request_id": "req-123",
                "timestamp": 1_234_567_890,
                "mfa_required": true,
                "important_context": "keep_me"
            }),
        );

        // Volatile fields should be removed
        assert!(request.context.get("request_id").is_none());
        assert!(request.context.get("timestamp").is_none());
        // Important fields should be kept
        assert!(request.context.get("mfa_required").is_some());
        assert!(request.context.get("important_context").is_some());
    }

    #[tokio::test]
    async fn test_disabled_cache() {
        let config = PolicyCacheConfig {
            enabled: false,
            ..Default::default()
        };
        let cache = PolicyCache::new(config);

        let request = PolicyRequest {
            principal: serde_json::json!({"id": "user1"}),
            action: "read".to_string(),
            resource: serde_json::json!({"type": "document"}),
            context: serde_json::json!({}),
        };

        let response = PolicyResponse {
            decision: "Allow".to_string(),
            cached_at: PolicyCache::current_timestamp(),
            ttl_seconds: 300,
        };

        // Should not cache when disabled
        cache.put(&request, response).await.unwrap();
        assert!(cache.get(&request).await.is_none());
    }
}
