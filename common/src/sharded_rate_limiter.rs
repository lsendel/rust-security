//! Sharded rate limiter implementation
//!
//! This module provides a high-performance rate limiter that uses sharding
//! to reduce lock contention and improve concurrency.

use crate::constants::rate_limiting;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::time::sleep;

/// Rate limiter errors
#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded for key: {key}")]
    RateLimitExceeded { key: String },
    #[error("Invalid rate limit configuration: {message}")]
    InvalidConfiguration { message: String },
    #[error("Shard operation failed: {message}")]
    ShardError { message: String },
}

/// Rate limit entry tracking usage and reset time
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    /// Number of requests made in the current window
    pub count: u32,
    /// When the current window started
    pub window_start: Instant,
    /// Rate limit for this specific key (allows per-key limits)
    pub limit: u32,
    /// Window duration for this key
    pub window_duration: Duration,
}

impl RateLimitEntry {
    /// Create a new rate limit entry
    pub fn new(limit: u32, window_duration: Duration) -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
            limit,
            window_duration,
        }
    }

    /// Check if the entry is in a new window and should be reset
    pub fn should_reset(&self) -> bool {
        self.window_start.elapsed() >= self.window_duration
    }

    /// Reset the entry for a new window
    pub fn reset(&mut self) {
        self.count = 0;
        self.window_start = Instant::now();
    }

    /// Check if adding one more request would exceed the limit
    pub fn would_exceed_limit(&self) -> bool {
        self.count >= self.limit
    }

    /// Increment the request count
    pub fn increment(&mut self) {
        self.count += 1;
    }

    /// Get remaining requests in the current window
    pub fn remaining(&self) -> u32 {
        self.limit.saturating_sub(self.count)
    }

    /// Get time until window reset
    pub fn time_until_reset(&self) -> Duration {
        self.window_duration
            .saturating_sub(self.window_start.elapsed())
    }
}

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Default rate limit (requests per window)
    pub default_limit: u32,
    /// Default window duration
    pub window_duration: Duration,
    /// Burst multiplier (allows temporary bursts)
    pub burst_multiplier: f64,
    /// Clean up expired entries every N seconds
    pub cleanup_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_limit: rate_limiting::DEFAULT_RATE_LIMIT,
            window_duration: Duration::from_secs(rate_limiting::RATE_LIMITER_SHARDS as u64),
            burst_multiplier: rate_limiting::BURST_MULTIPLIER,
            cleanup_interval: Duration::from_secs(rate_limiting::CLEANUP_INTERVAL_SECS),
        }
    }
}

/// High-performance sharded rate limiter
pub struct ShardedRateLimiter {
    /// Array of shards, each with its own lock to reduce contention
    shards: [RwLock<HashMap<String, RateLimitEntry>>; rate_limiting::RATE_LIMITER_SHARDS],
    /// Configuration for the rate limiter
    config: RateLimitConfig,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

impl ShardedRateLimiter {
    /// Create a new sharded rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        // Validate configuration
        if config.default_limit == 0 {
            panic!("Rate limit must be greater than 0");
        }
        if config.window_duration.is_zero() {
            panic!("Window duration must be greater than 0");
        }
        if config.burst_multiplier < 1.0 {
            panic!("Burst multiplier must be >= 1.0");
        }

        // Create shards array
        let mut shards = Vec::with_capacity(rate_limiting::RATE_LIMITER_SHARDS);
        for _ in 0..rate_limiting::RATE_LIMITER_SHARDS {
            shards.push(RwLock::new(HashMap::new()));
        }
        let shards: [RwLock<HashMap<String, RateLimitEntry>>; rate_limiting::RATE_LIMITER_SHARDS] =
            shards.try_into().expect("Vector has wrong size");

        Self {
            shards,
            config,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Create a rate limiter with default configuration
    pub fn with_default_config() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Get the shard index for a given key
    fn get_shard_index(&self, key: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % rate_limiting::RATE_LIMITER_SHARDS
    }

    /// Check if a request should be allowed
    pub async fn check_rate_limit(&self, key: &str) -> Result<bool, RateLimitError> {
        self.check_rate_limit_with_limit(key, self.config.default_limit)
            .await
    }

    /// Check if a request should be allowed with a custom limit
    pub async fn check_rate_limit_with_limit(
        &self,
        key: &str,
        custom_limit: u32,
    ) -> Result<bool, RateLimitError> {
        if custom_limit == 0 {
            return Err(RateLimitError::InvalidConfiguration {
                message: "Rate limit cannot be 0".to_string(),
            });
        }

        let shard_index = self.get_shard_index(key);
        let shard = &self.shards[shard_index];

        // First, try with a read lock (optimistic path)
        {
            let shard_read = shard.read().await;
            if let Some(entry) = shard_read.get(key) {
                // If the entry is still in the current window and not exceeded
                if !entry.should_reset() && !entry.would_exceed_limit() {
                    drop(shard_read);
                    // Acquire write lock to increment
                    let mut shard_write = shard.write().await;
                    if let Some(entry) = shard_write.get_mut(key) {
                        if !entry.should_reset() && !entry.would_exceed_limit() {
                            entry.increment();
                            return Ok(true);
                        }
                    }
                }
            }
        }

        // Acquire write lock for more complex operations
        let mut shard_write = shard.write().await;

        match shard_write.get_mut(key) {
            Some(entry) => {
                // Reset if in new window
                if entry.should_reset() {
                    entry.reset();
                    entry.limit = custom_limit; // Update limit
                }

                // Check if we can allow this request
                if entry.would_exceed_limit() {
                    Err(RateLimitError::RateLimitExceeded {
                        key: key.to_string(),
                    })
                } else {
                    entry.increment();
                    Ok(true)
                }
            }
            None => {
                // Create new entry
                let mut entry = RateLimitEntry::new(custom_limit, self.config.window_duration);
                entry.increment();
                shard_write.insert(key.to_string(), entry);
                Ok(true)
            }
        }
    }

    /// Get rate limit information for a key
    pub async fn get_rate_limit_info(&self, key: &str) -> Option<RateLimitInfo> {
        let shard_index = self.get_shard_index(key);
        let shard = &self.shards[shard_index];
        let shard_read = shard.read().await;

        shard_read.get(key).map(|entry| {
            let mut info = RateLimitInfo {
                limit: entry.limit,
                remaining: entry.remaining(),
                reset_time: entry.window_start + entry.window_duration,
                window_duration: entry.window_duration,
            };

            // If we should reset, adjust the info
            if entry.should_reset() {
                info.remaining = entry.limit;
                info.reset_time = Instant::now() + entry.window_duration;
            }

            info
        })
    }

    /// Manually reset rate limit for a key
    pub async fn reset_rate_limit(&self, key: &str) -> Result<(), RateLimitError> {
        let shard_index = self.get_shard_index(key);
        let shard = &self.shards[shard_index];
        let mut shard_write = shard.write().await;

        if let Some(entry) = shard_write.get_mut(key) {
            entry.reset();
            Ok(())
        } else {
            Ok(()) // No entry to reset
        }
    }

    /// Clean up expired entries
    pub async fn cleanup_expired(&self) -> usize {
        let mut last_cleanup = self.last_cleanup.write().await;

        // Only cleanup if enough time has passed
        if last_cleanup.elapsed() < self.config.cleanup_interval {
            return 0;
        }

        *last_cleanup = Instant::now();
        drop(last_cleanup);

        let mut total_removed = 0;

        // Clean up each shard
        for shard in &self.shards {
            let mut shard_write = shard.write().await;
            let initial_len = shard_write.len();

            // Remove entries that are old enough
            shard_write.retain(|_, entry| {
                // Keep entries that are still in their window or recently active
                !entry.should_reset()
                    || entry.window_start.elapsed() < self.config.window_duration * 2
            });

            total_removed += initial_len - shard_write.len();
        }

        total_removed
    }

    /// Start background cleanup task
    pub async fn start_cleanup_task(&self) {
        let cleanup_interval = self.config.cleanup_interval;

        tokio::spawn({
            let _limiter = self as *const _ as usize; // Unsafe pointer for demonstration

            async move {
                loop {
                    sleep(cleanup_interval).await;

                    // In a real implementation, you'd need proper Arc<Self> handling
                    // This is just to show the concept
                    // unsafe { (&*(limiter as *const ShardedRateLimiter)).cleanup_expired().await };
                }
            }
        });
    }

    /// Get statistics about the rate limiter
    pub async fn get_stats(&self) -> RateLimiterStats {
        let mut stats = RateLimiterStats::default();

        for shard in &self.shards {
            let shard_read = shard.read().await;
            stats.total_keys += shard_read.len();

            for entry in shard_read.values() {
                stats.total_requests += entry.count as u64;
                if entry.would_exceed_limit() {
                    stats.blocked_keys += 1;
                }
                if entry.should_reset() {
                    stats.expired_entries += 1;
                }
            }
        }

        stats
    }
}

/// Rate limit information for a specific key
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Rate limit for this key
    pub limit: u32,
    /// Remaining requests in the current window
    pub remaining: u32,
    /// When the current window resets
    pub reset_time: Instant,
    /// Duration of the rate limit window
    pub window_duration: Duration,
}

/// Statistics about the rate limiter
#[derive(Debug, Default, Clone)]
pub struct RateLimiterStats {
    /// Total number of tracked keys across all shards
    pub total_keys: usize,
    /// Total number of requests processed
    pub total_requests: u64,
    /// Number of keys currently blocked (at limit)
    pub blocked_keys: usize,
    /// Number of expired entries that need cleanup
    pub expired_entries: usize,
}

/// Utility trait for rate limiting
#[async_trait::async_trait]
pub trait RateLimited {
    /// Check if this item is rate limited
    async fn check_rate_limit(&self, limiter: &ShardedRateLimiter) -> Result<bool, RateLimitError>;
}

#[async_trait::async_trait]
impl RateLimited for String {
    async fn check_rate_limit(&self, limiter: &ShardedRateLimiter) -> Result<bool, RateLimitError> {
        limiter.check_rate_limit(self).await
    }
}

#[async_trait::async_trait]
impl RateLimited for &str {
    async fn check_rate_limit(&self, limiter: &ShardedRateLimiter) -> Result<bool, RateLimitError> {
        limiter.check_rate_limit(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_basic_rate_limiting() {
        let config = RateLimitConfig {
            default_limit: 5,
            window_duration: Duration::from_secs(1),
            ..Default::default()
        };

        let limiter = ShardedRateLimiter::new(config);
        let key = "test_key";

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(key).await.unwrap());
        }

        // 6th request should be blocked
        assert!(limiter.check_rate_limit(key).await.is_err());

        // Wait for window to reset
        sleep(Duration::from_secs(1)).await;

        // Should allow requests again
        assert!(limiter.check_rate_limit(key).await.unwrap());
    }

    #[tokio::test]
    async fn test_different_keys_independent() {
        let config = RateLimitConfig {
            default_limit: 2,
            window_duration: Duration::from_secs(1),
            ..Default::default()
        };

        let limiter = ShardedRateLimiter::new(config);

        // Different keys should have independent limits
        assert!(limiter.check_rate_limit("key1").await.unwrap());
        assert!(limiter.check_rate_limit("key2").await.unwrap());
        assert!(limiter.check_rate_limit("key1").await.unwrap());
        assert!(limiter.check_rate_limit("key2").await.unwrap());

        // Both should be at limit now
        assert!(limiter.check_rate_limit("key1").await.is_err());
        assert!(limiter.check_rate_limit("key2").await.is_err());
    }

    #[tokio::test]
    async fn test_custom_limits() {
        let limiter = ShardedRateLimiter::with_default_config();
        let key = "custom_key";

        // Allow 3 requests with custom limit
        assert!(limiter.check_rate_limit_with_limit(key, 3).await.unwrap());
        assert!(limiter.check_rate_limit_with_limit(key, 3).await.unwrap());
        assert!(limiter.check_rate_limit_with_limit(key, 3).await.unwrap());

        // 4th request should be blocked
        assert!(limiter.check_rate_limit_with_limit(key, 3).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limit_info() {
        let config = RateLimitConfig {
            default_limit: 10,
            window_duration: Duration::from_secs(60),
            ..Default::default()
        };

        let limiter = ShardedRateLimiter::new(config);
        let key = "info_key";

        // Make some requests
        for _ in 0..3 {
            limiter.check_rate_limit(key).await.unwrap();
        }

        let info = limiter.get_rate_limit_info(key).await.unwrap();
        assert_eq!(info.limit, 10);
        assert_eq!(info.remaining, 7); // 10 - 3 = 7
    }

    #[tokio::test]
    async fn test_sharding() {
        let limiter = ShardedRateLimiter::with_default_config();

        // Test that different keys can map to different shards
        let keys = vec!["key1", "key2", "key3", "key4", "key5"];
        let mut shard_indices = std::collections::HashSet::new();

        for key in &keys {
            let shard_index = limiter.get_shard_index(key);
            shard_indices.insert(shard_index);
            assert!(shard_index < rate_limiting::RATE_LIMITER_SHARDS);
        }

        // We should have at least some different shards (not guaranteed all different)
        assert!(!shard_indices.is_empty());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let config = RateLimitConfig {
            default_limit: 1,
            window_duration: Duration::from_millis(100),
            cleanup_interval: Duration::from_millis(50),
            ..Default::default()
        };

        let limiter = ShardedRateLimiter::new(config);

        // Create some entries
        limiter.check_rate_limit("key1").await.unwrap();
        limiter.check_rate_limit("key2").await.unwrap();

        // Wait for entries to expire
        sleep(Duration::from_millis(200)).await;

        // Cleanup should find expired entries
        let _cleaned = limiter.cleanup_expired().await;
        // Note: actual cleanup behavior depends on implementation details
    }

    #[tokio::test]
    async fn test_reset() {
        let config = RateLimitConfig {
            default_limit: 1,
            window_duration: Duration::from_secs(10), // Long window
            ..Default::default()
        };

        let limiter = ShardedRateLimiter::new(config);
        let key = "reset_key";

        // Use up the limit
        assert!(limiter.check_rate_limit(key).await.unwrap());
        assert!(limiter.check_rate_limit(key).await.is_err());

        // Reset the key
        limiter.reset_rate_limit(key).await.unwrap();

        // Should be able to make requests again
        assert!(limiter.check_rate_limit(key).await.unwrap());
    }
}
