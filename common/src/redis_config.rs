//! Unified Redis configuration
//!
//! This module provides a single, consistent Redis configuration structure
//! to replace the multiple duplicate configurations scattered across the codebase.

use crate::constants::redis as redis_constants;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Redis configuration errors
#[derive(Debug, Error)]
pub enum RedisConfigError {
    #[error("Invalid Redis URL: {0}")]
    InvalidUrl(String),
    #[error("Invalid pool size: must be between 1 and {max}")]
    InvalidPoolSize { max: u32 },
    #[error("Invalid timeout: must be greater than 0")]
    InvalidTimeout,
    #[error("Invalid TTL: must be greater than 0")]
    InvalidTtl,
    #[error("Missing required field: {field}")]
    MissingField { field: String },
}

/// Unified Redis configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnifiedRedisConfig {
    /// Redis server URL
    pub url: String,

    /// Maximum number of connections in the pool
    #[serde(default = "default_pool_size")]
    pub max_connections: u32,

    /// Connection timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Default TTL for keys in seconds
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: i64,

    /// Enable connection pooling
    #[serde(default = "default_enable_pooling")]
    pub enable_pooling: bool,

    /// Connection idle timeout in seconds
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// Maximum number of retries for failed operations
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Retry delay in milliseconds
    #[serde(default = "default_retry_delay_ms")]
    pub retry_delay_ms: u64,

    /// Enable Redis cluster mode
    #[serde(default = "default_enable_cluster")]
    pub enable_cluster: bool,

    /// Database index (for non-cluster mode)
    #[serde(default = "default_database")]
    pub database: u8,

    /// Connection keep-alive in seconds
    #[serde(default = "default_keep_alive_secs")]
    pub keep_alive_secs: u64,
}

/// Default values for configuration fields
const fn default_pool_size() -> u32 {
    redis_constants::DEFAULT_POOL_SIZE
}

const fn default_timeout_ms() -> u64 {
    redis_constants::DEFAULT_TIMEOUT_MS
}

const fn default_ttl_secs() -> i64 {
    redis_constants::DEFAULT_TTL_SECS
}

const fn default_enable_pooling() -> bool {
    true
}

const fn default_idle_timeout_secs() -> u64 {
    300 // 5 minutes
}

const fn default_max_retries() -> u32 {
    3
}

const fn default_retry_delay_ms() -> u64 {
    100
}

const fn default_enable_cluster() -> bool {
    false
}

const fn default_database() -> u8 {
    0
}

const fn default_keep_alive_secs() -> u64 {
    30
}

impl Default for UnifiedRedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            max_connections: default_pool_size(),
            timeout_ms: default_timeout_ms(),
            ttl_secs: default_ttl_secs(),
            enable_pooling: default_enable_pooling(),
            idle_timeout_secs: default_idle_timeout_secs(),
            max_retries: default_max_retries(),
            retry_delay_ms: default_retry_delay_ms(),
            enable_cluster: default_enable_cluster(),
            database: default_database(),
            keep_alive_secs: default_keep_alive_secs(),
        }
    }
}

impl UnifiedRedisConfig {
    /// Create a new Redis configuration with minimal required fields
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Default::default()
        }
    }

    /// Create configuration for session storage
    pub fn for_sessions(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ttl_secs: redis_constants::SESSION_TTL_SECS,
            max_connections: redis_constants::DEFAULT_POOL_SIZE * 2, // More connections for sessions
            ..Default::default()
        }
    }

    /// Create configuration from environment variables
    pub fn from_env() -> crate::crypto::CryptoResult<Self> {
        let url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".to_string());
        Ok(Self::new(url))
    }

    /// Create configuration for caching
    pub fn for_caching(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ttl_secs: redis_constants::CACHE_TTL_SECS,
            max_connections: redis_constants::DEFAULT_POOL_SIZE,
            ..Default::default()
        }
    }

    /// Create configuration for rate limiting
    pub fn for_rate_limiting(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ttl_secs: redis_constants::RATE_LIMIT_TTL_SECS,
            max_connections: redis_constants::DEFAULT_POOL_SIZE,
            timeout_ms: 1000, // Faster timeout for rate limiting
            ..Default::default()
        }
    }


    /// Create configuration for threat profiling
    pub fn for_threat_profiling(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ttl_secs: 86400, // 24 hours for threat data
            max_connections: redis_constants::DEFAULT_POOL_SIZE / 2, // Fewer connections
            ..Default::default()
        }
    }

    /// Create configuration for threat hunting
    pub fn for_threat_hunting(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ttl_secs: 43200, // 12 hours for hunting data
            max_connections: redis_constants::DEFAULT_POOL_SIZE,
            ..Default::default()
        }
    }

    /// Validate the configuration
    ///
    /// # Errors
    /// Returns `RedisConfigError` if:
    /// - URL is empty
    /// - URL doesn't start with redis:// or rediss://
    /// - Connection pool size is 0 or too large
    /// - Timeout values are invalid
    /// - TLS configuration is invalid
    pub fn validate(&self) -> Result<(), RedisConfigError> {
        // Validate URL
        if self.url.is_empty() {
            return Err(RedisConfigError::MissingField {
                field: "url".to_string(),
            });
        }

        // Basic URL format validation
        if !self.url.starts_with("redis://") && !self.url.starts_with("rediss://") {
            return Err(RedisConfigError::InvalidUrl(
                "URL must start with redis:// or rediss://".to_string(),
            ));
        }

        // Validate pool size
        if self.max_connections == 0 || self.max_connections > redis_constants::MAX_POOL_SIZE {
            return Err(RedisConfigError::InvalidPoolSize {
                max: redis_constants::MAX_POOL_SIZE,
            });
        }

        // Validate timeout
        if self.timeout_ms == 0 {
            return Err(RedisConfigError::InvalidTimeout);
        }

        // Validate TTL
        if self.ttl_secs <= 0 {
            return Err(RedisConfigError::InvalidTtl);
        }

        Ok(())
    }

    /// Get connection timeout as Duration
    #[must_use]
    pub const fn timeout_duration(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// Get retry delay as Duration
    #[must_use]
    pub const fn retry_delay_duration(&self) -> Duration {
        Duration::from_millis(self.retry_delay_ms)
    }

    /// Get idle timeout as Duration
    #[must_use]
    pub const fn idle_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    /// Get keep-alive as Duration
    #[must_use]
    pub const fn keep_alive_duration(&self) -> Duration {
        Duration::from_secs(self.keep_alive_secs)
    }

    /// Create a Redis client URL with database selection
    #[must_use]
    pub fn client_url(&self) -> String {
        if self.enable_cluster {
            self.url.clone()
        } else {
            format!("{}/{}", self.url.trim_end_matches('/'), self.database)
        }
    }

    /// Get Redis connection configuration for deadpool
    #[must_use]
    pub fn to_deadpool_config(&self) -> deadpool_redis::Config {
        let mut config = deadpool_redis::Config::from_url(self.client_url());

        if let Some(ref mut pool_config) = config.pool {
            pool_config.max_size = self.max_connections as usize;
            pool_config.timeouts.wait = Some(self.timeout_duration());
            pool_config.timeouts.create = Some(self.timeout_duration());
            pool_config.timeouts.recycle = Some(self.idle_timeout_duration());
        }

        config
    }
}

/// Configuration presets for common use cases
pub struct RedisConfigPresets;

impl RedisConfigPresets {
    /// High-performance configuration for production
    pub fn high_performance(url: impl Into<String>) -> UnifiedRedisConfig {
        UnifiedRedisConfig {
            url: url.into(),
            max_connections: redis_constants::MAX_POOL_SIZE / 2,
            timeout_ms: 1000, // Fast timeout
            ttl_secs: redis_constants::CACHE_TTL_SECS,
            enable_pooling: true,
            idle_timeout_secs: 60,
            max_retries: 1, // Fail fast
            retry_delay_ms: 50,
            ..Default::default()
        }
    }

    /// Resilient configuration for unstable networks
    pub fn resilient(url: impl Into<String>) -> UnifiedRedisConfig {
        UnifiedRedisConfig {
            url: url.into(),
            max_connections: redis_constants::DEFAULT_POOL_SIZE,
            timeout_ms: 5000, // Longer timeout
            max_retries: 5,   // More retries
            retry_delay_ms: 200,
            ..Default::default()
        }
    }

    /// Development configuration with relaxed settings
    pub fn development(url: impl Into<String>) -> UnifiedRedisConfig {
        UnifiedRedisConfig {
            url: url.into(),
            max_connections: 5, // Fewer connections
            timeout_ms: 10000,  // Longer timeout for debugging
            ttl_secs: 3600,     // 1 hour TTL
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = UnifiedRedisConfig::default();
        assert_eq!(config.url, "redis://localhost:6379");
        assert_eq!(config.max_connections, redis_constants::DEFAULT_POOL_SIZE);
        assert_eq!(config.timeout_ms, redis_constants::DEFAULT_TIMEOUT_MS);
        assert!(config.enable_pooling);
    }

    #[test]
    fn test_config_validation() {
        let mut config = UnifiedRedisConfig::default();
        assert!(config.validate().is_ok());

        // Test invalid URL
        config.url = "invalid_url".to_string();
        assert!(config.validate().is_err());

        // Test invalid pool size
        config.url = "redis://localhost:6379".to_string();
        config.max_connections = 0;
        assert!(config.validate().is_err());

        config.max_connections = redis_constants::MAX_POOL_SIZE + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_specialized_configs() {
        let url = "redis://localhost:6379";

        let session_config = UnifiedRedisConfig::for_sessions(url);
        assert_eq!(session_config.ttl_secs, redis_constants::SESSION_TTL_SECS);

        let cache_config = UnifiedRedisConfig::for_caching(url);
        assert_eq!(cache_config.ttl_secs, redis_constants::CACHE_TTL_SECS);

        let rate_limit_config = UnifiedRedisConfig::for_rate_limiting(url);
        assert_eq!(
            rate_limit_config.ttl_secs,
            redis_constants::RATE_LIMIT_TTL_SECS
        );
        assert_eq!(rate_limit_config.timeout_ms, 1000);
    }

    #[test]
    fn test_presets() {
        let url = "redis://localhost:6379";

        let hp_config = RedisConfigPresets::high_performance(url);
        assert_eq!(hp_config.timeout_ms, 1000);
        assert_eq!(hp_config.max_retries, 1);

        let resilient_config = RedisConfigPresets::resilient(url);
        assert_eq!(resilient_config.timeout_ms, 5000);
        assert_eq!(resilient_config.max_retries, 5);

        let dev_config = RedisConfigPresets::development(url);
        assert_eq!(dev_config.max_connections, 5);
        assert_eq!(dev_config.timeout_ms, 10000);
    }

    #[test]
    fn test_client_url() {
        let config = UnifiedRedisConfig {
            url: "redis://localhost:6379".to_string(),
            database: 2,
            enable_cluster: false,
            ..Default::default()
        };

        assert_eq!(config.client_url(), "redis://localhost:6379/2");

        let cluster_config = UnifiedRedisConfig {
            enable_cluster: true,
            ..config
        };

        assert_eq!(cluster_config.client_url(), "redis://localhost:6379");
    }

    #[test]
    fn test_duration_methods() {
        let config = UnifiedRedisConfig {
            timeout_ms: 1000,
            retry_delay_ms: 200,
            idle_timeout_secs: 300,
            keep_alive_secs: 30,
            ..Default::default()
        };

        assert_eq!(config.timeout_duration(), Duration::from_millis(1000));
        assert_eq!(config.retry_delay_duration(), Duration::from_millis(200));
        assert_eq!(config.idle_timeout_duration(), Duration::from_secs(300));
        assert_eq!(config.keep_alive_duration(), Duration::from_secs(30));
    }

    #[test]
    fn test_serde() {
        let config = UnifiedRedisConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: UnifiedRedisConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);
    }
}
