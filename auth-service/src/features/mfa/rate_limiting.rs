use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug)]
pub enum RateLimitError {
    #[error("Redis connection error: {0}")]
    RedisError(#[from] RedisError),
    #[error("Rate limit exceeded: {limit_type}")]
    RateLimitExceeded { limit_type: String },
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub max_verification_attempts_per_5min: i64,
    pub max_registration_attempts_per_hour: i64,
    pub max_otp_sends_per_hour: i64,
    pub max_backup_code_attempts_per_hour: i64,
    pub lockout_duration_secs: u64,
    pub progressive_delays_enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_verification_attempts_per_5min: 10,
            max_registration_attempts_per_hour: 5,
            max_otp_sends_per_hour: 5,
            max_backup_code_attempts_per_hour: 3,
            lockout_duration_secs: 900, // 15 minutes
            progressive_delays_enabled: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining_attempts: i64,
    pub reset_time: Option<u64>,
    pub retry_after_secs: Option<u64>,
}

// In-memory fallback for when Redis is unavailable
#[derive(Debug, Default)]
struct InMemoryRateLimit {
    verification_attempts: Arc<RwLock<HashMap<String, (i64, u64)>>>, // (count, reset_time)
    registration_attempts: Arc<RwLock<HashMap<String, (i64, u64)>>>,
    otp_sends: Arc<RwLock<HashMap<String, (i64, u64)>>>,
    backup_code_attempts: Arc<RwLock<HashMap<String, (i64, u64)>>>,
}

pub struct MfaRateLimiter {
    redis: Option<ConnectionManager>,
    config: RateLimitConfig,
    fallback: InMemoryRateLimit,
}

impl MfaRateLimiter {
    pub async fn new(config: RateLimitConfig) -> Self {
        let redis = Self::create_redis_connection().await;
        Self {
            redis,
            config,
            fallback: InMemoryRateLimit::default(),
        }
    }

    pub async fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default()).await
    }

    async fn create_redis_connection() -> Option<ConnectionManager> {
        let url = std::env::var("REDIS_URL").ok()?;
        let client = redis::Client::open(url).ok()?;
        client.get_connection_manager().await.ok()
    }

    async fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub async fn check_verification_attempts(&self, user_id: &str) -> Result<RateLimitResult, RateLimitError> {
        self.check_rate_limit(
            user_id,
            "verify",
            self.config.max_verification_attempts_per_5min,
            300, // 5 minutes
        ).await
    }

    pub async fn check_registration_attempts(&self, user_id: &str) -> Result<RateLimitResult, RateLimitError> {
        self.check_rate_limit(
            user_id,
            "register",
            self.config.max_registration_attempts_per_hour,
            3600, // 1 hour
        ).await
    }

    pub async fn check_otp_send_attempts(&self, user_id: &str) -> Result<RateLimitResult, RateLimitError> {
        self.check_rate_limit(
            user_id,
            "otp_send",
            self.config.max_otp_sends_per_hour,
            3600, // 1 hour
        ).await
    }

    pub async fn check_backup_code_attempts(&self, user_id: &str) -> Result<RateLimitResult, RateLimitError> {
        self.check_rate_limit(
            user_id,
            "backup_code",
            self.config.max_backup_code_attempts_per_hour,
            3600, // 1 hour
        ).await
    }

    async fn check_rate_limit(
        &self,
        user_id: &str,
        limit_type: &str,
        max_attempts: i64,
        window_secs: u64,
    ) -> Result<RateLimitResult, RateLimitError> {
        if let Some(mut conn) = self.redis.clone() {
            self.check_rate_limit_redis(&mut conn, user_id, limit_type, max_attempts, window_secs).await
        } else {
            self.check_rate_limit_memory(user_id, limit_type, max_attempts, window_secs).await
        }
    }

    async fn check_rate_limit_redis(
        &self,
        conn: &mut ConnectionManager,
        user_id: &str,
        limit_type: &str,
        max_attempts: i64,
        window_secs: u64,
    ) -> Result<RateLimitResult, RateLimitError> {
        let key = format!("mfa:rate:{}:{}:{}", limit_type, user_id, Self::current_time().await / window_secs);

        // Use multi-command transaction for atomicity
        let (current_count, ttl): (i64, i64) = redis::pipe()
            .atomic()
            .incr(&key, 1)
            .expire(&key, window_secs as u64)
            .ttl(&key)
            .query_async(conn)
            .await?;

        let remaining = (max_attempts - current_count).max(0);
        let reset_time = if ttl > 0 {
            Some(Self::current_time().await + ttl as u64)
        } else {
            None
        };

        if current_count > max_attempts {
            // Calculate progressive delay if enabled
            let retry_after = if self.config.progressive_delays_enabled {
                Some(self.calculate_progressive_delay(current_count - max_attempts))
            } else {
                Some(ttl as u64)
            };

            Ok(RateLimitResult {
                allowed: false,
                remaining_attempts: 0,
                reset_time,
                retry_after_secs: retry_after,
            })
        } else {
            Ok(RateLimitResult {
                allowed: true,
                remaining_attempts: remaining,
                reset_time,
                retry_after_secs: None,
            })
        }
    }

    async fn check_rate_limit_memory(
        &self,
        user_id: &str,
        limit_type: &str,
        max_attempts: i64,
        window_secs: u64,
    ) -> Result<RateLimitResult, RateLimitError> {
        let current_time = Self::current_time().await;
        let window_start = (current_time / window_secs) * window_secs;
        let reset_time = window_start + window_secs;

        let attempts_map = match limit_type {
            "verify" => &self.fallback.verification_attempts,
            "register" => &self.fallback.registration_attempts,
            "otp_send" => &self.fallback.otp_sends,
            "backup_code" => &self.fallback.backup_code_attempts,
            _ => return Err(RateLimitError::InvalidConfiguration(format!("Unknown limit type: {}", limit_type))),
        };

        let mut attempts = attempts_map.write().await;
        let (current_count, stored_reset_time) = attempts
            .entry(user_id.to_string())
            .or_insert((0, reset_time));

        // Reset counter if we're in a new window
        if current_time >= *stored_reset_time {
            *current_count = 0;
            *stored_reset_time = reset_time;
        }

        *current_count += 1;
        let remaining = (max_attempts - *current_count).max(0);

        if *current_count > max_attempts {
            let retry_after = if self.config.progressive_delays_enabled {
                Some(self.calculate_progressive_delay(*current_count - max_attempts))
            } else {
                Some(*stored_reset_time - current_time)
            };

            Ok(RateLimitResult {
                allowed: false,
                remaining_attempts: 0,
                reset_time: Some(*stored_reset_time),
                retry_after_secs: retry_after,
            })
        } else {
            Ok(RateLimitResult {
                allowed: true,
                remaining_attempts: remaining,
                reset_time: Some(*stored_reset_time),
                retry_after_secs: None,
            })
        }
    }

    fn calculate_progressive_delay(&self, excess_attempts: i64) -> u64 {
        // Exponential backoff: 2^(excess_attempts) seconds, capped at lockout duration
        let delay = (2_u64.pow(excess_attempts.min(10) as u32)).min(self.config.lockout_duration_secs);
        delay
    }

    pub async fn reset_rate_limit(&self, user_id: &str, limit_type: &str) -> Result<(), RateLimitError> {
        if let Some(mut conn) = self.redis.clone() {
            let pattern = format!("mfa:rate:{}:{}:*", limit_type, user_id);
            let keys: Vec<String> = conn.keys(&pattern).await?;
            if !keys.is_empty() {
                conn.del(&keys).await?;
            }
        } else {
            // Reset in memory
            let attempts_map = match limit_type {
                "verify" => &self.fallback.verification_attempts,
                "register" => &self.fallback.registration_attempts,
                "otp_send" => &self.fallback.otp_sends,
                "backup_code" => &self.fallback.backup_code_attempts,
                _ => return Err(RateLimitError::InvalidConfiguration(format!("Unknown limit type: {}", limit_type))),
            };

            let mut attempts = attempts_map.write().await;
            attempts.remove(user_id);
        }

        tracing::info!("Reset rate limit for user {} and type {}", user_id, limit_type);
        Ok(())
    }

    pub async fn get_rate_limit_status(&self, user_id: &str) -> Result<HashMap<String, RateLimitResult>, RateLimitError> {
        let mut status = HashMap::new();

        status.insert("verification".to_string(), self.check_verification_attempts(user_id).await?);
        status.insert("registration".to_string(), self.check_registration_attempts(user_id).await?);
        status.insert("otp_send".to_string(), self.check_otp_send_attempts(user_id).await?);
        status.insert("backup_code".to_string(), self.check_backup_code_attempts(user_id).await?);

        Ok(status)
    }

    pub async fn cleanup_expired_limits(&self) -> Result<u64, RateLimitError> {
        let Some(mut conn) = self.redis.clone() else {
            // For in-memory, cleanup happens automatically with time window checks
            return Ok(0);
        };

        let pattern = "mfa:rate:*";
        let keys: Vec<String> = conn.keys(&pattern).await?;
        let mut cleaned = 0;

        for key in keys {
            let ttl: i64 = conn.ttl(&key).await?;
            if ttl < 0 {
                // Key has no TTL or is expired
                let deleted: u64 = conn.del(&key).await?;
                cleaned += deleted;
            }
        }

        if cleaned > 0 {
            tracing::debug!("Cleaned up {} expired rate limit entries", cleaned);
        }

        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_rate_limiting_basic() {
        let config = RateLimitConfig {
            max_verification_attempts_per_5min: 3,
            ..Default::default()
        };
        let limiter = MfaRateLimiter::new(config).await;
        let user_id = "test_user";

        // First 3 attempts should succeed
        for i in 1..=3 {
            let result = limiter.check_verification_attempts(user_id).await.unwrap();
            assert!(operation_result.allowed, "Attempt {} should be allowed", i);
            assert_eq!(operation_result.remaining_attempts, 3 - i);
        }

        // 4th attempt should fail
        let result = limiter.check_verification_attempts(user_id).await.unwrap();
        assert!(!operation_result.allowed);
        assert_eq!(operation_result.remaining_attempts, 0);
    }

    #[tokio::test]
    async fn test_progressive_delays() {
        let config = RateLimitConfig {
            max_verification_attempts_per_5min: 1,
            progressive_delays_enabled: true,
            ..Default::default()
        };
        let limiter = MfaRateLimiter::new(config).await;
        let user_id = "test_user";

        // First attempt succeeds
        let result1 = limiter.check_verification_attempts(user_id).await.unwrap();
        assert!(result1.allowed);

        // Second attempt fails with 2 second delay
        let result2 = limiter.check_verification_attempts(user_id).await.unwrap();
        assert!(!result2.allowed);
        assert_eq!(result2.retry_after_secs, Some(2));

        // Third attempt fails with 4 second delay
        let result3 = limiter.check_verification_attempts(user_id).await.unwrap();
        assert!(!result3.allowed);
        assert_eq!(result3.retry_after_secs, Some(4));
    }

    #[tokio::test]
    async fn test_rate_limit_reset() {
        let config = RateLimitConfig {
            max_verification_attempts_per_5min: 1,
            ..Default::default()
        };
        let limiter = MfaRateLimiter::new(config).await;
        let user_id = "test_user";

        // Exhaust rate limit
        let _result1 = limiter.check_verification_attempts(user_id).await.unwrap();
        let result2 = limiter.check_verification_attempts(user_id).await.unwrap();
        assert!(!result2.allowed);

        // Reset rate limit
        limiter.reset_rate_limit(user_id, "verify").await.unwrap();

        // Should be able to make requests again
        let result3 = limiter.check_verification_attempts(user_id).await.unwrap();
        assert!(result3.allowed);
    }

    #[tokio::test]
    async fn test_different_limit_types_independent() {
        let limiter = MfaRateLimiter::with_defaults().await;
        let user_id = "test_user";

        // Check different limit types don't interfere with each other
        let verify_result = limiter.check_verification_attempts(user_id).await.unwrap();
        let register_result = limiter.check_registration_attempts(user_id).await.unwrap();
        let otp_result = limiter.check_otp_send_attempts(user_id).await.unwrap();

        assert!(verify_operation_result.allowed);
        assert!(register_operation_result.allowed);
        assert!(otp_operation_result.allowed);
    }
}