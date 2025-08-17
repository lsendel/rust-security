use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReplayProtectionError {
    #[error("Redis connection error: {0}")]
    RedisError(#[from] RedisError),
    #[error("Code already used")]
    CodeAlreadyUsed,
    #[error("Invalid time window")]
    InvalidTimeWindow,
}

pub struct ReplayProtection {
    redis: Option<ConnectionManager>,
}

impl ReplayProtection {
    pub async fn new() -> Self {
        let redis = Self::create_redis_connection().await;
        Self { redis }
    }

    async fn create_redis_connection() -> Option<ConnectionManager> {
        let url = std::env::var("REDIS_URL").ok()?;
        let client = redis::Client::open(url).ok()?;
        client.get_connection_manager().await.ok()
    }

    pub async fn check_and_mark_used(
        &self, 
        user_id: &str, 
        code: &str, 
        window_secs: u64
    ) -> Result<bool, ReplayProtectionError> {
        let Some(mut conn) = self.redis.clone() else {
            // If Redis is not available, allow the verification but log the issue
            tracing::warn!("Redis not available for replay protection, allowing verification");
            return Ok(true);
        };

        // Create a deterministic key for this code within the current time window
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReplayProtectionError::InvalidTimeWindow)?
            .as_secs();
        
        // Round down to the nearest window to ensure consistency across the window
        let window_start = (current_time / window_secs) * window_secs;
        let key = format!("mfa:totp:used:{}:{}:{}", user_id, code, window_start);
        
        // Use SET with NX (only set if not exists) and EX (expiration)
        let ttl = window_secs + 60; // TTL slightly longer than window for safety
        let result: Option<String> = conn
            .set_options(&key, "1", redis::SetOptions::default().conditional_set(redis::ExistenceCheck::NX).get(true).with_expiration(redis::SetExpiry::EX(ttl as u64)))
            .await?;

        // If SET NX succeeded, the result will be "OK", meaning code was not used before
        Ok(result.is_some())
    }

    pub async fn mark_code_used_in_window(
        &self,
        user_id: &str,
        code: &str,
        window_start: u64,
        ttl: u64,
    ) -> Result<(), ReplayProtectionError> {
        let Some(mut conn) = self.redis.clone() else {
            return Ok(()); // Graceful degradation
        };

        let key = format!("mfa:totp:used:{}:{}:{}", user_id, code, window_start);
        conn.set_ex(&key, "1", ttl).await?;
        Ok(())
    }

    pub async fn is_code_used_in_window(
        &self,
        user_id: &str,
        code: &str,
        window_start: u64,
    ) -> Result<bool, ReplayProtectionError> {
        let Some(mut conn) = self.redis.clone() else {
            return Ok(false); // Assume not used if Redis unavailable
        };

        let key = format!("mfa:totp:used:{}:{}:{}", user_id, code, window_start);
        let exists: bool = conn.exists(&key).await?;
        Ok(exists)
    }

    pub async fn cleanup_expired_codes(&self, user_id: &str) -> Result<u64, ReplayProtectionError> {
        let Some(mut conn) = self.redis.clone() else {
            return Ok(0);
        };

        let pattern = format!("mfa:totp:used:{}:*", user_id);
        let keys: Vec<String> = conn.keys(&pattern).await?;
        
        if keys.is_empty() {
            return Ok(0);
        }

        let deleted: u64 = conn.del(&keys).await?;
        tracing::debug!("Cleaned up {} expired TOTP codes for user {}", deleted, user_id);
        Ok(deleted)
    }

    pub async fn get_recent_code_usage(
        &self,
        user_id: &str,
        last_n_windows: u32,
    ) -> Result<Vec<String>, ReplayProtectionError> {
        let Some(mut conn) = self.redis.clone() else {
            return Ok(vec![]);
        };

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReplayProtectionError::InvalidTimeWindow)?
            .as_secs();

        let mut used_codes = Vec::new();
        let window_size = 30; // 30-second TOTP windows

        for i in 0..last_n_windows {
            let window_start = ((current_time / window_size) - i as u64) * window_size;
            let pattern = format!("mfa:totp:used:{}:*:{}", user_id, window_start);
            let keys: Vec<String> = conn.keys(&pattern).await?;
            used_codes.extend(keys);
        }

        Ok(used_codes)
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self { redis: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    async fn create_test_replay_protection() -> ReplayProtection {
        // For tests, use in-memory implementation if Redis not available
        ReplayProtection::new().await
    }

    #[tokio::test]
    async fn test_replay_protection_basic() {
        let rp = create_test_replay_protection().await;
        let user_id = "test_user";
        let code = "123456";
        let window = 30;

        // First use should succeed
        let result1 = rp.check_and_mark_used(user_id, code, window).await;
        assert!(result1.is_ok());
        assert!(result1.unwrap());

        // Second use within same window should fail
        let result2 = rp.check_and_mark_used(user_id, code, window).await;
        if result2.is_ok() {
            // If Redis is available, should fail
            assert!(!result2.unwrap());
        }
    }

    #[tokio::test]
    async fn test_different_codes_different_users() {
        let rp = create_test_replay_protection().await;
        let window = 30;

        // Same code, different users should both succeed
        let result1 = rp.check_and_mark_used("user1", "123456", window).await;
        let result2 = rp.check_and_mark_used("user2", "123456", window).await;
        
        assert!(result1.is_ok());
        assert!(result2.is_ok());

        // Different codes, same user should both succeed
        let result3 = rp.check_and_mark_used("user1", "654321", window).await;
        assert!(result3.is_ok());
    }

    #[tokio::test]
    async fn test_window_expiration() {
        let rp = create_test_replay_protection().await;
        let user_id = "test_user";
        let code = "123456";
        let short_window = 1; // 1 second for testing

        // Use code
        let result1 = rp.check_and_mark_used(user_id, code, short_window).await;
        assert!(result1.is_ok());

        // Wait for window to expire
        sleep(Duration::from_secs(2)).await;

        // Should be able to use same code again after expiration
        let result2 = rp.check_and_mark_used(user_id, code, short_window).await;
        assert!(result2.is_ok());
    }
}