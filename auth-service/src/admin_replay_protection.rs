use crate::shared::error::AppError;
use dashmap::DashMap;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, warn};

/// Replay protection for admin requests
/// Prevents replay attacks by tracking nonces and enforcing time windows
#[derive(Clone)]
pub struct ReplayProtection {
    /// Redis client for distributed nonce storage
    redis_client: Option<redis::Client>,
    /// In-memory fallback for nonce storage
    local_cache: Arc<DashMap<String, u64>>,
    /// Time window for request validity (seconds)
    time_window: u64,
    /// Maximum allowed clock skew (seconds)
    max_clock_skew: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestSignature {
    /// Unique nonce for this request
    pub nonce: String,
    /// Timestamp when request was created
    pub timestamp: u64,
    /// Request method (GET, POST, etc.)
    pub method: String,
    /// Request path
    pub path: String,
    /// HMAC signature
    pub signature: String,
}

impl ReplayProtection {
    /// Create a new replay protection instance
    #[must_use]
    pub fn new(redis_url: Option<&str>, time_window: u64, max_clock_skew: u64) -> Self {
        let redis_client = redis_url.and_then(|url| {
            redis::Client::open(url)
                .map_err(|e| {
                    error!("Failed to create Redis client for replay protection: {}", e);
                    e
                })
                .ok()
        });

        Self {
            redis_client,
            local_cache: Arc::new(DashMap::new()),
            time_window,
            max_clock_skew,
        }
    }

    /// Validate request to prevent replay attacks
    pub async fn validate_request(
        &self,
        nonce: &str,
        timestamp: u64,
        signature: &str,
        secret: &str,
        method: &str,
        path: &str,
    ) -> Result<(), crate::shared::error::AppError> {
        // Step 1: Verify HMAC signature first
        if !Self::verify_signature(secret, method, path, nonce, timestamp, signature) {
            warn!("Invalid signature provided for admin request");
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Invalid request signature".to_string(),
            });
        }

        // Step 2: Validate timestamp is within acceptable window
        self.validate_timestamp(timestamp)?;

        // Step 3: Check if nonce has been used
        if self.is_nonce_used(nonce).await? {
            warn!("Replay attack detected: nonce already used");
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Request replay detected".to_string(),
            });
        }

        // Step 4: Store nonce to prevent future replay
        self.store_nonce(nonce, timestamp).await?;

        Ok(())
    }

    /// Validate timestamp is within acceptable window
    fn validate_timestamp(&self, timestamp: u64) -> Result<(), crate::shared::error::AppError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crate::shared::error::AppError::Internal {
                error_id: uuid::Uuid::new_v4(),
                context: "Time error".to_string(),
            })?
            .as_secs();

        // Check if timestamp is too old
        if timestamp + self.time_window < now {
            warn!(
                "Request timestamp too old: {} (current: {})",
                timestamp, now
            );
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Request expired".to_string(),
            });
        }

        // Check if timestamp is too far in the future (clock skew)
        if timestamp > now + self.max_clock_skew {
            warn!(
                "Request timestamp too far in future: {} (current: {})",
                timestamp, now
            );
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Invalid timestamp".to_string(),
            });
        }

        Ok(())
    }

    /// Check if nonce has been used
    async fn is_nonce_used(&self, nonce: &str) -> Result<bool, crate::shared::error::AppError> {
        // Try Redis first
        if let Some(client) = &self.redis_client {
            match self.check_redis_nonce(client, nonce).await {
                Ok(used) => return Ok(used),
                Err(e) => {
                    error!("Redis nonce check failed, falling back to local: {}", e);
                }
            }
        }

        // Fallback to local cache
        Ok(self.local_cache.contains_key(nonce))
    }

    /// Check Redis for nonce
    async fn check_redis_nonce(
        &self,
        client: &redis::Client,
        nonce: &str,
    ) -> Result<bool, redis::RedisError> {
        let mut conn = client.get_multiplexed_async_connection().await?;
        let key = format!("admin:nonce:{}", nonce);
        let exists: bool = conn.exists(&key).await?;
        Ok(exists)
    }

    /// Store nonce to prevent replay
    async fn store_nonce(
        &self,
        nonce: &str,
        timestamp: u64,
    ) -> Result<(), crate::shared::error::AppError> {
        let expiry = self.time_window + self.max_clock_skew;

        // Try Redis first
        if let Some(client) = &self.redis_client {
            match self
                .store_redis_nonce(client, nonce, timestamp, expiry)
                .await
            {
                Ok(()) => {
                    // Also store locally for redundancy
                    self.local_cache.insert(nonce.to_string(), timestamp);
                    self.cleanup_local_cache();
                    return Ok(());
                }
                Err(e) => {
                    error!("Redis nonce storage failed, using local only: {}", e);
                }
            }
        }

        // Fallback to local cache
        self.local_cache.insert(nonce.to_string(), timestamp);
        self.cleanup_local_cache();
        Ok(())
    }

    /// Store nonce in Redis with expiry
    async fn store_redis_nonce(
        &self,
        client: &redis::Client,
        nonce: &str,
        timestamp: u64,
        expiry: u64,
    ) -> Result<(), redis::RedisError> {
        let mut conn = client.get_multiplexed_async_connection().await?;
        let key = format!("admin:nonce:{}", nonce);

        // Store with expiry
        conn.set_ex(&key, timestamp, expiry).await?;
        Ok(())
    }

    /// Clean up expired entries from local cache
    fn cleanup_local_cache(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expired_window = self.time_window + self.max_clock_skew;

        // Remove entries older than the time window
        self.local_cache
            .retain(|_, timestamp| *timestamp + expired_window > now);
    }

    /// Generate a secure nonce
    #[must_use]
    pub fn generate_nonce() -> String {
        use base64::{engine::general_purpose, Engine as _};
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        general_purpose::STANDARD.encode(bytes)
    }
}

impl ReplayProtection {
    /// Create HMAC signature for request
    #[must_use]
    pub fn create_signature(
        secret: &str,
        method: &str,
        path: &str,
        nonce: &str,
        timestamp: u64,
    ) -> String {
        use crate::infrastructure::crypto::crypto_unified::UnifiedHmac;
        use base64::{engine::general_purpose, Engine as _};

        let message = format!("{}:{}:{}:{}", method, path, nonce, timestamp);
        let hmac_result = UnifiedHmac::hmac_sha256(secret.as_bytes(), message.as_bytes());

        general_purpose::STANDARD.encode(hmac_result)
    }

    /// Verify HMAC signature
    #[must_use]
    pub fn verify_signature(
        secret: &str,
        method: &str,
        path: &str,
        nonce: &str,
        timestamp: u64,
        provided_signature: &str,
    ) -> bool {
        use crate::infrastructure::crypto::crypto_unified::UnifiedHmac;
        use base64::{engine::general_purpose, Engine as _};

        let message = format!("{}:{}:{}:{}", method, path, nonce, timestamp);

        // Decode the provided signature
        let Ok(provided_bytes) = general_purpose::STANDARD.decode(provided_signature) else {
            return false;
        };

        // Use ring's constant-time HMAC verification
        UnifiedHmac::verify_hmac_sha256(secret.as_bytes(), message.as_bytes(), &provided_bytes)
    }
}

/// Rate limiter for admin endpoints
pub struct AdminRateLimiter {
    /// Request counts per admin key
    requests: Arc<DashMap<String, Vec<u64>>>,
    /// Maximum requests per window
    max_requests: u32,
    /// Time window in seconds
    window_seconds: u64,
}

impl AdminRateLimiter {
    #[must_use]
    pub fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            requests: Arc::new(DashMap::new()),
            max_requests,
            window_seconds,
        }
    }

    /// Check if request should be rate limited
    pub fn check_rate_limit(&self, admin_key: &str) -> Result<(), crate::shared::error::AppError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let window_start = now - self.window_seconds;

        // Get or create request history
        let mut entry = self.requests.entry(admin_key.to_string()).or_default();

        // Remove old entries outside the window
        entry.retain(|timestamp| *timestamp > window_start);

        // Check if limit exceeded
        if entry.len() >= self.max_requests as usize {
            warn!(
                "Rate limit exceeded for admin key: {} ({} requests in {} seconds)",
                admin_key,
                entry.len(),
                self.window_seconds
            );
            return Err(crate::shared::error::AppError::RateLimitExceeded);
        }

        // Add current request
        entry.push(now);

        Ok(())
    }

    /// Clean up old entries periodically
    pub fn cleanup(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let window_start = now - self.window_seconds;

        self.requests.retain(|_, timestamps| {
            timestamps.retain(|t| *t > window_start);
            !timestamps.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_replay_protection() {
        let replay_protection = ReplayProtection::new(None, 300, 60);
        let secret = std::env::var("TEST_SECRET")
            .unwrap_or_else(|_| "test_secret_for_development_only".to_string());
        let method = "POST";
        let path = "/admin/test";

        let nonce = ReplayProtection::generate_nonce();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signature =
            ReplayProtection::create_signature(&secret, method, path, &nonce, timestamp);

        // First request should succeed
        assert!(replay_protection
            .validate_request(&nonce, timestamp, &signature, &secret, method, path)
            .await
            .is_ok());

        // Replay should fail
        assert!(replay_protection
            .validate_request(&nonce, timestamp, &signature, &secret, method, path)
            .await
            .is_err());
    }

    #[test]
    fn test_signature_generation() {
        let secret = std::env::var("TEST_SECRET")
            .unwrap_or_else(|_| "test_secret_for_development_only".to_string());
        let method = "POST";
        let path = "/admin/users";
        let nonce = "test_nonce";
        let timestamp = 1_234_567_890;

        let signature = ReplayProtection::create_signature(&secret, method, path, nonce, timestamp);

        assert!(ReplayProtection::verify_signature(
            secret, method, path, nonce, timestamp, &signature
        ));

        // Wrong signature should fail
        assert!(!ReplayProtection::verify_signature(
            secret,
            method,
            path,
            nonce,
            timestamp,
            "wrong_signature"
        ));
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = AdminRateLimiter::new(3, 60);
        let admin_key = std::env::var("ADMIN_TEST_KEY")
            .unwrap_or_else(|_| "admin_test_key_for_development_only".to_string());

        // First 3 requests should succeed
        assert!(limiter.check_rate_limit(&admin_key).is_ok());
        assert!(limiter.check_rate_limit(&admin_key).is_ok());
        assert!(limiter.check_rate_limit(&admin_key).is_ok());

        // 4th request should fail
        assert!(limiter.check_rate_limit(&admin_key).is_err());
    }

    #[tokio::test]
    async fn test_timestamp_validation() {
        let replay_protection = ReplayProtection::new(None, 300, 60);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Current timestamp should be valid
        assert!(replay_protection.validate_timestamp(now).is_ok());

        // Old timestamp should fail
        assert!(replay_protection.validate_timestamp(now - 400).is_err());

        // Future timestamp beyond skew should fail
        assert!(replay_protection.validate_timestamp(now + 120).is_err());
    }
}
