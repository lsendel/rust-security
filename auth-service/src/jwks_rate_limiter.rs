//! JWKS-specific rate limiting implementation
//!
//! Provides strict rate limiting for JWKS endpoints with:
//! - Per-IP rate limiting
//! - Global rate limiting
//! - Burst protection
//! - Distributed rate limiting with Redis
//! - Automatic ban list for abusive clients

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use deadpool_redis::redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

/// Rate limit configuration for JWKS endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksRateLimitConfig {
    /// Maximum requests per minute per IP
    pub per_ip_rpm: u32,
    /// Maximum burst size per IP
    pub per_ip_burst: u32,
    /// Global maximum requests per minute
    pub global_rpm: u32,
    /// Global burst size
    pub global_burst: u32,
    /// Ban duration for violators (seconds)
    pub ban_duration_seconds: u64,
    /// Number of violations before ban
    pub violations_before_ban: u32,
    /// Enable Redis-backed distributed rate limiting
    pub use_redis: bool,
    /// Redis key prefix
    pub redis_prefix: String,
}

impl Default for JwksRateLimitConfig {
    fn default() -> Self {
        Self {
            per_ip_rpm: 60,             // 60 requests per minute per IP
            per_ip_burst: 10,           // Allow burst of 10 requests
            global_rpm: 1000,           // 1000 requests per minute globally
            global_burst: 100,          // Allow global burst of 100
            ban_duration_seconds: 3600, // 1 hour ban
            violations_before_ban: 5,   // Ban after 5 violations
            use_redis: true,
            redis_prefix: "jwks_rate_limit".to_string(),
        }
    }
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u32,
    tokens: f64,
    refill_rate: f64,
    last_refill: SystemTime,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: SystemTime::now(),
        }
    }

    pub fn try_consume(&mut self, tokens: u32) -> bool {
        self.refill();

        if self.tokens >= tokens as f64 {
            self.tokens -= tokens as f64;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = SystemTime::now();
        let elapsed = now
            .duration_since(self.last_refill)
            .unwrap_or(Duration::ZERO);
        let tokens_to_add = elapsed.as_secs_f64() * self.refill_rate;

        self.tokens = (self.tokens + tokens_to_add).min(self.capacity as f64);
        self.last_refill = now;
    }

    pub fn tokens_available(&self) -> u32 {
        self.tokens as u32
    }
}

/// Rate limiter state
pub struct JwksRateLimiter {
    config: JwksRateLimitConfig,
    ip_buckets: DashMap<IpAddr, TokenBucket>,
    global_bucket: Arc<RwLock<TokenBucket>>,
    violations: DashMap<IpAddr, u32>,
    ban_list: DashMap<IpAddr, SystemTime>,
    redis_client: Option<deadpool_redis::Pool>,
}

impl JwksRateLimiter {
    pub async fn new(config: JwksRateLimitConfig, redis_url: Option<String>) -> Self {
        let redis_client = if config.use_redis && redis_url.is_some() {
            let redis_config = deadpool_redis::Config::from_url(&redis_url.unwrap());
            match redis_config.create_pool(Some(deadpool_redis::Runtime::Tokio1)) {
                Ok(pool) => Some(pool),
                Err(e) => {
                    error!("Failed to create Redis pool for rate limiting: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let global_bucket = TokenBucket::new(config.global_burst, config.global_rpm as f64 / 60.0);

        Self {
            config,
            ip_buckets: DashMap::new(),
            global_bucket: Arc::new(RwLock::new(global_bucket)),
            violations: DashMap::new(),
            ban_list: DashMap::new(),
            redis_client,
        }
    }

    /// Check if an IP is banned
    pub async fn is_banned(&self, ip: &IpAddr) -> bool {
        // Check local ban list
        if let Some(ban_until) = self.ban_list.get(ip) {
            if SystemTime::now() < *ban_until {
                return true;
            } else {
                // Ban expired, remove it
                self.ban_list.remove(ip);
            }
        }

        // Check Redis ban list if available
        if let Some(ref pool) = self.redis_client {
            if let Ok(mut conn) = pool.get().await {
                let key = format!("{}:ban:{}", self.config.redis_prefix, ip);
                match conn.exists::<_, bool>(&key).await {
                    Ok(banned) => return banned,
                    Err(e) => {
                        warn!("Failed to check Redis ban list: {}", e);
                    }
                }
            }
        }

        false
    }

    /// Ban an IP address
    pub async fn ban_ip(&self, ip: IpAddr) {
        let ban_until = SystemTime::now() + Duration::from_secs(self.config.ban_duration_seconds);

        // Add to local ban list
        self.ban_list.insert(ip, ban_until);

        // Add to Redis ban list if available
        if let Some(ref pool) = self.redis_client {
            if let Ok(mut conn) = pool.get().await {
                let key = format!("{}:ban:{}", self.config.redis_prefix, ip);
                let _: Result<(), _> = conn.set(&key, 1).await;
                let _: Result<(), _> = conn
                    .expire(&key, self.config.ban_duration_seconds as i64)
                    .await;
            }
        }

        warn!(
            "IP {} has been banned for {} seconds",
            ip, self.config.ban_duration_seconds
        );
    }

    /// Record a violation for an IP
    pub async fn record_violation(&self, ip: IpAddr) {
        let mut violations = self.violations.entry(ip).or_insert(0);
        *violations += 1;

        if *violations >= self.config.violations_before_ban {
            self.ban_ip(ip).await;
            self.violations.remove(&ip);
        }
    }

    /// Check rate limit for an IP
    pub async fn check_rate_limit(&self, ip: IpAddr) -> RateLimitResult {
        // Check if banned
        if self.is_banned(&ip).await {
            return RateLimitResult::Banned;
        }

        // Check global rate limit
        let global_allowed = {
            let mut global_bucket = self.global_bucket.write().await;
            global_bucket.try_consume(1)
        };

        if !global_allowed {
            debug!("Global rate limit exceeded");
            return RateLimitResult::GlobalLimitExceeded;
        }

        // Check per-IP rate limit
        let ip_allowed = if let Some(ref pool) = self.redis_client {
            // Use Redis for distributed rate limiting
            if let Ok(mut conn) = pool.get().await {
                self.check_redis_rate_limit(&mut conn, &ip).await
            } else {
                // Fall back to local rate limiting
                self.check_local_rate_limit(&ip)
            }
        } else {
            // Use local rate limiting
            self.check_local_rate_limit(&ip)
        };

        if !ip_allowed {
            self.record_violation(ip).await;
            return RateLimitResult::IpLimitExceeded;
        }

        RateLimitResult::Allowed
    }

    /// Check rate limit using local token bucket
    fn check_local_rate_limit(&self, ip: &IpAddr) -> bool {
        let mut bucket = self.ip_buckets.entry(*ip).or_insert_with(|| {
            TokenBucket::new(
                self.config.per_ip_burst,
                self.config.per_ip_rpm as f64 / 60.0,
            )
        });

        bucket.try_consume(1)
    }

    /// Check rate limit using Redis
    async fn check_redis_rate_limit(
        &self,
        conn: &mut deadpool_redis::Connection,
        ip: &IpAddr,
    ) -> bool {
        let key = format!("{}:ip:{}", self.config.redis_prefix, ip);
        let window = 60; // 1 minute window

        // Use Redis INCR with expiry (simplified approach)
        match conn.incr::<_, _, i64>(&key, 1).await {
            Ok(count) => {
                if count == 1 {
                    // Set expiry on first increment
                    let _: Result<(), _> = conn.expire(&key, window as i64).await;
                }
                count <= self.config.per_ip_rpm as i64
            }
            Err(e) => {
                warn!("Redis rate limit check failed: {}", e);
                // Fall back to local rate limiting
                self.check_local_rate_limit(ip)
            }
        }
    }

    /// Clean up expired entries
    pub async fn cleanup(&self) {
        // Clean up expired bans
        let now = SystemTime::now();
        self.ban_list.retain(|_, ban_until| *ban_until > now);

        // Clean up old violation records
        self.violations.clear();

        // Clean up old token buckets (keep only recent ones)
        let cutoff = SystemTime::now() - Duration::from_secs(300); // 5 minutes
        self.ip_buckets
            .retain(|_, bucket| bucket.last_refill > cutoff);

        debug!("Rate limiter cleanup completed");
    }
}

/// Rate limit check result
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitResult {
    Allowed,
    IpLimitExceeded,
    GlobalLimitExceeded,
    Banned,
}

/// Rate limiting middleware for JWKS endpoints
pub async fn jwks_rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(limiter): State<Arc<JwksRateLimiter>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let ip = addr.ip();

    match limiter.check_rate_limit(ip).await {
        RateLimitResult::Allowed => {
            // Continue to the handler
            next.run(request).await
        }
        RateLimitResult::IpLimitExceeded => {
            warn!("Rate limit exceeded for IP: {}", ip);
            rate_limit_response(429, "Rate limit exceeded", Some(60))
        }
        RateLimitResult::GlobalLimitExceeded => {
            warn!("Global rate limit exceeded");
            rate_limit_response(503, "Service temporarily unavailable", Some(10))
        }
        RateLimitResult::Banned => {
            warn!("Banned IP attempted access: {}", ip);
            rate_limit_response(403, "Access forbidden", None)
        }
    }
}

/// Build rate limit error response
fn rate_limit_response(status_code: u16, message: &str, retry_after: Option<u32>) -> Response {
    let mut headers = HeaderMap::new();

    if let Some(retry) = retry_after {
        headers.insert("Retry-After", retry.to_string().parse().unwrap());
    }

    headers.insert("X-RateLimit-Limit", "60".parse().unwrap());

    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::TOO_MANY_REQUESTS);

    (status, headers, message.to_string()).into_response()
}

/// Start background cleanup task
pub async fn start_rate_limit_cleanup(limiter: Arc<JwksRateLimiter>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60)); // Every minute

    loop {
        interval.tick().await;
        limiter.cleanup().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 1.0);

        // Should allow initial burst
        for _ in 0..10 {
            assert!(bucket.try_consume(1));
        }

        // Should be exhausted
        assert!(!bucket.try_consume(1));

        // Wait and refill
        std::thread::sleep(Duration::from_secs(2));
        bucket.refill();

        // Should have ~2 tokens
        assert!(bucket.try_consume(1));
        assert!(bucket.try_consume(1));
        assert!(!bucket.try_consume(1));
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let config = JwksRateLimitConfig {
            per_ip_rpm: 10,
            per_ip_burst: 5,
            global_rpm: 100,
            global_burst: 20,
            use_redis: false,
            ..Default::default()
        };

        let limiter = JwksRateLimiter::new(config, None).await;
        let ip = "127.0.0.1".parse().unwrap();

        // Should allow initial requests
        for _ in 0..5 {
            assert_eq!(limiter.check_rate_limit(ip).await, RateLimitResult::Allowed);
        }

        // Should be rate limited after burst
        assert_eq!(
            limiter.check_rate_limit(ip).await,
            RateLimitResult::IpLimitExceeded
        );
    }
}
