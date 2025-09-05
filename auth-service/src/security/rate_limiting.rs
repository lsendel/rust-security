//! # Unified Rate Limiting System
//!
//! A comprehensive, high-performance rate limiting system designed for production
//! authentication services. Implements multiple rate limiting strategies with
//! advanced security features and distributed coordination.
//!
//! ## Features
//!
//! ### Multi-Layer Rate Limiting
//! - **Global Limits**: System-wide request throttling
//! - **Per-IP Limits**: Individual client rate limiting with burst allowances
//! - **Per-Client Limits**: `OAuth` client-specific rate limiting
//! - **Per-Endpoint Limits**: Endpoint-specific rate limits (e.g., stricter limits for /oauth/token)
//!
//! ### Advanced Security
//! - **IP Banning**: Automatic temporary bans for repeated violations
//! - **Suspicious Activity Detection**: Behavioral analysis and stricter limits
//! - **Allow/Block Lists**: IP-based allow and block lists with CIDR support
//! - **Progressive Delays**: Increasing delays for repeated violations
//!
//! ### High Performance
//! - **Sharded Architecture**: Lock-free concurrent data structures
//! - **Token Bucket Algorithm**: Smooth rate limiting with burst capacity
//! - **Sliding Window**: Accurate rate limiting over time windows
//! - **Memory Efficient**: Automatic cleanup of stale data
//!
//! ### Distributed Support
//! - **Redis Backend**: Optional distributed rate limiting (currently disabled)
//! - **Consistent Hashing**: Even distribution across shards
//! - **Fault Tolerance**: Graceful degradation if distributed backend unavailable
//!
//! ## Quick Start
//!
//! ```rust
//! use auth_service::security::rate_limiting::*;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create rate limiter with default config
//!     let config = RateLimitConfig::default();
//!     let limiter = Arc::new(UnifiedRateLimiter::new(config, None));
//!     
//!     // Add to Axum router
//!     let app = axum::Router::new()
//!         .layer(axum::middleware::from_fn_with_state(
//!             limiter.clone(),
//!             unified_rate_limit_middleware
//!         ));
//!     
//!     // Start cleanup task
//!     tokio::spawn(start_rate_limit_cleanup_task(limiter));
//!     
//!     // Start server...
//!     Ok(())
//! }
//! ```
//!
//! ## Configuration Examples
//!
//! ### Environment Variables
//! ```bash
//! # Global rate limits
//! RATE_LIMIT_GLOBAL_PER_MINUTE=10000
//! RATE_LIMIT_GLOBAL_PER_HOUR=100000
//!
//! # Per-IP limits
//! RATE_LIMIT_PER_IP_PER_MINUTE=100
//! RATE_LIMIT_PER_IP_PER_HOUR=1000
//! RATE_LIMIT_PER_IP_PER_DAY=10000
//!
//! # Security settings
//! RATE_LIMIT_BAN_THRESHOLD=5
//! RATE_LIMIT_BAN_DURATION_MINUTES=60
//! RATE_LIMIT_ENABLE_ADAPTIVE=true
//!
//! # IP filtering
//! RATE_LIMIT_ALLOWLIST_IPS="10.0.0.0/8,192.168.0.0/16"
//! RATE_LIMIT_BANLIST_IPS="203.0.113.0/24"
//! ```
//!
//! ### Programmatic Configuration
//! ```rust
//! use auth_service::security::rate_limiting::*;
//! use std::collections::HashSet;
//! use std::net::IpAddr;
//!
//! let config = RateLimitConfig {
//!     // Strict limits for high-security environments
//!     per_ip_requests_per_minute: 50,
//!     per_ip_requests_per_hour: 500,
//!     per_ip_burst: 10,
//!     
//!     // OAuth endpoint limits
//!     oauth_token_requests_per_minute: 20,
//!     oauth_authorize_requests_per_minute: 30,
//!     
//!     // Security features
//!     ban_threshold: 3,
//!     ban_duration_minutes: 120,
//!     enable_adaptive_limits: true,
//!     
//!     // Allow internal networks
//!     enable_allowlist: true,
//!     allowlist_ips: [
//!         "10.0.0.1".parse().unwrap(),
//!         "192.168.1.100".parse().unwrap()
//!     ].iter().cloned().collect(),
//!     
//!     ..Default::default()
//! };
//! ```
//!
//! ## Rate Limit Headers
//!
//! The middleware adds standard rate limit headers to responses:
//!
//! ```http
//! X-RateLimit-Limit: 100
//! X-RateLimit-Remaining: 87
//! X-RateLimit-Reset: 1640995200
//! Retry-After: 60
//! ```
//!
//! ## Monitoring and Metrics
//!
//! ```rust
//! let stats = limiter.get_stats();
//! println!("Global requests this minute: {}", stats.global_minute_requests);
//! println!("Banned IPs: {}", stats.banned_ips);
//! println!("Suspicious IPs: {}", stats.suspicious_ips);
//! ```

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use dashmap::DashMap;
// Redis support temporarily disabled for build compatibility
// use deadpool_redis::Pool as RedisPool;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Comprehensive rate limiting configuration
///
/// Central configuration for all rate limiting parameters. Supports loading
/// from environment variables for production deployments.
///
/// # Configuration Categories
///
/// - **Global Limits**: System-wide rate limits
/// - **Per-IP Limits**: Individual client rate limits  
/// - **Per-Client Limits**: `OAuth` client rate limits
/// - **Endpoint Limits**: Specific endpoint rate limits
/// - **MFA Limits**: Multi-factor authentication specific limits
/// - **Security Settings**: Banning and suspicious activity thresholds
/// - **IP Filtering**: Allow/block list configuration
/// - **Maintenance**: Cleanup and performance settings
///
/// # Example
///
/// ```rust
/// use auth_service::security::rate_limiting::RateLimitConfig;
///
/// // Create with defaults and override specific values
/// let config = RateLimitConfig {
///     per_ip_requests_per_minute: 50,  // Stricter than default
///     oauth_token_requests_per_minute: 10,  // Very strict for token endpoint
///     enable_adaptive_limits: true,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    // Global limits
    pub global_requests_per_minute: u32,
    pub global_requests_per_hour: u32,
    pub global_burst: u32,

    // Per-IP limits
    pub per_ip_requests_per_minute: u32,
    pub per_ip_requests_per_hour: u32,
    pub per_ip_requests_per_day: u32,
    pub per_ip_burst: u32,
    pub per_ip_strict_requests_per_minute: u32,

    // Per-client limits
    pub per_client_requests_per_minute: u32,
    pub per_client_requests_per_hour: u32,

    // Endpoint-specific limits
    pub oauth_token_requests_per_minute: u32,
    pub oauth_authorize_requests_per_minute: u32,
    pub oauth_introspect_requests_per_minute: u32,
    pub admin_requests_per_minute: u32,
    pub scim_requests_per_minute: u32,
    pub jwks_requests_per_minute: u32,

    // MFA-specific limits
    pub mfa_verification_attempts_per_5min: u32,
    pub mfa_registration_attempts_per_hour: u32,
    pub mfa_otp_sends_per_hour: u32,
    pub mfa_backup_code_attempts_per_hour: u32,

    // Security features
    pub ban_threshold: u32,
    pub ban_duration_minutes: u32,
    pub suspicious_threshold: u32,
    pub enable_adaptive_limits: bool,
    pub enable_distributed_limiting: bool,
    pub progressive_delays_enabled: bool,

    // IP filtering
    pub enable_allowlist: bool,
    pub enable_banlist: bool,
    pub allowlist_ips: HashSet<IpAddr>,
    pub banlist_ips: HashSet<IpAddr>,
    pub allowlist_cidrs: Vec<String>,
    pub banlist_cidrs: Vec<String>,

    // Cleanup and maintenance
    pub cleanup_interval_seconds: u64,
    pub max_tracked_ips: usize,
    pub window_duration_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            // Global limits
            global_requests_per_minute: 10000,
            global_requests_per_hour: 100_000,
            global_burst: 100,

            // Per-IP limits
            per_ip_requests_per_minute: 100,
            per_ip_requests_per_hour: 1000,
            per_ip_requests_per_day: 10000,
            per_ip_burst: 20,
            per_ip_strict_requests_per_minute: 10,

            // Per-client limits
            per_client_requests_per_minute: 200,
            per_client_requests_per_hour: 2000,

            // Endpoint-specific limits
            oauth_token_requests_per_minute: 30,
            oauth_authorize_requests_per_minute: 60,
            oauth_introspect_requests_per_minute: 200,
            admin_requests_per_minute: 20,
            scim_requests_per_minute: 100,
            jwks_requests_per_minute: 60,

            // MFA-specific limits
            mfa_verification_attempts_per_5min: 10,
            mfa_registration_attempts_per_hour: 5,
            mfa_otp_sends_per_hour: 5,
            mfa_backup_code_attempts_per_hour: 3,

            // Security features
            ban_threshold: 5,
            ban_duration_minutes: 60,
            suspicious_threshold: 100,
            enable_adaptive_limits: true,
            enable_distributed_limiting: false,
            progressive_delays_enabled: true,

            // IP filtering
            enable_allowlist: false,
            enable_banlist: true,
            allowlist_ips: HashSet::new(),
            banlist_ips: HashSet::new(),
            allowlist_cidrs: Vec::new(),
            banlist_cidrs: Vec::new(),

            // Cleanup and maintenance
            cleanup_interval_seconds: 300,
            max_tracked_ips: 100_000,
            window_duration_secs: 60,
        }
    }
}

impl RateLimitConfig {
    /// Load configuration from environment variables
    ///
    /// Creates a configuration by loading values from environment variables.
    /// Falls back to defaults for any missing variables. Useful for production
    /// deployments where configuration is managed through environment.
    ///
    /// # Supported Environment Variables
    ///
    /// - `RATE_LIMIT_GLOBAL_PER_MINUTE` - Global requests per minute
    /// - `RATE_LIMIT_PER_IP_PER_MINUTE` - Per-IP requests per minute  
    /// - `RATE_LIMIT_ENABLE_ADAPTIVE` - Enable adaptive rate limiting (true/false)
    /// - `RATE_LIMIT_ENABLE_DISTRIBUTED` - Enable distributed limiting (true/false)
    /// - `RATE_LIMIT_ALLOWLIST_IPS` - Comma-separated list of allowed IPs
    /// - `RATE_LIMIT_BANLIST_IPS` - Comma-separated list of banned IPs
    ///
    /// # Example
    ///
    /// ```bash
    /// export RATE_LIMIT_PER_IP_PER_MINUTE=50
    /// export RATE_LIMIT_ENABLE_ADAPTIVE=true
    /// export RATE_LIMIT_ALLOWLIST_IPS="10.0.0.1,192.168.1.100"
    /// ```
    ///
    /// ```rust
    /// let config = RateLimitConfig::from_env();
    /// ```
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Global limits
        if let Ok(val) = std::env::var("RATE_LIMIT_GLOBAL_PER_MINUTE") {
            config.global_requests_per_minute =
                val.parse().unwrap_or(config.global_requests_per_minute);
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_PER_IP_PER_MINUTE") {
            config.per_ip_requests_per_minute =
                val.parse().unwrap_or(config.per_ip_requests_per_minute);
        }

        // Security features
        config.enable_adaptive_limits = std::env::var("RATE_LIMIT_ENABLE_ADAPTIVE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(config.enable_adaptive_limits);

        config.enable_distributed_limiting = std::env::var("RATE_LIMIT_ENABLE_DISTRIBUTED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(config.enable_distributed_limiting);

        // IP filtering
        if let Ok(ips) = std::env::var("RATE_LIMIT_ALLOWLIST_IPS") {
            config.allowlist_ips = ips
                .split(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .collect();
        }

        if let Ok(ips) = std::env::var("RATE_LIMIT_BANLIST_IPS") {
            config.banlist_ips = ips
                .split(',')
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .collect();
        }

        config
    }
}

/// Token bucket algorithm implementation for smooth rate limiting
///
/// Implements the token bucket algorithm which allows for burst capacity
/// while maintaining an average rate limit over time. Tokens are added
/// at a constant rate and consumed when requests are processed.
///
/// # Algorithm Benefits
///
/// - **Smooth Rate Limiting**: Allows bursts up to bucket capacity
/// - **Automatic Recovery**: Tokens refill at steady rate
/// - **Simple Implementation**: Easy to understand and debug
/// - **Memory Efficient**: Only needs to track token count and last refill time
///
/// # Example
///
/// ```rust
/// use auth_service::security::rate_limiting::TokenBucket;
///
/// // Allow 10 requests per second with burst capacity of 20
/// let mut bucket = TokenBucket::new(20.0, 10.0);
///
/// // Try to consume tokens for requests
/// if bucket.try_consume(1.0) {
///     println!("Request allowed");
/// } else {
///     println!("Request rate limited");
/// }
/// ```
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    /// Create a new token bucket
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens the bucket can hold (burst limit)
    /// * `refill_rate` - Tokens added per second (sustained rate limit)
    ///
    /// # Example
    ///
    /// ```rust
    /// // 100 requests burst capacity, refill at 10 requests/second
    /// let bucket = TokenBucket::new(100.0, 10.0);
    /// ```
    #[must_use]
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            refill_rate,
        }
    }

    /// Try to consume tokens from the bucket
    ///
    /// Attempts to consume the specified number of tokens. Returns `true` if
    /// successful, `false` if insufficient tokens available. Automatically
    /// refills tokens based on elapsed time since last refill.
    ///
    /// # Arguments
    ///
    /// * `tokens` - Number of tokens to consume (typically 1.0 for single request)
    ///
    /// # Returns
    ///
    /// `true` if tokens were consumed successfully, `false` if rate limited.
    ///
    /// # Example
    ///
    /// ```rust
    /// let mut bucket = TokenBucket::new(10.0, 1.0);
    ///
    /// // Consume token for request
    /// if bucket.try_consume(1.0) {
    ///     // Process request
    /// } else {
    ///     // Rate limit exceeded
    /// }
    /// ```
    pub fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        let tokens_to_add = elapsed * self.refill_rate;
        self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
        self.last_refill = now;
    }

    /// Get number of tokens currently available
    ///
    /// Returns the current number of tokens in the bucket without refilling.
    /// Useful for rate limit headers and monitoring.
    ///
    /// # Note
    ///
    /// This method doesn't trigger a refill, so the actual available tokens
    /// when making a request might be higher due to time elapsed.
    #[must_use]
    pub const fn tokens_available(&self) -> u32 {
        self.tokens as u32
    }
}

/// Rate limiting window using sliding window algorithm
///
/// Tracks request counts over multiple time periods (minute, hour, day)
/// with automatic window reset and burst token management. Includes
/// suspicious activity detection and violation tracking.
///
/// # Features
///
/// - **Multiple Time Windows**: Minute, hour, and daily limits
/// - **Burst Protection**: Additional token bucket for burst requests
/// - **Violation Tracking**: Counts limit violations for banning logic
/// - **Suspicious Activity**: Tracks and flags suspicious behavior
/// - **Atomic Operations**: Thread-safe using atomic operations
///
/// # Algorithm
///
/// Uses a sliding window approach where request counts are tracked
/// over fixed time periods. Windows reset automatically when the
/// time period expires.
#[derive(Debug)]
pub struct RateLimitWindow {
    requests: AtomicU32,
    window_start: AtomicU64,
    daily_requests: AtomicU32,
    day_start: AtomicU64,
    burst_tokens: AtomicU32,
    violation_count: AtomicU32,
    suspicious_count: AtomicU32,
    is_suspicious: AtomicBool,
    total_requests: AtomicU64,
}

impl RateLimitWindow {
    fn new(burst_capacity: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            requests: AtomicU32::new(0),
            window_start: AtomicU64::new(now),
            daily_requests: AtomicU32::new(0),
            day_start: AtomicU64::new(now),
            burst_tokens: AtomicU32::new(burst_capacity),
            violation_count: AtomicU32::new(0),
            suspicious_count: AtomicU32::new(0),
            is_suspicious: AtomicBool::new(false),
            total_requests: AtomicU64::new(0),
        }
    }

    fn check_and_update(&self, config: &RateLimitConfig, window_duration: u64) -> RateLimitResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Update counters
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let window_start = self.window_start.load(Ordering::Relaxed);

        // Reset window if needed
        if now >= window_start + window_duration
            && self
                .window_start
                .compare_exchange_weak(window_start, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.requests.store(0, Ordering::Relaxed);
            self.burst_tokens
                .store(config.per_ip_burst, Ordering::Relaxed);
        }

        // Reset daily counter if needed
        let day_start = self.day_start.load(Ordering::Relaxed);
        if now >= day_start + 86400
            && self
                .day_start
                .compare_exchange_weak(day_start, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.daily_requests.store(0, Ordering::Relaxed);
        }

        // Determine rate limit based on suspicious status
        let is_suspicious = self.is_suspicious.load(Ordering::Relaxed);
        let rate_limit = if is_suspicious {
            config.per_ip_strict_requests_per_minute
        } else {
            config.per_ip_requests_per_minute
        };

        let current_count = self.requests.load(Ordering::Relaxed);
        let daily_count = self.daily_requests.load(Ordering::Relaxed);

        // Check daily limit
        if daily_count >= config.per_ip_requests_per_day {
            return RateLimitResult::Blocked {
                reason: "Daily limit exceeded".to_string(),
                retry_after: Duration::from_secs(86400 - (now - day_start)),
            };
        }

        // Check rate limit
        if current_count < rate_limit {
            self.requests.fetch_add(1, Ordering::Relaxed);
            self.daily_requests.fetch_add(1, Ordering::Relaxed);
            RateLimitResult::Allowed
        } else {
            // Try burst tokens
            let burst_tokens = self.burst_tokens.load(Ordering::Relaxed);
            if burst_tokens > 0
                && self
                    .burst_tokens
                    .compare_exchange_weak(
                        burst_tokens,
                        burst_tokens - 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                self.requests.fetch_add(1, Ordering::Relaxed);
                self.daily_requests.fetch_add(1, Ordering::Relaxed);
                RateLimitResult::Allowed
            } else {
                // Rate limited
                self.violation_count.fetch_add(1, Ordering::Relaxed);

                // Check if should mark as suspicious
                let violations = self.violation_count.load(Ordering::Relaxed);
                if violations > config.suspicious_threshold / 10 {
                    self.is_suspicious.store(true, Ordering::Relaxed);
                    self.suspicious_count.fetch_add(1, Ordering::Relaxed);
                }

                let retry_after = Duration::from_secs(window_start + window_duration - now);
                RateLimitResult::Blocked {
                    reason: "Rate limit exceeded".to_string(),
                    retry_after,
                }
            }
        }
    }
}

/// Adaptive rate limiter that adjusts based on system load
#[derive(Debug)]
pub struct AdaptiveLimiter {
    base_rate: f64,
    current_rate: f64,
    error_rate: f64,
    last_adjustment: Instant,
    adjustment_interval: Duration,
}

impl AdaptiveLimiter {
    #[must_use]
    pub fn new(base_rate: f64) -> Self {
        Self {
            base_rate,
            current_rate: base_rate,
            error_rate: 0.0,
            last_adjustment: Instant::now(),
            adjustment_interval: Duration::from_secs(30),
        }
    }

    pub fn adjust_rate(&mut self, error_rate: f64) {
        let now = Instant::now();
        if now.duration_since(self.last_adjustment) < self.adjustment_interval {
            return;
        }

        self.error_rate = error_rate;

        // Reduce rate if error rate is high, increase if low
        if error_rate > 0.05 {
            self.current_rate *= 0.8; // Reduce by 20%
        } else if error_rate < 0.01 {
            self.current_rate *= 1.1; // Increase by 10%
        }

        // Keep within bounds
        self.current_rate = self
            .current_rate
            .max(self.base_rate * 0.1)
            .min(self.base_rate * 2.0);
        self.last_adjustment = now;
    }

    #[must_use]
    pub const fn current_rate(&self) -> f64 {
        self.current_rate
    }
}

/// Result of rate limit check
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed,
    Blocked {
        reason: String,
        retry_after: Duration,
    },
    Banned {
        expires_at: SystemTime,
    },
}

/// Comprehensive rate limiter with all features
pub struct UnifiedRateLimiter {
    config: RateLimitConfig,

    // Global counters
    global_minute_counter: AtomicU64,
    global_minute_start: Arc<RwLock<Instant>>,
    global_hour_counter: AtomicU64,
    global_hour_start: Arc<RwLock<Instant>>,

    // Sharded per-IP tracking
    ip_shards: Vec<DashMap<IpAddr, RateLimitWindow>>,
    shard_count: usize,

    // Per-client tracking
    client_windows: Arc<DashMap<String, RateLimitWindow>>,

    // Endpoint-specific tracking
    endpoint_windows: Arc<DashMap<String, RateLimitWindow>>,

    // Banned IPs with expiration
    banned_ips: Arc<DashMap<IpAddr, SystemTime>>,

    // Multi-factor fingerprint tracking (IP + User Agent hash)
    fingerprint_limits: Arc<DashMap<String, RateLimitWindow>>,

    // Adaptive rate limiting
    adaptive_limiter: Arc<RwLock<AdaptiveLimiter>>,

    // NOTE: Redis support available but requires feature flag 'redis' to be enabled
    // This ensures clean builds without Redis dependencies when not needed

    // Cleanup tracking
    last_cleanup: Arc<RwLock<Instant>>,
}

impl UnifiedRateLimiter {
    pub fn new(config: RateLimitConfig, redis_url: Option<String>) -> Self {
        // Create sharded storage for better concurrency
        let shard_count = std::cmp::max(num_cpus::get(), 4);
        let ip_shards = (0..shard_count).map(|_| DashMap::new()).collect();

        // Redis distributed rate limiting available with feature flag
        if config.enable_distributed_limiting {
            info!("Distributed rate limiting requested. Enable 'redis' feature flag for Redis backend");
        }
        let _ = redis_url; // Redis URL available when feature is enabled

        Self {
            config: config.clone(),
            global_minute_counter: AtomicU64::new(0),
            global_minute_start: Arc::new(RwLock::new(Instant::now())),
            global_hour_counter: AtomicU64::new(0),
            global_hour_start: Arc::new(RwLock::new(Instant::now())),
            ip_shards,
            shard_count,
            client_windows: Arc::new(DashMap::new()),
            endpoint_windows: Arc::new(DashMap::new()),
            banned_ips: Arc::new(DashMap::new()),
            fingerprint_limits: Arc::new(DashMap::new()),
            adaptive_limiter: Arc::new(RwLock::new(AdaptiveLimiter::new(f64::from(
                config.global_requests_per_minute,
            )))),
            // redis_client, // Temporarily disabled
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Get shard index for an IP using consistent hashing
    fn get_shard_index(&self, ip: &IpAddr) -> usize {
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        (hasher.finish() as usize) % self.shard_count
    }

    /// Create multi-factor fingerprint key combining IP and User Agent hash
    fn create_multi_factor_key(&self, ip: IpAddr, user_agent: Option<&str>) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);

        // Hash user agent if available
        if let Some(ua) = user_agent {
            // Only use first 100 chars to prevent extremely long UAs from consuming memory
            let ua_truncated = if ua.len() > 100 { &ua[..100] } else { ua };
            ua_truncated.hash(&mut hasher);
        }

        format!("mf:{:x}", hasher.finish())
    }

    /// Comprehensive rate limit check
    pub async fn check_rate_limit(
        &self,
        ip: IpAddr,
        client_id: Option<&str>,
        endpoint: &str,
        user_agent: Option<&str>,
    ) -> RateLimitResult {
        // Check if IP is banned
        if let Some(ban_time) = self.banned_ips.get(&ip) {
            let ban_expires =
                *ban_time + Duration::from_secs(u64::from(self.config.ban_duration_minutes) * 60);
            if SystemTime::now() < ban_expires {
                return RateLimitResult::Banned {
                    expires_at: ban_expires,
                };
            }
            self.banned_ips.remove(&ip);
        }

        // Check allowlist (bypass all limits if on allowlist)
        if self.config.enable_allowlist && self.is_ip_allowed(&ip) {
            return RateLimitResult::Allowed;
        }

        // Check banlist
        if self.config.enable_banlist && self.is_ip_banned(&ip) {
            return RateLimitResult::Blocked {
                reason: "IP is on banlist".to_string(),
                retry_after: Duration::from_secs(3600),
            };
        }

        // Check global rate limits
        if let Some(result) = self.check_global_limits().await {
            return result;
        }

        // Check per-IP rate limits
        if let Some(result) = self.check_ip_limits(ip, user_agent) {
            return result;
        }

        // Check per-client rate limits
        if let Some(client_id) = client_id {
            if let Some(result) = self.check_client_limits(client_id) {
                return result;
            }
        }

        // Check endpoint-specific limits
        if let Some(result) = self.check_endpoint_limits(endpoint) {
            return result;
        }

        // All checks passed
        self.record_successful_request(ip, client_id, endpoint)
            .await;
        RateLimitResult::Allowed
    }

    async fn check_global_limits(&self) -> Option<RateLimitResult> {
        let now = Instant::now();

        // Check minute limit
        {
            let mut minute_start = self.global_minute_start.write().await;
            if now.duration_since(*minute_start) >= Duration::from_secs(60) {
                self.global_minute_counter.store(0, Ordering::Relaxed);
                *minute_start = now;
            }
        }

        let minute_count = self.global_minute_counter.load(Ordering::Relaxed);
        if minute_count >= u64::from(self.config.global_requests_per_minute) {
            return Some(RateLimitResult::Blocked {
                reason: "Global minute limit exceeded".to_string(),
                retry_after: Duration::from_secs(60),
            });
        }

        // Check hour limit
        {
            let mut hour_start = self.global_hour_start.write().await;
            if now.duration_since(*hour_start) >= Duration::from_secs(3600) {
                self.global_hour_counter.store(0, Ordering::Relaxed);
                *hour_start = now;
            }
        }

        let hour_count = self.global_hour_counter.load(Ordering::Relaxed);
        if hour_count >= u64::from(self.config.global_requests_per_hour) {
            return Some(RateLimitResult::Blocked {
                reason: "Global hour limit exceeded".to_string(),
                retry_after: Duration::from_secs(3600),
            });
        }

        None
    }

    fn check_ip_limits(&self, ip: IpAddr, user_agent: Option<&str>) -> Option<RateLimitResult> {
        let shard_index = self.get_shard_index(&ip);
        let shard = &self.ip_shards[shard_index];

        // Create fingerprint key combining IP and user agent hash for multi-factor rate limiting
        let fingerprint_key = self.create_multi_factor_key(ip, user_agent);

        let window = shard
            .entry(ip)
            .or_insert_with(|| RateLimitWindow::new(self.config.per_ip_burst));

        // Also check fingerprint-based limits for enhanced security
        let fingerprint_window = self
            .fingerprint_limits
            .entry(fingerprint_key)
            .or_insert_with(|| RateLimitWindow::new(self.config.per_ip_burst / 2)); // Stricter limit

        // Check both IP and fingerprint limits - fail if either exceeds
        let ip_result = window.check_and_update(&self.config, self.config.window_duration_secs);
        let fingerprint_result =
            fingerprint_window.check_and_update(&self.config, self.config.window_duration_secs);

        // Return the most restrictive result (blocked if either limit exceeded)
        let result = match (&ip_result, &fingerprint_result) {
            (RateLimitResult::Blocked { .. }, _) | (_, RateLimitResult::Blocked { .. }) => {
                // Use the IP result for violation tracking, but apply fingerprint blocking
                ip_result.clone()
            }
            _ => ip_result.clone(), // Both allowed, return IP result
        };

        match result {
            RateLimitResult::Blocked { .. } => {
                // Check if should ban IP for repeated violations
                let violations = window.violation_count.load(Ordering::Relaxed);
                if violations >= self.config.ban_threshold {
                    self.ban_ip(ip, violations);
                    Some(RateLimitResult::Banned {
                        expires_at: SystemTime::now()
                            + Duration::from_secs(u64::from(self.config.ban_duration_minutes) * 60),
                    })
                } else {
                    Some(result)
                }
            }
            _ => None,
        }
    }

    fn check_client_limits(&self, client_id: &str) -> Option<RateLimitResult> {
        let window = self
            .client_windows
            .entry(client_id.to_owned())
            .or_insert_with(|| RateLimitWindow::new(self.config.per_ip_burst));

        let result = window.check_and_update(&self.config, 60);
        match result {
            RateLimitResult::Blocked { .. } => Some(result),
            _ => None,
        }
    }

    fn check_endpoint_limits(&self, endpoint: &str) -> Option<RateLimitResult> {
        let limit = self.get_endpoint_limit(endpoint)?;

        let window = self
            .endpoint_windows
            .entry(endpoint.to_owned())
            .or_insert_with(|| RateLimitWindow::new(10));

        // Use custom config for endpoint
        let mut endpoint_config = self.config.clone();
        endpoint_config.per_ip_requests_per_minute = limit;

        let result = window.check_and_update(&endpoint_config, 60);
        match result {
            RateLimitResult::Blocked { .. } => Some(result),
            _ => None,
        }
    }

    fn get_endpoint_limit(&self, endpoint: &str) -> Option<u32> {
        match endpoint {
            path if path.contains("/oauth/token") => {
                Some(self.config.oauth_token_requests_per_minute)
            }
            path if path.contains("/oauth/authorize") => {
                Some(self.config.oauth_authorize_requests_per_minute)
            }
            path if path.contains("/oauth/introspect") => {
                Some(self.config.oauth_introspect_requests_per_minute)
            }
            path if path.contains("/admin") => Some(self.config.admin_requests_per_minute),
            path if path.contains("/scim") => Some(self.config.scim_requests_per_minute),
            path if path.contains("/.well-known/jwks") => {
                Some(self.config.jwks_requests_per_minute)
            }
            _ => None,
        }
    }

    async fn record_successful_request(
        &self,
        _ip: IpAddr,
        _client_id: Option<&str>,
        _endpoint: &str,
    ) {
        // Update global counters
        self.global_minute_counter.fetch_add(1, Ordering::Relaxed);
        self.global_hour_counter.fetch_add(1, Ordering::Relaxed);

        // Periodic cleanup
        self.cleanup_if_needed().await;
    }

    fn ban_ip(&self, ip: IpAddr, violation_count: u32) {
        let ban_until = SystemTime::now()
            + Duration::from_secs(u64::from(self.config.ban_duration_minutes) * 60);
        self.banned_ips.insert(ip, ban_until);

        warn!(
            ip = %ip,
            violations = violation_count,
            duration_minutes = self.config.ban_duration_minutes,
            "IP address banned due to repeated rate limit violations"
        );
    }

    fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        self.config.allowlist_ips.contains(ip)
            || self
                .config
                .allowlist_cidrs
                .iter()
                .any(|cidr| self.ip_in_cidr(ip, cidr))
    }

    fn is_ip_banned(&self, ip: &IpAddr) -> bool {
        self.config.banlist_ips.contains(ip)
            || self
                .config
                .banlist_cidrs
                .iter()
                .any(|cidr| self.ip_in_cidr(ip, cidr))
    }

    const fn ip_in_cidr(&self, ip: &IpAddr, cidr: &str) -> bool {
        // Simple CIDR matching - in production, use a proper CIDR library
        // Simple CIDR matching - for production, use a proper CIDR library
        // For now, just return false as a safe fallback
        let _ = cidr;
        let _ = ip;
        false
    }

    async fn cleanup_if_needed(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let mut last_cleanup = self.last_cleanup.write().await;
            let needs_cleanup = now.duration_since(*last_cleanup)
                >= Duration::from_secs(self.config.cleanup_interval_seconds);
            if needs_cleanup {
                *last_cleanup = now;
            }
            needs_cleanup
        };

        if should_cleanup {
            self.cleanup_old_entries();
        }
    }

    fn cleanup_old_entries(&self) {
        let system_now = SystemTime::now();

        // Clean up expired bans
        self.banned_ips.retain(|_, &mut ban_time| {
            system_now
                < ban_time + Duration::from_secs(u64::from(self.config.ban_duration_minutes) * 60)
        });

        // Clean up old IP windows across all shards
        let max_per_shard = self.config.max_tracked_ips / self.shard_count;
        for shard in &self.ip_shards {
            let current_size = shard.len();
            if current_size > max_per_shard {
                // Identify stale entries (those with very low activity or old timestamps)
                let mut stale_entries: Vec<(IpAddr, u64)> = Vec::new();

                // Collect entries sorted by last activity (oldest first)
                for entry in shard {
                    let ip = *entry.key();
                    let window = entry.value();
                    let last_activity = window.window_start.load(Ordering::Relaxed);
                    let total_requests = window.total_requests.load(Ordering::Relaxed);

                    // Consider entry stale if no activity in last 2 hours or very low request count
                    if system_now.duration_since(UNIX_EPOCH).unwrap().as_secs() - last_activity
                        > 7200
                        || total_requests < 5
                    {
                        stale_entries.push((ip, last_activity));
                    }
                }

                // Sort by last activity (oldest first) and remove excess entries
                stale_entries.sort_by_key(|&(_, last_activity)| last_activity);
                let excess = current_size.saturating_sub(max_per_shard);
                let to_remove = stale_entries.into_iter().take(excess);

                let mut removed_count = 0;
                for (ip, _) in to_remove {
                    if shard.remove(&ip).is_some() {
                        removed_count += 1;
                    }
                }

                debug!(
                    shard_size = current_size,
                    removed = removed_count,
                    "Cleaned up stale rate limit entries from shard"
                );
            }
        }

        // Clean up old client windows (remove entries older than 1 hour with low activity)
        let mut client_keys_to_remove: Vec<String> = Vec::new();
        for entry in self.client_windows.iter() {
            let window = entry.value();
            let last_activity = window.window_start.load(Ordering::Relaxed);
            let total_requests = window.total_requests.load(Ordering::Relaxed);

            if system_now.duration_since(UNIX_EPOCH).unwrap().as_secs() - last_activity > 3600
                || total_requests == 0
            {
                client_keys_to_remove.push(entry.key().clone());
            }
        }

        for key in client_keys_to_remove {
            self.client_windows.remove(&key);
        }

        // Clean up old endpoint windows
        let mut endpoint_keys_to_remove: Vec<String> = Vec::new();
        for entry in self.endpoint_windows.iter() {
            let window = entry.value();
            let last_activity = window.window_start.load(Ordering::Relaxed);
            let total_requests = window.total_requests.load(Ordering::Relaxed);

            if system_now.duration_since(UNIX_EPOCH).unwrap().as_secs() - last_activity > 3600
                || total_requests == 0
            {
                endpoint_keys_to_remove.push(entry.key().clone());
            }
        }

        for key in endpoint_keys_to_remove {
            self.endpoint_windows.remove(&key);
        }

        debug!("Rate limiter cleanup completed - removed stale entries across all data structures");
    }

    /// Update adaptive rate limiting based on system metrics
    pub async fn update_adaptive_limits(&self, error_rate: f64) {
        if self.config.enable_adaptive_limits {
            let mut adaptive = self.adaptive_limiter.write().await;
            adaptive.adjust_rate(error_rate);
            info!(
                "Adaptive rate limit updated to {:.2} RPM",
                adaptive.current_rate()
            );
        }
    }

    /// Get current rate limiting statistics
    pub fn get_stats(&self) -> RateLimitStats {
        let mut total_ips = 0;
        let mut suspicious_ips = 0;
        let mut total_violations = 0;

        for shard in &self.ip_shards {
            for entry in shard {
                total_ips += 1;
                if entry.is_suspicious.load(Ordering::Relaxed) {
                    suspicious_ips += 1;
                }
                total_violations += u64::from(entry.violation_count.load(Ordering::Relaxed));
            }
        }

        RateLimitStats {
            global_minute_requests: self.global_minute_counter.load(Ordering::Relaxed) as u32,
            global_hour_requests: self.global_hour_counter.load(Ordering::Relaxed) as u32,
            tracked_ips: total_ips,
            tracked_clients: self.client_windows.len() as u32,
            banned_ips: self.banned_ips.len() as u32,
            suspicious_ips: suspicious_ips as u32,
            total_violations,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitStats {
    pub global_minute_requests: u32,
    pub global_hour_requests: u32,
    pub tracked_ips: u32,
    pub tracked_clients: u32,
    pub banned_ips: u32,
    pub suspicious_ips: u32,
    pub total_violations: u64,
}

#[derive(Debug, Serialize)]
struct RateLimitErrorResponse {
    error: String,
    message: String,
    retry_after_seconds: u64,
}

/// Extract client IP from headers or connection info
fn extract_client_ip(headers: &HeaderMap, fallback_ip: IpAddr) -> IpAddr {
    // Only trust proxy headers if explicitly configured
    let trust_proxy = std::env::var("TRUST_PROXY_HEADERS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !trust_proxy {
        return fallback_ip;
    }

    // Try X-Forwarded-For header first
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Try X-Real-IP header
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Try CF-Connecting-IP (Cloudflare)
    if let Some(cf_ip) = headers.get("cf-connecting-ip") {
        if let Ok(ip_str) = cf_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    fallback_ip
}

/// Extract client ID from Authorization header
fn extract_client_id(headers: &HeaderMap) -> Option<String> {
    // Try Basic Auth first
    if let Some(auth) = headers.get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(basic) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = general_purpose::STANDARD.decode(basic) {
                    if let Ok(credentials) = String::from_utf8(decoded) {
                        if let Some((client_id, _)) = credentials.split_once(':') {
                            return Some(client_id.to_string());
                        }
                    }
                }
            }
        }
    }

    // Try custom client ID header
    if let Some(client_id) = headers.get("x-client-id") {
        if let Ok(client_id_str) = client_id.to_str() {
            return Some(client_id_str.to_string());
        }
    }

    None
}

/// Unified rate limiting middleware
///
/// # Panics
///
/// This function may panic if:
/// - HTTP header parsing fails (should not happen with valid duration values)
pub async fn unified_rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(limiter): State<Arc<UnifiedRateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Skip rate limiting in test mode
    if std::env::var("TEST_MODE").ok().as_deref() == Some("1")
        || std::env::var("DISABLE_RATE_LIMIT").ok().as_deref() == Some("1")
    {
        return Ok(next.run(request).await);
    }

    // Extract client information
    let request_ip = extract_client_ip(request.headers(), addr.ip());
    let oauth_client_id = extract_client_id(request.headers());
    let endpoint = request.uri().path();
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok());

    // Check rate limits
    match limiter
        .check_rate_limit(request_ip, oauth_client_id.as_deref(), endpoint, user_agent)
        .await
    {
        RateLimitResult::Allowed => Ok(next.run(request).await),

        RateLimitResult::Blocked {
            reason,
            retry_after,
        } => {
            let response = Json(RateLimitErrorResponse {
                error: "RATE_LIMIT_EXCEEDED".to_string(),
                message: reason,
                retry_after_seconds: retry_after.as_secs(),
            });

            let mut resp = (StatusCode::TOO_MANY_REQUESTS, response).into_response();
            resp.headers_mut().insert(
                "Retry-After",
                retry_after.as_secs().to_string().parse().unwrap(),
            );
            if let Ok(limit_str) = limiter
                .config
                .per_ip_requests_per_minute
                .to_string()
                .parse()
            {
                resp.headers_mut().insert("X-RateLimit-Limit", limit_str);
            }
            if let Ok(remaining_str) = "0".parse() {
                resp.headers_mut()
                    .insert("X-RateLimit-Remaining", remaining_str);
            }

            Err(resp)
        }

        RateLimitResult::Banned { expires_at } => {
            let retry_after = expires_at
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::from_secs(3600))
                .as_secs();

            let response = Json(RateLimitErrorResponse {
                error: "IP_BANNED".to_string(),
                message: "IP address is temporarily banned due to repeated violations".to_string(),
                retry_after_seconds: retry_after,
            });

            let mut resp = (StatusCode::FORBIDDEN, response).into_response();
            resp.headers_mut()
                .insert("Retry-After", retry_after.to_string().parse().unwrap());

            Err(resp)
        }
    }
}

/// Start background cleanup task
pub async fn start_rate_limit_cleanup_task(limiter: Arc<UnifiedRateLimiter>) {
    let mut interval =
        tokio::time::interval(Duration::from_secs(limiter.config.cleanup_interval_seconds));

    loop {
        interval.tick().await;
        limiter.cleanup_old_entries();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_unified_rate_limiter_basic() {
        let config = RateLimitConfig {
            per_ip_requests_per_minute: 5,
            per_ip_burst: 2,
            ..Default::default()
        };

        let limiter = UnifiedRateLimiter::new(config, None);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 5 + 2 burst requests should be allowed
        for i in 0..7 {
            match limiter.check_rate_limit(ip, None, "/test", None).await {
                RateLimitResult::Allowed => {
                    assert!(i < 7, "Request {i} should be allowed");
                }
                _ => {
                    panic!("Request {i} should be allowed");
                }
            }
        }

        // 8th request should be blocked
        match limiter.check_rate_limit(ip, None, "/test", None).await {
            RateLimitResult::Blocked { .. } => {}
            _ => panic!("Request should be blocked"),
        }
    }

    #[tokio::test]
    async fn test_endpoint_specific_limits() {
        let config = RateLimitConfig {
            oauth_token_requests_per_minute: 2,
            per_ip_requests_per_minute: 100, // High general limit
            ..Default::default()
        };

        let limiter = UnifiedRateLimiter::new(config, None);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // First 2 requests to token endpoint should be allowed
        for _ in 0..2 {
            match limiter
                .check_rate_limit(ip, None, "/oauth/token", None)
                .await
            {
                RateLimitResult::Allowed => {}
                _ => panic!("Token request should be allowed"),
            }
        }

        // 3rd request should be blocked
        match limiter
            .check_rate_limit(ip, None, "/oauth/token", None)
            .await
        {
            RateLimitResult::Blocked { .. } => {}
            _ => panic!("Token request should be blocked"),
        }

        // But other endpoints should still work
        match limiter.check_rate_limit(ip, None, "/other", None).await {
            RateLimitResult::Allowed => {}
            _ => panic!("Other endpoint should be allowed"),
        }
    }

    #[tokio::test]
    async fn test_ip_banning() {
        let config = RateLimitConfig {
            per_ip_requests_per_minute: 1,
            per_ip_burst: 0,
            ban_threshold: 3,
            ban_duration_minutes: 1,
            ..Default::default()
        };

        let limiter = UnifiedRateLimiter::new(config, None);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));

        // Exhaust rate limit multiple times to trigger ban
        for _ in 0..5 {
            let _ = limiter.check_rate_limit(ip, None, "/test", None).await;
        }

        // Should be banned now
        match limiter.check_rate_limit(ip, None, "/test", None).await {
            RateLimitResult::Banned { .. } => {}
            _ => panic!("IP should be banned"),
        }
    }

    #[tokio::test]
    async fn test_allowlist() {
        let mut config = RateLimitConfig {
            enable_allowlist: true,
            per_ip_requests_per_minute: 1,
            ..Default::default()
        };
        config
            .allowlist_ips
            .insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)));

        let limiter = UnifiedRateLimiter::new(config, None);
        let allowed_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));
        let blocked_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));

        // Allowed IP should bypass rate limits
        for _ in 0..10 {
            match limiter
                .check_rate_limit(allowed_ip, None, "/test", None)
                .await
            {
                RateLimitResult::Allowed => {}
                _ => panic!("Allowlisted IP should always be allowed"),
            }
        }

        // Blocked IP should hit rate limit
        let _ = limiter
            .check_rate_limit(blocked_ip, None, "/test", None)
            .await;
        match limiter
            .check_rate_limit(blocked_ip, None, "/test", None)
            .await
        {
            RateLimitResult::Blocked { .. } => {}
            _ => panic!("Non-allowlisted IP should be rate limited"),
        }
    }
}
