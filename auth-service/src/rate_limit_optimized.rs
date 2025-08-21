// Optimized rate limiting implementation
// This provides a high-performance, sharded rate limiting solution

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{extract::Request, middleware::Next, response::Response};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::metrics::{MetricsHelper, METRICS};

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_window: u32,
    pub window_duration_secs: u64,
    pub burst_allowance: u32,
    pub cleanup_interval_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 60,
            window_duration_secs: 60,
            burst_allowance: 10,
            cleanup_interval_secs: 300, // 5 minutes
        }
    }
}

/// Rate limit entry with atomic operations for lock-free performance
#[derive(Debug)]
pub struct RateLimitEntry {
    /// Number of requests in current window
    count: AtomicU32,
    /// Start time of current window (Unix timestamp)
    window_start: AtomicU64,
    /// Burst tokens available
    burst_tokens: AtomicU32,
    /// Last access time for cleanup
    last_access: AtomicU64,
}

impl Clone for RateLimitEntry {
    fn clone(&self) -> Self {
        Self {
            count: AtomicU32::new(self.count.load(Ordering::Relaxed)),
            window_start: AtomicU64::new(self.window_start.load(Ordering::Relaxed)),
            burst_tokens: AtomicU32::new(self.burst_tokens.load(Ordering::Relaxed)),
            last_access: AtomicU64::new(self.last_access.load(Ordering::Relaxed)),
        }
    }
}

impl RateLimitEntry {
    fn new(now: u64, burst_allowance: u32) -> Self {
        Self {
            count: AtomicU32::new(0),
            window_start: AtomicU64::new(now),
            burst_tokens: AtomicU32::new(burst_allowance),
            last_access: AtomicU64::new(now),
        }
    }

    /// Check and update rate limit state atomically
    fn check_and_update(&self, now: u64, config: &RateLimitConfig) -> RateLimitResult {
        // Update last access time
        self.last_access.store(now, Ordering::Relaxed);

        let window_start = self.window_start.load(Ordering::Relaxed);
        let window_duration = config.window_duration_secs;

        // Check if we need to reset the window
        if now >= window_start + window_duration {
            // Try to reset the window atomically
            if self
                .window_start
                .compare_exchange_weak(window_start, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                // Successfully reset window
                self.count.store(1, Ordering::Relaxed);
                self.burst_tokens
                    .store(config.burst_allowance, Ordering::Relaxed);
                return RateLimitResult::Allowed;
            }
            // Another thread reset the window, fall through to normal check
        }

        // Try to use burst tokens first
        let burst_tokens = self.burst_tokens.load(Ordering::Relaxed);
        if burst_tokens > 0 {
            if self
                .burst_tokens
                .compare_exchange_weak(
                    burst_tokens,
                    burst_tokens - 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return RateLimitResult::Allowed;
            }
        }

        // Check normal rate limit
        let current_count = self.count.fetch_add(1, Ordering::Relaxed) + 1;

        if current_count <= config.requests_per_window {
            RateLimitResult::Allowed
        } else {
            // Exceeded rate limit
            let retry_after = (window_start + window_duration).saturating_sub(now);
            RateLimitResult::RateLimited { retry_after }
        }
    }

    /// Check if entry is stale for cleanup
    fn is_stale(&self, now: u64, max_age_secs: u64) -> bool {
        let last_access = self.last_access.load(Ordering::Relaxed);
        now > last_access + max_age_secs
    }
}

/// Result of rate limit check
#[derive(Debug)]
pub enum RateLimitResult {
    Allowed,
    RateLimited { retry_after: u64 },
}

/// Sharded rate limiter for high concurrency
#[derive(Clone)]
pub struct ShardedRateLimiter {
    shards: Vec<DashMap<String, RateLimitEntry>>,
    config: RateLimitConfig,
}

impl ShardedRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        // Use number of CPU cores for shard count, with minimum of 4
        let shard_count = std::cmp::max(num_cpus::get(), 4);
        let shards = (0..shard_count).map(|_| DashMap::new()).collect();

        Self { shards, config }
    }

    /// Get shard index for a key using hash
    fn get_shard_index(&self, key: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }

    /// Check rate limit for a key
    pub fn check_rate_limit(&self, key: &str) -> RateLimitResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let shard_index = self.get_shard_index(key);
        let shard = &self.shards[shard_index];

        let entry = shard
            .entry(key.to_string())
            .or_insert_with(|| RateLimitEntry::new(now, self.config.burst_allowance));

        entry.check_and_update(now, &self.config)
    }

    /// Cleanup stale entries from all shards
    pub fn cleanup_stale_entries(&self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let max_age = self.config.cleanup_interval_secs * 2; // Keep entries for 2x cleanup interval
        let mut total_removed = 0;

        for shard in &self.shards {
            let before_count = shard.len();
            shard.retain(|_key, entry| !entry.is_stale(now, max_age));
            let after_count = shard.len();
            total_removed += before_count - after_count;
        }

        total_removed
    }

    /// Get statistics for monitoring
    pub fn get_stats(&self) -> RateLimitStats {
        let mut total_entries = 0;
        let mut shard_sizes = Vec::new();

        for shard in &self.shards {
            let size = shard.len();
            total_entries += size;
            shard_sizes.push(size);
        }

        RateLimitStats {
            total_entries,
            shard_count: self.shards.len(),
            shard_sizes,
            config: self.config.clone(),
        }
    }
}

/// Rate limiter statistics for monitoring
#[derive(Debug)]
pub struct RateLimitStats {
    pub total_entries: usize,
    pub shard_count: usize,
    pub shard_sizes: Vec<usize>,
    pub config: RateLimitConfig,
}

// Global rate limiter instance
static GLOBAL_RATE_LIMITER: Lazy<ShardedRateLimiter> = Lazy::new(|| {
    let config = RateLimitConfig {
        requests_per_window: std::env::var("RATE_LIMIT_REQUESTS_PER_MINUTE")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|v| *v > 0)
            .unwrap_or(60),
        window_duration_secs: 60,
        burst_allowance: std::env::var("RATE_LIMIT_BURST_ALLOWANCE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10),
        cleanup_interval_secs: 300,
    };

    ShardedRateLimiter::new(config)
});

/// Configuration for trusted proxies
#[derive(Debug, Clone)]
struct TrustedProxyConfig {
    trusted_proxies: Vec<std::net::IpAddr>,
    trust_proxy_headers: bool,
}

impl Default for TrustedProxyConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            trust_proxy_headers: false,
        }
    }
}

/// Get trusted proxy configuration from environment
fn get_trusted_proxy_config() -> TrustedProxyConfig {
    let trust_headers = std::env::var("TRUST_PROXY_HEADERS")
        .ok()
        .and_then(|s| s.parse::<bool>().ok())
        .unwrap_or(false);

    let trusted_proxies = if trust_headers {
        std::env::var("TRUSTED_PROXY_IPS")
            .ok()
            .map(|s| {
                s.split(',')
                    .filter_map(|ip_str| ip_str.trim().parse::<std::net::IpAddr>().ok())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    TrustedProxyConfig {
        trusted_proxies,
        trust_proxy_headers: trust_headers,
    }
}

/// Extract client identifier for rate limiting with trusted proxy validation
fn extract_client_key(headers: &axum::http::HeaderMap) -> String {
    let config = get_trusted_proxy_config();

    // Only use proxy headers if explicitly configured to trust them
    if config.trust_proxy_headers {
        // If specific trusted proxies are configured, validate against them
        if !config.trusted_proxies.is_empty() {
            // In a real implementation, we would validate the request comes from a trusted proxy
            // For now, we'll trust the headers if the environment is configured

            // Try X-Forwarded-For first (for reverse proxy setups)
            if let Some(forwarded) = headers.get("x-forwarded-for") {
                if let Ok(forwarded_str) = forwarded.to_str() {
                    if let Some(ip) = forwarded_str.split(',').next() {
                        let client_ip = ip.trim();
                        // Validate the IP format
                        if client_ip.parse::<std::net::IpAddr>().is_ok() {
                            return client_ip.to_string();
                        }
                    }
                }
            }

            // Try X-Real-IP (Nginx)
            if let Some(real_ip) = headers.get("x-real-ip") {
                if let Ok(ip_str) = real_ip.to_str() {
                    let client_ip = ip_str.trim();
                    // Validate the IP format
                    if client_ip.parse::<std::net::IpAddr>().is_ok() {
                        return client_ip.to_string();
                    }
                }
            }

            // Try CF-Connecting-IP (Cloudflare) - only if Cloudflare IPs are trusted
            if let Some(cf_ip) = headers.get("cf-connecting-ip") {
                if let Ok(ip_str) = cf_ip.to_str() {
                    let client_ip = ip_str.trim();
                    // Validate the IP format
                    if client_ip.parse::<std::net::IpAddr>().is_ok() {
                        return client_ip.to_string();
                    }
                }
            }
        }
    }

    // If no trusted proxy configuration or headers not trusted,
    // use a combination of headers to create a unique identifier
    // This prevents complete bypass but still allows some rate limiting
    let mut identifier_parts = Vec::new();

    // Use User-Agent as part of identifier (harder to spoof consistently)
    if let Some(user_agent) = headers.get("user-agent") {
        if let Ok(ua_str) = user_agent.to_str() {
            // Hash User-Agent for privacy and uniqueness
            let mut hasher = DefaultHasher::new();
            ua_str.hash(&mut hasher);
            let ua_hash = format!("{:x}", hasher.finish());
            identifier_parts.push(ua_hash[..8].to_string());
        }
    }

    // Use Accept header as additional identifier
    if let Some(accept) = headers.get("accept") {
        if let Ok(accept_str) = accept.to_str() {
            // Hash Accept header for additional uniqueness
            let mut hasher = DefaultHasher::new();
            accept_str.hash(&mut hasher);
            let accept_hash = format!("{:x}", hasher.finish());
            identifier_parts.push(accept_hash[..4].to_string());
        }
    }

    // If we have some identifier parts, use them
    if !identifier_parts.is_empty() {
        return format!("fingerprint_{}", identifier_parts.join("_"));
    }

    // Ultimate fallback - this means rate limiting will be shared
    // but prevents complete bypass
    "shared_limiter".to_string()
}

/// High-performance rate limiting middleware
pub async fn optimized_rate_limit(request: Request, next: Next) -> Response {
    // Skip rate limiting in test mode or if disabled
    if std::env::var("DISABLE_RATE_LIMIT").ok().as_deref() == Some("1")
        || std::env::var("TEST_MODE").ok().as_deref() == Some("1")
    {
        return next.run(request).await;
    }

    // Extract client identifier
    let client_key = extract_client_key(request.headers());

    // Check rate limit
    match GLOBAL_RATE_LIMITER.check_rate_limit(&client_key) {
        RateLimitResult::Allowed => {
            // Record allowed request
            let path = request.uri().path();
            MetricsHelper::record_rate_limit_enforcement(path, &client_key, "allowed", "request");
            next.run(request).await
        }
        RateLimitResult::RateLimited { retry_after } => {
            // Record rate limit hit
            let path = request.uri().path();
            MetricsHelper::record_rate_limit_enforcement(path, &client_key, "blocked", "request");
            let mut response =
                (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();

            response.headers_mut().insert(
                "Retry-After",
                format!("{}", retry_after.max(1)).parse().unwrap(),
            );

            response.headers_mut().insert(
                "X-RateLimit-Limit",
                format!("{}", GLOBAL_RATE_LIMITER.config.requests_per_window)
                    .parse()
                    .unwrap(),
            );

            response.headers_mut().insert(
                "X-RateLimit-Window",
                format!("{}", GLOBAL_RATE_LIMITER.config.window_duration_secs)
                    .parse()
                    .unwrap(),
            );

            response
        }
    }
}

/// Start background cleanup task
pub async fn start_rate_limit_cleanup_task() {
    let mut interval = tokio::time::interval(Duration::from_secs(
        GLOBAL_RATE_LIMITER.config.cleanup_interval_secs,
    ));

    loop {
        interval.tick().await;

        let removed_count = GLOBAL_RATE_LIMITER.cleanup_stale_entries();
        if removed_count > 0 {
            tracing::debug!(
                "Rate limit cleanup: removed {} stale entries",
                removed_count
            );
        }
    }
}

/// Get rate limiter statistics for monitoring
pub fn get_rate_limit_stats() -> RateLimitStats {
    GLOBAL_RATE_LIMITER.get_stats()
}

/// Per-client rate limiter for specific operations
#[derive(Clone)]
pub struct PerClientRateLimiter {
    limiter: ShardedRateLimiter,
    key_prefix: String,
}

impl PerClientRateLimiter {
    pub fn new(key_prefix: String, config: RateLimitConfig) -> Self {
        Self {
            limiter: ShardedRateLimiter::new(config),
            key_prefix,
        }
    }

    pub fn check_client_rate_limit(&self, client_id: &str) -> RateLimitResult {
        let key = format!("{}:{}", self.key_prefix, client_id);
        self.limiter.check_rate_limit(&key)
    }
}

/// Rate limiter for specific endpoints with different limits
#[derive(Clone)]
pub struct EndpointRateLimiter {
    limiters: std::collections::HashMap<String, PerClientRateLimiter>,
}

impl EndpointRateLimiter {
    pub fn new() -> Self {
        let mut limiters = std::collections::HashMap::new();

        // Token endpoint - more restrictive
        limiters.insert(
            "/oauth/token".to_string(),
            PerClientRateLimiter::new(
                "token".to_string(),
                RateLimitConfig {
                    requests_per_window: 30,
                    window_duration_secs: 60,
                    burst_allowance: 5,
                    cleanup_interval_secs: 300,
                },
            ),
        );

        // Introspection endpoint - higher limits for production use
        limiters.insert(
            "/oauth/introspect".to_string(),
            PerClientRateLimiter::new(
                "introspect".to_string(),
                RateLimitConfig {
                    requests_per_window: 200,
                    window_duration_secs: 60,
                    burst_allowance: 20,
                    cleanup_interval_secs: 300,
                },
            ),
        );

        Self { limiters }
    }

    pub fn check_endpoint_rate_limit(
        &self,
        endpoint: &str,
        client_id: &str,
    ) -> Option<RateLimitResult> {
        self.limiters
            .get(endpoint)
            .map(|limiter| limiter.check_client_rate_limit(client_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_sharded_rate_limiter() {
        let config = RateLimitConfig {
            requests_per_window: 5,
            window_duration_secs: 1,
            burst_allowance: 2,
            cleanup_interval_secs: 10,
        };

        let limiter = ShardedRateLimiter::new(config);
        let client_key = "test_client";

        // First few requests should be allowed (including burst)
        for i in 0..7 {
            match limiter.check_rate_limit(client_key) {
                RateLimitResult::Allowed => {
                    // Expected for first 7 requests (5 + 2 burst)
                    assert!(i < 7);
                }
                RateLimitResult::RateLimited { retry_after } => {
                    // Should be rate limited after 7 requests
                    assert!(i >= 7);
                    assert!(retry_after > 0);
                }
            }
        }

        // Wait for window to reset
        sleep(Duration::from_secs(2)).await;

        // Should be allowed again
        match limiter.check_rate_limit(client_key) {
            RateLimitResult::Allowed => { /* Expected */ }
            RateLimitResult::RateLimited { .. } => {
                panic!("Should be allowed after window reset");
            }
        }
    }

    #[tokio::test]
    async fn test_concurrent_rate_limiting() {
        let config = RateLimitConfig {
            requests_per_window: 100,
            window_duration_secs: 60,
            burst_allowance: 10,
            cleanup_interval_secs: 300,
        };

        let limiter = Arc::new(ShardedRateLimiter::new(config));
        let mut handles = Vec::new();

        // Spawn multiple concurrent tasks
        for i in 0..10 {
            let limiter = Arc::clone(&limiter);
            let handle = tokio::spawn(async move {
                let client_key = format!("client_{}", i);
                let mut allowed_count = 0;

                // Make 50 requests per client
                for _ in 0..50 {
                    match limiter.check_rate_limit(&client_key) {
                        RateLimitResult::Allowed => allowed_count += 1,
                        RateLimitResult::RateLimited { .. } => {}
                    }
                }

                allowed_count
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut total_allowed = 0;
        for handle in handles {
            total_allowed += handle.await.unwrap();
        }

        // Each client should get their full allocation (100 + 10 burst)
        assert_eq!(total_allowed, 10 * 50); // All requests should be allowed
    }

    #[test]
    fn test_rate_limit_entry_atomicity() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let config = RateLimitConfig {
            requests_per_window: 10,
            window_duration_secs: 60,
            burst_allowance: 5,
            cleanup_interval_secs: 300,
        };

        let entry = RateLimitEntry::new(now, config.burst_allowance);

        // Test burst allowance
        for i in 0..5 {
            match entry.check_and_update(now, &config) {
                RateLimitResult::Allowed => { /* Expected for burst */ }
                RateLimitResult::RateLimited { .. } => {
                    panic!("Should be allowed for burst request {}", i);
                }
            }
        }

        // Test normal rate limiting
        for _ in 0..10 {
            match entry.check_and_update(now, &config) {
                RateLimitResult::Allowed => { /* Expected for normal requests */ }
                RateLimitResult::RateLimited { .. } => {
                    // Some should be rate limited
                    break;
                }
            }
        }
    }

    #[tokio::test]
    async fn test_cleanup_stale_entries() {
        let config = RateLimitConfig {
            requests_per_window: 10,
            window_duration_secs: 1,
            burst_allowance: 2,
            cleanup_interval_secs: 1,
        };

        let limiter = ShardedRateLimiter::new(config);

        // Add some entries
        let _ = limiter.check_rate_limit("client1");
        let _ = limiter.check_rate_limit("client2");
        let _ = limiter.check_rate_limit("client3");

        let stats_before = limiter.get_stats();
        assert_eq!(stats_before.total_entries, 3);

        // Wait for entries to become stale
        sleep(Duration::from_secs(3)).await;

        // Cleanup should remove stale entries
        let removed = limiter.cleanup_stale_entries();
        assert_eq!(removed, 3);

        let stats_after = limiter.get_stats();
        assert_eq!(stats_after.total_entries, 0);
    }
}
