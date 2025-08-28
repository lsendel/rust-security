use axum::{
    extract::{Request, ConnectInfo},
    http::{StatusCode, HeaderMap},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use dashmap::DashMap;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use std::time::{Duration, Instant, SystemTime};
#[cfg(feature = "monitoring")]
use prometheus::{IntCounter, IntGauge, Histogram, register_int_counter, register_int_gauge, register_histogram};

/// Advanced rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    // Global rate limiting
    pub global_requests_per_minute: u32,
    pub global_requests_per_hour: u32,

    // Per-IP rate limiting
    pub per_ip_requests_per_minute: u32,
    pub per_ip_requests_per_hour: u32,
    pub per_ip_requests_per_day: u32,

    // Per-client rate limiting
    pub per_client_requests_per_minute: u32,
    pub per_client_requests_per_hour: u32,

    // Endpoint-specific limits
    pub oauth_requests_per_minute: u32,
    pub admin_requests_per_minute: u32,
    pub scim_requests_per_minute: u32,
    pub introspection_requests_per_minute: u32,

    // Burst allowances
    pub burst_capacity: u32,
    pub burst_refill_rate: u32, // tokens per second

    // IP filtering
    pub enable_allowlist: bool,
    pub enable_banlist: bool,
    pub allowlist_ips: HashSet<IpAddr>,
    pub banlist_ips: HashSet<IpAddr>,
    pub allowlist_cidrs: Vec<String>,
    pub banlist_cidrs: Vec<String>,

    // Advanced features
    pub enable_adaptive_limits: bool,
    pub enable_distributed_limiting: bool,
    pub suspicious_threshold: u32, // Requests that trigger suspicious activity
    pub ban_duration_minutes: u32,

    // Cleanup settings
    pub cleanup_interval_seconds: u64,
    pub max_tracked_ips: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_requests_per_minute: 10000,
            global_requests_per_hour: 100_000,
            per_ip_requests_per_minute: 100,
            per_ip_requests_per_hour: 1000,
            per_ip_requests_per_day: 10000,
            per_client_requests_per_minute: 200,
            per_client_requests_per_hour: 2000,
            oauth_requests_per_minute: 60,
            admin_requests_per_minute: 20,
            scim_requests_per_minute: 100,
            introspection_requests_per_minute: 300,
            burst_capacity: 50,
            burst_refill_rate: 10,
            enable_allowlist: false,
            enable_banlist: true,
            allowlist_ips: HashSet::new(),
            banlist_ips: HashSet::new(),
            allowlist_cidrs: Vec::new(),
            banlist_cidrs: Vec::new(),
            enable_adaptive_limits: true,
            enable_distributed_limiting: false,
            suspicious_threshold: 1000,
            ban_duration_minutes: 60,
            cleanup_interval_seconds: 300, // 5 minutes
            max_tracked_ips: 100_000,
        }
    }
}

impl RateLimitConfig {
    /// Load rate limit configuration from environment
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Global limits
        if let Ok(val) = std::env::var("RATE_LIMIT_GLOBAL_PER_MINUTE") {
            config.global_requests_per_minute = val.parse().unwrap_or(config.global_requests_per_minute);
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_GLOBAL_PER_HOUR") {
            config.global_requests_per_hour = val.parse().unwrap_or(config.global_requests_per_hour);
        }

        // Per-IP limits
        if let Ok(val) = std::env::var("RATE_LIMIT_PER_IP_PER_MINUTE") {
            config.per_ip_requests_per_minute = val.parse().unwrap_or(config.per_ip_requests_per_minute);
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_PER_IP_PER_HOUR") {
            config.per_ip_requests_per_hour = val.parse().unwrap_or(config.per_ip_requests_per_hour);
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_PER_IP_PER_DAY") {
            config.per_ip_requests_per_day = val.parse().unwrap_or(config.per_ip_requests_per_day);
        }

        // Per-client limits
        if let Ok(val) = std::env::var("RATE_LIMIT_PER_CLIENT_PER_MINUTE") {
            config.per_client_requests_per_minute = val.parse().unwrap_or(config.per_client_requests_per_minute);
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_PER_CLIENT_PER_HOUR") {
            config.per_client_requests_per_hour = val.parse().unwrap_or(config.per_client_requests_per_hour);
        }

        // Endpoint-specific limits
        if let Ok(val) = std::env::var("RATE_LIMIT_OAUTH_PER_MINUTE") {
            config.oauth_requests_per_minute = val.parse().unwrap_or(config.oauth_requests_per_minute);
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_ADMIN_PER_MINUTE") {
            config.admin_requests_per_minute = val.parse().unwrap_or(config.admin_requests_per_minute);
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_SCIM_PER_MINUTE") {
            config.scim_requests_per_minute = val.parse().unwrap_or(config.scim_requests_per_minute);
        }

        // Burst settings
        if let Ok(val) = std::env::var("RATE_LIMIT_BURST_CAPACITY") {
            config.burst_capacity = val.parse().unwrap_or(config.burst_capacity);
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_BURST_REFILL_RATE") {
            config.burst_refill_rate = val.parse().unwrap_or(config.burst_refill_rate);
        }

        // Feature flags
        config.enable_allowlist = std::env::var("RATE_LIMIT_ENABLE_ALLOWLIST")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(config.enable_allowlist);

        config.enable_banlist = std::env::var("RATE_LIMIT_ENABLE_BANLIST")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(config.enable_banlist);

        config.enable_adaptive_limits = std::env::var("RATE_LIMIT_ENABLE_ADAPTIVE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(config.enable_adaptive_limits);

        // IP lists
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

        if let Ok(cidrs) = std::env::var("RATE_LIMIT_ALLOWLIST_CIDRS") {
            config.allowlist_cidrs = cidrs
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        if let Ok(cidrs) = std::env::var("RATE_LIMIT_BANLIST_CIDRS") {
            config.banlist_cidrs = cidrs
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        config
    }
}

/// Rate limiting window for different time periods
#[derive(Debug, Clone)]
struct RateLimitWindow {
    requests: u32,
    window_start: Instant,
    daily_requests: u32,
    day_start: SystemTime,
    burst_tokens: f32,
    last_refill: Instant,
}

impl RateLimitWindow {
    fn new() -> Self {
        Self {
            requests: 0,
            window_start: Instant::now(),
            daily_requests: 0,
            day_start: SystemTime::now(),
            burst_tokens: 0.0,
            last_refill: Instant::now(),
        }
    }

    fn reset_if_needed(&mut self, window_duration: Duration) {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= window_duration {
            self.requests = 0;
            self.window_start = now;
        }

        // Reset daily counter if needed
        let now_system = SystemTime::now();
        if now_system.duration_since(self.day_start).unwrap_or(Duration::from_secs(0)) >= Duration::from_secs(86400) {
            self.daily_requests = 0;
            self.day_start = now_system;
        }
    }

    fn refill_burst_tokens(&mut self, refill_rate: u32, capacity: u32) {
        let now = Instant::now();
        let time_passed = now.duration_since(self.last_refill).as_secs_f32();

        self.burst_tokens = (self.burst_tokens + (refill_rate as f32 * time_passed)).min(capacity as f32);
        self.last_refill = now;
    }

    fn can_consume_burst_token(&mut self) -> bool {
        if self.burst_tokens >= 1.0 {
            self.burst_tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Advanced rate limiter with multiple strategies
#[derive(Debug)]
pub struct AdvancedRateLimiter {
    config: RateLimitConfig,

    // Global counters
    global_minute_counter: AtomicU64,
    global_minute_start: Arc<std::sync::Mutex<Instant>>,
    global_hour_counter: AtomicU64,
    global_hour_start: Arc<std::sync::Mutex<Instant>>,

    // Per-IP tracking
    ip_windows: Arc<DashMap<IpAddr, RateLimitWindow>>,

    // Per-client tracking
    client_windows: Arc<DashMap<String, RateLimitWindow>>,

    // Endpoint-specific tracking
    endpoint_windows: Arc<DashMap<String, RateLimitWindow>>,

    // Banned IPs with expiration
    banned_ips: Arc<DashMap<IpAddr, SystemTime>>,

    // Metrics
    last_cleanup: Arc<std::sync::Mutex<Instant>>,
}

impl AdvancedRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            global_minute_counter: AtomicU64::new(0),
            global_minute_start: Arc::new(std::sync::Mutex::new(Instant::now())),
            global_hour_counter: AtomicU64::new(0),
            global_hour_start: Arc::new(std::sync::Mutex::new(Instant::now())),
            ip_windows: Arc::new(DashMap::new()),
            client_windows: Arc::new(DashMap::new()),
            endpoint_windows: Arc::new(DashMap::new()),
            banned_ips: Arc::new(DashMap::new()),
            last_cleanup: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    /// Check if request should be rate limited
    pub async fn check_rate_limit(
        &self,
        ip: IpAddr,
        client_id: Option<&str>,
        endpoint: &str,
    ) -> RateLimitResult {
        // Check if IP is banned
        if let Some(ban_time) = self.banned_ips.get(&ip) {
            let ban_expires = *ban_time + Duration::from_secs(self.config.ban_duration_minutes as u64 * 60);
            if SystemTime::now() < ban_expires {
                inc_blocked_total();
                return RateLimitResult::Banned {
                    expires_at: ban_expires,
                };
            } else {
                // Ban expired, remove it
                self.banned_ips.remove(&ip);
            }
        }

        // Check allowlist (bypass all limits if on allowlist)
        if self.config.enable_allowlist && self.is_ip_allowed(&ip) {
            inc_allowed_total();
            return RateLimitResult::Allowed;
        }

        // Check banlist
        if self.config.enable_banlist && self.is_ip_banned(&ip) {
            inc_blocked_total();
            return RateLimitResult::Blocked {
                reason: "IP is on banlist".to_string(),
                retry_after: Duration::from_secs(3600), // 1 hour
            };
        }

        // Check global rate limits
        if let Some(result) = self.check_global_limits().await {
            return result;
        }

        // Check per-IP rate limits
        if let Some(result) = self.check_ip_limits(ip).await {
            return result;
        }

        // Check per-client rate limits
        if let Some(client_id) = client_id {
            if let Some(result) = self.check_client_limits(client_id).await {
                return result;
            }
        }

        // Check endpoint-specific limits
        if let Some(result) = self.check_endpoint_limits(endpoint).await {
            return result;
        }

        // All checks passed, record the request
        self.record_request(ip, client_id, endpoint).await;

        inc_allowed_total();
        RateLimitResult::Allowed
    }

    async fn check_global_limits(&self) -> Option<RateLimitResult> {
        let now = Instant::now();

        // Check minute limit
        {
            let mut minute_start = self.global_minute_start.lock().unwrap();
            if now.duration_since(*minute_start) >= Duration::from_secs(60) {
                self.global_minute_counter.store(0, Ordering::Relaxed);
                *minute_start = now;
            }
        }

        let minute_count = self.global_minute_counter.load(Ordering::Relaxed);
        if minute_count >= self.config.global_requests_per_minute as u64 {
            inc_blocked_total();
            return Some(RateLimitResult::Blocked {
                reason: "Global minute limit exceeded".to_string(),
                retry_after: Duration::from_secs(60),
            });
        }

        // Check hour limit
        {
            let mut hour_start = self.global_hour_start.lock().unwrap();
            if now.duration_since(*hour_start) >= Duration::from_secs(3600) {
                self.global_hour_counter.store(0, Ordering::Relaxed);
                *hour_start = now;
            }
        }

        let hour_count = self.global_hour_counter.load(Ordering::Relaxed);
        if hour_count >= self.config.global_requests_per_hour as u64 {
            inc_blocked_total();
            return Some(RateLimitResult::Blocked {
                reason: "Global hour limit exceeded".to_string(),
                retry_after: Duration::from_secs(3600),
            });
        }

        None
    }

    async fn check_ip_limits(&self, ip: IpAddr) -> Option<RateLimitResult> {
        let mut window = self.ip_windows.entry(ip)
            .or_insert_with(RateLimitWindow::new);

        window.reset_if_needed(Duration::from_secs(60));
        window.refill_burst_tokens(self.config.burst_refill_rate, self.config.burst_capacity);

        // Check minute limit
        if window.requests >= self.config.per_ip_requests_per_minute {
            // Try to use burst tokens
            if !window.can_consume_burst_token() {
                inc_blocked_total();
                return Some(RateLimitResult::Blocked {
                    reason: "Per-IP minute limit exceeded".to_string(),
                    retry_after: Duration::from_secs(60),
                });
            }
        }

        // Check daily limit
        if window.daily_requests >= self.config.per_ip_requests_per_day {
            inc_blocked_total();
            return Some(RateLimitResult::Blocked {
                reason: "Per-IP daily limit exceeded".to_string(),
                retry_after: Duration::from_secs(86400),
            });
        }

        // Check for suspicious activity
        if self.config.enable_adaptive_limits && window.requests > self.config.suspicious_threshold {
            self.ban_ip(ip);
            inc_blocked_total();
            return Some(RateLimitResult::Banned {
                expires_at: SystemTime::now() + Duration::from_secs(self.config.ban_duration_minutes as u64 * 60),
            });
        }

        None
    }

    async fn check_client_limits(&self, client_id: &str) -> Option<RateLimitResult> {
        let mut window = self.client_windows.entry(client_id.to_string())
            .or_insert_with(RateLimitWindow::new);

        window.reset_if_needed(Duration::from_secs(60));

        if window.requests >= self.config.per_client_requests_per_minute {
            inc_blocked_total();
            return Some(RateLimitResult::Blocked {
                reason: format!("Per-client limit exceeded for client: {}", client_id),
                retry_after: Duration::from_secs(60),
            });
        }

        None
    }

    async fn check_endpoint_limits(&self, endpoint: &str) -> Option<RateLimitResult> {
        let limit = match endpoint {
            path if path.starts_with("/oauth") => self.config.oauth_requests_per_minute,
            path if path.starts_with("/admin") => self.config.admin_requests_per_minute,
            path if path.starts_with("/scim") => self.config.scim_requests_per_minute,
            path if path.contains("introspect") => self.config.introspection_requests_per_minute,
            _ => return None, // No specific limit for this endpoint
        };

        let mut window = self.endpoint_windows.entry(endpoint.to_string())
            .or_insert_with(RateLimitWindow::new);

        window.reset_if_needed(Duration::from_secs(60));

        if window.requests >= limit {
            inc_blocked_total();
            return Some(RateLimitResult::Blocked {
                reason: format!("Endpoint-specific limit exceeded for: {}", endpoint),
                retry_after: Duration::from_secs(60),
            });
        }

        None
    }

    async fn record_request(&self, ip: IpAddr, client_id: Option<&str>, endpoint: &str) {
        // Update global counters
        self.global_minute_counter.fetch_add(1, Ordering::Relaxed);
        self.global_hour_counter.fetch_add(1, Ordering::Relaxed);

        // Update IP window
        if let Some(mut window) = self.ip_windows.get_mut(&ip) {
            window.requests += 1;
            window.daily_requests += 1;
        }

        // Update client window
        if let Some(client_id) = client_id {
            if let Some(mut window) = self.client_windows.get_mut(client_id) {
                window.requests += 1;
            }
        }

        // Update endpoint window
        if let Some(mut window) = self.endpoint_windows.get_mut(endpoint) {
            window.requests += 1;
        }

        // Update metrics
        inc_requests_total();

        // Periodic cleanup
        self.cleanup_if_needed().await;
    }

    fn ban_ip(&self, ip: IpAddr) {
        let ban_until = SystemTime::now() + Duration::from_secs(self.config.ban_duration_minutes as u64 * 60);
        self.banned_ips.insert(ip, ban_until);

        tracing::warn!(
            ip = %ip,
            duration_minutes = self.config.ban_duration_minutes,
            "IP address banned due to suspicious activity"
        );

        inc_bans_total();
    }

    fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        self.config.allowlist_ips.contains(ip) ||
        self.config.allowlist_cidrs.iter().any(|cidr| self.ip_in_cidr(ip, cidr))
    }

    fn is_ip_banned(&self, ip: &IpAddr) -> bool {
        self.config.banlist_ips.contains(ip) ||
        self.config.banlist_cidrs.iter().any(|cidr| self.ip_in_cidr(ip, cidr))
    }

    fn ip_in_cidr(&self, ip: &IpAddr, cidr: &str) -> bool {
        // Simple CIDR matching - in production, use a proper CIDR library
        if let Ok(network) = cidr.parse::<ipnetwork::IpNetwork>() {
            network.contains(*ip)
        } else {
            false
        }
    }

    async fn cleanup_if_needed(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let mut last_cleanup = self.last_cleanup.lock().unwrap();
            if now.duration_since(*last_cleanup) >= Duration::from_secs(self.config.cleanup_interval_seconds) {
                *last_cleanup = now;
                true
            } else {
                false
            }
        };

        if should_cleanup {
            self.cleanup_old_entries().await;
        }
    }

    async fn cleanup_old_entries(&self) {
        let now = Instant::now();
        let system_now = SystemTime::now();

        // Clean up old IP windows
        self.ip_windows.retain(|_, window| {
            now.duration_since(window.window_start) < Duration::from_secs(3600) // Keep for 1 hour
        });

        // Clean up old client windows
        self.client_windows.retain(|_, window| {
            now.duration_since(window.window_start) < Duration::from_secs(3600)
        });

        // Clean up old endpoint windows
        self.endpoint_windows.retain(|_, window| {
            now.duration_since(window.window_start) < Duration::from_secs(3600)
        });

        // Clean up expired bans
        self.banned_ips.retain(|_, &mut ban_time| {
            system_now < ban_time + Duration::from_secs(self.config.ban_duration_minutes as u64 * 60)
        });

        // Enforce maximum tracked IPs
        if self.ip_windows.len() > self.config.max_tracked_ips {
            let excess = self.ip_windows.len() - self.config.max_tracked_ips;
            let keys_to_remove: Vec<_> = self.ip_windows.iter()
                .take(excess)
                .map(|entry| *entry.key())
                .collect();

            for key in keys_to_remove {
                self.ip_windows.remove(&key);
            }
        }

        tracing::debug!(
            ip_windows = self.ip_windows.len(),
            client_windows = self.client_windows.len(),
            endpoint_windows = self.endpoint_windows.len(),
            banned_ips = self.banned_ips.len(),
            "Rate limiter cleanup completed"
        );
    }

    /// Get current rate limiting statistics
    pub fn get_stats(&self) -> RateLimitStats {
        RateLimitStats {
            global_minute_requests: self.global_minute_counter.load(Ordering::Relaxed) as u32,
            global_hour_requests: self.global_hour_counter.load(Ordering::Relaxed) as u32,
            tracked_ips: self.ip_windows.len() as u32,
            tracked_clients: self.client_windows.len() as u32,
            banned_ips: self.banned_ips.len() as u32,
            active_endpoints: self.endpoint_windows.len() as u32,
        }
    }
}

/// Result of rate limit check
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed,
    Blocked { reason: String, retry_after: Duration },
    Banned { expires_at: SystemTime },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitStats {
    pub global_minute_requests: u32,
    pub global_hour_requests: u32,
    pub tracked_ips: u32,
    pub tracked_clients: u32,
    pub banned_ips: u32,
    pub active_endpoints: u32,
}

#[derive(Debug, Serialize)]
struct RateLimitErrorResponse {
    error: String,
    message: String,
    retry_after_seconds: u64,
}

// Metrics (feature-gated)
#[cfg(feature = "monitoring")]
static RATE_LIMIT_REQUESTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("rate_limit_requests_total", "Total requests processed by rate limiter").unwrap()
});

#[cfg(feature = "monitoring")]
static RATE_LIMIT_ALLOWED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("rate_limit_allowed_total", "Total requests allowed by rate limiter").unwrap()
});

#[cfg(feature = "monitoring")]
static RATE_LIMIT_BLOCKED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("rate_limit_blocked_total", "Total requests blocked by rate limiter").unwrap()
});

#[cfg(feature = "monitoring")]
static RATE_LIMIT_BANS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("rate_limit_bans_total", "Total IP bans issued").unwrap()
});

#[cfg(feature = "monitoring")]
static RATE_LIMIT_CHECK_DURATION: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!("rate_limit_check_duration_seconds", "Time spent checking rate limits").unwrap()
});

// Metrics helper functions to handle feature gates
#[cfg(feature = "monitoring")]
#[inline]
fn inc_requests_total() { 
    // TODO: Implement actual metrics increment
    // METRICS.requests_total.inc();
}
#[cfg(not(feature = "monitoring"))]
#[inline]
fn inc_requests_total() {}

#[cfg(feature = "monitoring")]
#[inline]
fn inc_allowed_total() { 
    // TODO: Implement actual metrics increment
    // METRICS.allowed_total.inc();
}
#[cfg(not(feature = "monitoring"))]
#[inline]
fn inc_allowed_total() {}

#[cfg(feature = "monitoring")]
#[inline]
fn inc_blocked_total() { 
    // TODO: Implement actual metrics increment
    // METRICS.blocked_total.inc();
}
#[cfg(not(feature = "monitoring"))]
#[inline]
fn inc_blocked_total() {}

#[cfg(feature = "monitoring")]
#[inline]
fn inc_bans_total() { 
    // TODO: Implement actual metrics increment
    // METRICS.bans_total.inc();
}
#[cfg(not(feature = "monitoring"))]
#[inline]
fn inc_bans_total() {}

#[cfg(feature = "monitoring")]
#[inline]
fn start_check_timer() -> prometheus::HistogramTimer { RATE_LIMIT_CHECK_DURATION.start_timer() }
#[cfg(not(feature = "monitoring"))]
#[inline]
fn start_check_timer() -> () { () }

/// Advanced rate limiting middleware
pub async fn advanced_rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let _timer = start_check_timer();

    // Skip rate limiting in test mode
    if std::env::var("TEST_MODE").ok().as_deref() == Some("1") ||
       std::env::var("DISABLE_RATE_LIMIT").ok().as_deref() == Some("1") {
        return Ok(next.run(request).await);
    }

    // Extract client information
    let client_ip = extract_client_ip(&headers, addr.ip());
    let client_id = extract_client_id(&headers);
    let endpoint = request.uri().path();

    // Get rate limiter instance (in real implementation, this would be injected)
    let config = RateLimitConfig::from_env();
    let _limiter = AdvancedRateLimiter::new(config);

    // Check rate limits
    match limiter.check_rate_limit(client_ip, client_id.as_deref(), endpoint).await {
        RateLimitResult::Allowed => {
            Ok(next.run(request).await)
        }

        RateLimitResult::Blocked { reason, retry_after } => {
            let response = Json(RateLimitErrorResponse {
                error: "RATE_LIMIT_EXCEEDED".to_string(),
                message: reason,
                retry_after_seconds: retry_after.as_secs(),
            });

            let mut resp = (StatusCode::TOO_MANY_REQUESTS, response).into_response();
            resp.headers_mut().insert(
                "Retry-After",
                retry_after.as_secs().to_string().parse().unwrap()
            );
            resp.headers_mut().insert(
                "X-RateLimit-Limit",
                "100".parse().unwrap() // This should be dynamic
            );
            resp.headers_mut().insert(
                "X-RateLimit-Remaining",
                "0".parse().unwrap()
            );

            Err(resp)
        }

        RateLimitResult::Banned { expires_at } => {
            let retry_after = expires_at.duration_since(SystemTime::now())
                .unwrap_or(Duration::from_secs(3600))
                .as_secs();

            let response = Json(RateLimitErrorResponse {
                error: "IP_BANNED".to_string(),
                message: "IP address is temporarily banned due to suspicious activity".to_string(),
                retry_after_seconds: retry_after,
            });

            let mut resp = (StatusCode::FORBIDDEN, response).into_response();
            resp.headers_mut().insert(
                "Retry-After",
                retry_after.to_string().parse().unwrap()
            );

            Err(resp)
        }
    }
}

/// Extract client IP from headers or connection info
fn extract_client_ip(headers: &HeaderMap, fallback_ip: IpAddr) -> IpAddr {
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

/// Extract client ID from Authorization header or other client identification
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_rate_limit_basic() {
        let mut config = RateLimitConfig::default();
        config.per_ip_requests_per_minute = 5;

        let limiter = AdvancedRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 5 requests should be allowed
        for _ in 0..5 {
            match limiter.check_rate_limit(ip, None, "/test").await {
                RateLimitResult::Allowed => {},
                _ => panic!("Request should be allowed"),
            }
        }

        // 6th request should be blocked
        match limiter.check_rate_limit(ip, None, "/test").await {
            RateLimitResult::Blocked { .. } => {},
            _ => panic!("Request should be blocked"),
        }
    }

    #[tokio::test]
    async fn test_allowlist() {
        let mut config = RateLimitConfig::default();
        config.enable_allowlist = true;
        config.allowlist_ips.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        config.per_ip_requests_per_minute = 1;

        let limiter = AdvancedRateLimiter::new(config);
        let allowed_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let blocked_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Allowed IP should bypass rate limits
        for _ in 0..10 {
            match limiter.check_rate_limit(allowed_ip, None, "/test").await {
                RateLimitResult::Allowed => {},
                _ => panic!("Allowlisted IP should always be allowed"),
            }
        }

        // Blocked IP should hit rate limit
        match limiter.check_rate_limit(blocked_ip, None, "/test").await {
            RateLimitResult::Allowed => {},
            _ => panic!("First request should be allowed"),
        }

        match limiter.check_rate_limit(blocked_ip, None, "/test").await {
            RateLimitResult::Blocked { .. } => {},
            _ => panic!("Second request should be blocked"),
        }
    }

    #[test]
    fn test_config_from_env() {
        std::env::set_var("RATE_LIMIT_GLOBAL_PER_MINUTE", "500");
        std::env::set_var("RATE_LIMIT_PER_IP_PER_MINUTE", "50");
        std::env::set_var("RATE_LIMIT_ENABLE_ALLOWLIST", "true");

        let config = RateLimitConfig::from_env();

        assert_eq!(config.global_requests_per_minute, 500);
        assert_eq!(config.per_ip_requests_per_minute, 50);
        assert!(config.enable_allowlist);

        // Cleanup
        std::env::remove_var("RATE_LIMIT_GLOBAL_PER_MINUTE");
        std::env::remove_var("RATE_LIMIT_PER_IP_PER_MINUTE");
        std::env::remove_var("RATE_LIMIT_ENABLE_ALLOWLIST");
    }
}