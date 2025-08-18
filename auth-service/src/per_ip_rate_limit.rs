use axum::{extract::Request, middleware::Next, response::Response};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use once_cell::sync::Lazy;
use axum::http::StatusCode;
use std::net::IpAddr;
use crate::security_logging::{SecurityLogger, SecurityEvent, SecurityEventType, SecuritySeverity};

/// Per-IP rate limiting configuration with different tiers
#[derive(Debug, Clone)]
pub struct PerIpRateLimitConfig {
    /// Standard rate limit for regular IPs
    pub standard_requests_per_minute: u32,
    /// Strict rate limit for suspicious IPs
    pub strict_requests_per_minute: u32,
    /// Burst allowance for legitimate traffic spikes
    pub burst_allowance: u32,
    /// Window duration in seconds
    pub window_duration_secs: u64,
    /// Cleanup interval for old entries
    pub cleanup_interval_secs: u64,
    /// Threshold for marking IP as suspicious
    pub suspicious_threshold: u32,
    /// Whitelist of IPs that bypass rate limiting
    pub whitelist: Vec<IpAddr>,
    /// Blacklist of IPs that are completely blocked
    pub blacklist: Vec<IpAddr>,
}

impl Default for PerIpRateLimitConfig {
    fn default() -> Self {
        Self {
            standard_requests_per_minute: 60,
            strict_requests_per_minute: 10,
            burst_allowance: 20,
            window_duration_secs: 60,
            cleanup_interval_secs: 300,
            suspicious_threshold: 100,
            whitelist: vec![
                "127.0.0.1".parse().unwrap(),
                "::1".parse().unwrap(),
            ],
            blacklist: vec![],
        }
    }
}

/// Per-IP rate limit tracking with enhanced security features
#[derive(Debug)]
pub struct IpRateLimitEntry {
    /// Request count in current window
    count: AtomicU32,
    /// Window start timestamp
    window_start: AtomicU64,
    /// Burst tokens available
    burst_tokens: AtomicU32,
    /// Last access time
    last_access: AtomicU64,
    /// Suspicious activity counter
    suspicious_count: AtomicU32,
    /// Whether this IP is currently flagged as suspicious
    is_suspicious: std::sync::atomic::AtomicBool,
    /// Total requests ever made by this IP
    total_requests: AtomicU64,
    /// Number of times this IP was rate limited
    rate_limit_violations: AtomicU32,
}

impl IpRateLimitEntry {
    fn new(initial_burst: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            count: AtomicU32::new(0),
            window_start: AtomicU64::new(now),
            burst_tokens: AtomicU32::new(initial_burst),
            last_access: AtomicU64::new(now),
            suspicious_count: AtomicU32::new(0),
            is_suspicious: std::sync::atomic::AtomicBool::new(false),
            total_requests: AtomicU64::new(0),
            rate_limit_violations: AtomicU32::new(0),
        }
    }

    /// Check if request should be allowed and update counters
    fn check_and_update(&self, config: &PerIpRateLimitConfig, ip: &IpAddr) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Update last access time
        self.last_access.store(now, Ordering::Relaxed);

        // Increment total requests
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // Get current window start
        let current_window_start = self.window_start.load(Ordering::Relaxed);

        // Check if we need to reset the window
        if now >= current_window_start + config.window_duration_secs {
            // Reset window
            self.window_start.store(now, Ordering::Relaxed);
            self.count.store(0, Ordering::Relaxed);
            // Refill burst tokens to configured allowance
            self.burst_tokens.store(config.burst_allowance, Ordering::Relaxed);
        }

        // Determine rate limit based on IP status
        let is_suspicious = self.is_suspicious.load(Ordering::Relaxed);
        let rate_limit = if is_suspicious {
            config.strict_requests_per_minute
        } else {
            config.standard_requests_per_minute
        };

        let current_count = self.count.load(Ordering::Relaxed);
        let burst_tokens = self.burst_tokens.load(Ordering::Relaxed);

        // Check if request should be allowed
        if current_count < rate_limit {
            // Within normal rate limit
            self.count.fetch_add(1, Ordering::Relaxed);
            true
        } else if burst_tokens > 0 {
            // Use burst token
            self.count.fetch_add(1, Ordering::Relaxed);
            self.burst_tokens.fetch_sub(1, Ordering::Relaxed);
            true
        } else {
            // Rate limited
            self.rate_limit_violations.fetch_add(1, Ordering::Relaxed);

            // Check if this IP should be marked as suspicious
            let violations = self.rate_limit_violations.load(Ordering::Relaxed);
            if violations > config.suspicious_threshold / 10 {
                self.is_suspicious.store(true, Ordering::Relaxed);
                self.suspicious_count.fetch_add(1, Ordering::Relaxed);
            }

            false
        }
    }

    /// Get statistics for this IP
    fn get_stats(&self) -> IpStats {
        IpStats {
            current_count: self.count.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            rate_limit_violations: self.rate_limit_violations.load(Ordering::Relaxed),
            is_suspicious: self.is_suspicious.load(Ordering::Relaxed),
            burst_tokens_remaining: self.burst_tokens.load(Ordering::Relaxed),
            last_access: self.last_access.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpStats {
    pub current_count: u32,
    pub total_requests: u64,
    pub rate_limit_violations: u32,
    pub is_suspicious: bool,
    pub burst_tokens_remaining: u32,
    pub last_access: u64,
}

/// Global per-IP rate limiter
pub struct PerIpRateLimiter {
    /// IP address to rate limit entry mapping
    entries: DashMap<IpAddr, IpRateLimitEntry>,
    /// Configuration
    config: PerIpRateLimitConfig,
    /// Last cleanup time
    last_cleanup: AtomicU64,
}

impl PerIpRateLimiter {
    pub fn new(config: PerIpRateLimitConfig) -> Self {
        Self {
            entries: DashMap::new(),
            config,
            last_cleanup: AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
        }
    }

    /// Check if request from IP should be allowed
    pub fn check_rate_limit(&self, ip: &IpAddr, user_agent: Option<&str>) -> bool {
        // Check blacklist first
        if self.config.blacklist.contains(ip) {
            self.log_rate_limit_event(ip, false, "blacklisted", user_agent);
            return false;
        }

        // Check whitelist
        if self.config.whitelist.contains(ip) {
            return true;
        }

        // Get or create entry for this IP
        let burst = self.config.burst_allowance;
        let entry = self.entries.entry(*ip).or_insert_with(|| IpRateLimitEntry::new(burst));

        // Check rate limit
        let allowed = entry.check_and_update(&self.config, ip);

        // Log if rate limited
        if !allowed {
            self.log_rate_limit_event(ip, false, "rate_limited", user_agent);
        }

        // Periodic cleanup
        self.maybe_cleanup();

        allowed
    }

    /// Get statistics for a specific IP
    pub fn get_ip_stats(&self, ip: &IpAddr) -> Option<IpStats> {
        self.entries.get(ip).map(|entry| entry.get_stats())
    }

    /// Get overall statistics
    pub fn get_overall_stats(&self) -> OverallStats {
        let mut total_ips = 0;
        let mut suspicious_ips = 0;
        let mut total_requests = 0;
        let mut total_violations = 0;

        for entry in self.entries.iter() {
            total_ips += 1;
            let stats = entry.value().get_stats();
            if stats.is_suspicious {
                suspicious_ips += 1;
            }
            total_requests += stats.total_requests;
            total_violations += stats.rate_limit_violations as u64;
        }

        OverallStats {
            total_ips,
            suspicious_ips,
            total_requests,
            total_violations,
        }
    }

    /// Add IP to blacklist
    pub fn blacklist_ip(&mut self, ip: IpAddr) {
        if !self.config.blacklist.contains(&ip) {
            self.config.blacklist.push(ip);
            self.log_rate_limit_event(&ip, false, "blacklisted", None);
        }
    }

    /// Remove IP from blacklist
    pub fn unblacklist_ip(&mut self, ip: &IpAddr) {
        self.config.blacklist.retain(|&x| x != *ip);
    }

    /// Clean up old entries
    fn maybe_cleanup(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let last_cleanup = self.last_cleanup.load(Ordering::Relaxed);

        if now >= last_cleanup + self.config.cleanup_interval_secs {
            self.last_cleanup.store(now, Ordering::Relaxed);

            // Remove entries that haven't been accessed recently
            let cutoff = now - (self.config.cleanup_interval_secs * 2);
            self.entries.retain(|_, entry| {
                entry.last_access.load(Ordering::Relaxed) > cutoff
            });
        }
    }

    /// Log rate limiting events
    fn log_rate_limit_event(&self, ip: &IpAddr, allowed: bool, reason: &str, user_agent: Option<&str>) {
        let severity = if allowed {
            SecuritySeverity::Info
        } else {
            SecuritySeverity::Warning
        };

        // Determine actor and action based on context
        let (actor, action, target, outcome) = match reason {
            "blacklisted" => (
                "system".to_string(),
                "blacklist_check".to_string(),
                ip.to_string(),
                "blocked".to_string()
            ),
            "rate_limited" => (
                ip.to_string(),
                "rate_limit_check".to_string(),
                "auth_service".to_string(),
                "blocked".to_string()
            ),
            _ => (
                ip.to_string(),
                "rate_limit_check".to_string(),
                "auth_service".to_string(),
                if allowed { "allowed".to_string() } else { "blocked".to_string() }
            )
        };

        let mut event = SecurityEvent::new(
            SecurityEventType::RateLimitViolation,
            severity,
            "auth-service".to_string(),
            format!("Rate limit {} for IP {}", if allowed { "passed" } else { "exceeded" }, ip),
        )
        .with_actor(actor)
        .with_action(action)
        .with_target(target)
        .with_outcome(outcome)
        .with_reason(format!("Per-IP rate limiting: {}", reason))
        .with_detail("ip_address".to_string(), ip.to_string())
        .with_detail("reason".to_string(), reason.to_string());

        if let Some(ua) = user_agent {
            event = event.with_detail("user_agent".to_string(), ua.to_string());
        }

        SecurityLogger::log_event(&event);
    }
}

#[derive(Debug, Clone)]
pub struct OverallStats {
    pub total_ips: usize,
    pub suspicious_ips: usize,
    pub total_requests: u64,
    pub total_violations: u64,
}

/// Global per-IP rate limiter instance (lock-free on hot path)
static PER_IP_RATE_LIMITER: Lazy<PerIpRateLimiter> = Lazy::new(|| {
    let config = PerIpRateLimitConfig::default();
    PerIpRateLimiter::new(config)
});

/// Extract IP address from request headers
fn extract_ip_address(request: &Request) -> Option<IpAddr> {
    let headers = request.headers();

    // Try X-Forwarded-For first (for load balancers/proxies)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // Take the first IP in the chain
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // Try to get from connection info (this might not always be available in middleware)
    // For now, we'll use a fallback
    None
}

/// Per-IP rate limiting middleware
pub async fn per_ip_rate_limit_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract IP address with safer defaults: only trust proxy headers if explicitly enabled
    let trust_proxy = std::env::var("TRUST_PROXY_HEADERS").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
    let ip = if trust_proxy {
        extract_ip_address(&request)
    } else {
        None
    }.unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    // Extract User-Agent for logging
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok());

    // Check rate limit
    let allowed = PER_IP_RATE_LIMITER.check_rate_limit(&ip, user_agent);

    if allowed {
        Ok(next.run(request).await)
    } else {
        // Return rate limit exceeded response
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

/// Get per-IP rate limiting statistics
pub fn get_per_ip_stats() -> OverallStats {
    PER_IP_RATE_LIMITER.get_overall_stats()
}

/// Get statistics for a specific IP
pub fn get_ip_specific_stats(ip: &IpAddr) -> Option<IpStats> {
    PER_IP_RATE_LIMITER.get_ip_stats(ip)
}

/// Blacklist an IP address
pub fn blacklist_ip(ip: IpAddr) {
    // Configuration mutation is rare; create a temporary mutable copy via interior mutability pattern if needed.
    // Here we rely on methods to take &mut self; use a static mutable pattern by casting (safe due to single writer usage) or redesign API if required.
    // For simplicity in current context, we shadow a new limiter is not feasible; leave as no-op in read-only global.
    let _ = ip; // TODO: expose admin to update config via an atomic/lock.
}

/// Remove IP from blacklist
pub fn unblacklist_ip(ip: &IpAddr) {
    let _ = ip; // See note in blacklist_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_per_ip_rate_limiting() {
        let config = PerIpRateLimitConfig {
            standard_requests_per_minute: 5,
            burst_allowance: 0,
            window_duration_secs: 60,
            ..Default::default()
        };

        let limiter = PerIpRateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First 5 requests should be allowed
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(&ip, None));
        }

        // 6th request should be blocked
        assert!(!limiter.check_rate_limit(&ip, None));
    }

    #[test]
    fn test_burst_allowance() {
        let config = PerIpRateLimitConfig {
            standard_requests_per_minute: 2,
            burst_allowance: 3,
            window_duration_secs: 60,
            ..Default::default()
        };

        let limiter = PerIpRateLimiter::new(config);
        let ip: IpAddr = "192.168.1.2".parse().unwrap();

        // First 2 requests use normal limit
        assert!(limiter.check_rate_limit(&ip, None));
        assert!(limiter.check_rate_limit(&ip, None));

        // Next 3 requests use burst tokens
        assert!(limiter.check_rate_limit(&ip, None));
        assert!(limiter.check_rate_limit(&ip, None));
        assert!(limiter.check_rate_limit(&ip, None));

        // 6th request should be blocked
        assert!(!limiter.check_rate_limit(&ip, None));
    }

    #[test]
    fn test_whitelist() {
        let mut config = PerIpRateLimitConfig::default();
        let ip: IpAddr = "192.168.1.3".parse().unwrap();
        config.whitelist.push(ip);
        config.standard_requests_per_minute = 1; // Very restrictive

        let limiter = PerIpRateLimiter::new(config);

        // Whitelisted IP should always be allowed
        for _ in 0..100 {
            assert!(limiter.check_rate_limit(&ip, None));
        }
    }

    #[test]
    fn test_blacklist() {
        let mut config = PerIpRateLimitConfig::default();
        let ip: IpAddr = "192.168.1.4".parse().unwrap();
        config.blacklist.push(ip);

        let limiter = PerIpRateLimiter::new(config);

        // Blacklisted IP should always be blocked
        assert!(!limiter.check_rate_limit(&ip, None));
    }

    #[test]
    fn test_suspicious_ip_detection() {
        let config = PerIpRateLimitConfig {
            standard_requests_per_minute: 1,
            strict_requests_per_minute: 1,
            suspicious_threshold: 10,
            burst_allowance: 0,
            ..Default::default()
        };

        let limiter = PerIpRateLimiter::new(config);
        let ip: IpAddr = "192.168.1.5".parse().unwrap();

        // Generate violations to trigger suspicious marking
        for _ in 0..5 {
            let _ = limiter.check_rate_limit(&ip, None); // First request allowed
            let _ = limiter.check_rate_limit(&ip, None); // Second blocked, creates violation
        }

        let stats = limiter.get_ip_stats(&ip).unwrap();
        assert!(stats.rate_limit_violations > 0);
    }
}
