use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Enhanced rate limiter with adaptive security controls
pub struct SecureRateLimiter {
    // Per-IP rate limits with ban tracking
    ip_buckets: Arc<RwLock<HashMap<IpAddr, IpTokenBucket>>>,
    // Per-client rate limits
    client_buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    // Per-endpoint rate limits
    endpoint_buckets: Arc<RwLock<HashMap<String, HashMap<IpAddr, TokenBucket>>>>,
    // Global rate limit
    global_bucket: Arc<RwLock<TokenBucket>>,
    // Banned IPs with expiration
    banned_ips: Arc<RwLock<HashMap<IpAddr, DateTime<Utc>>>>,
    config: RateLimitConfig,
}

#[derive(Clone)]
pub struct RateLimitConfig {
    pub global_requests_per_minute: u32,
    pub ip_requests_per_minute: u32,
    pub client_requests_per_minute: u32,
    pub burst_size: u32,
    pub ban_threshold: u32,
    pub ban_duration_minutes: u32,
    pub endpoint_limits: HashMap<String, u32>,
    pub suspicious_threshold: u32,
    pub adaptive_scaling: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let mut endpoint_limits = HashMap::new();
        endpoint_limits.insert("/oauth/token".to_string(), 10);
        endpoint_limits.insert("/oauth/authorize".to_string(), 20);
        endpoint_limits.insert("/oauth/introspect".to_string(), 100);
        endpoint_limits.insert("/admin/".to_string(), 5); // Strict admin limits

        Self {
            global_requests_per_minute: 1000,
            ip_requests_per_minute: 60,
            client_requests_per_minute: 100,
            burst_size: 10,
            ban_threshold: 5,
            ban_duration_minutes: 15,
            endpoint_limits,
            suspicious_threshold: 3,
            adaptive_scaling: true,
        }
    }
}

#[derive(Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: DateTime<Utc>,
    capacity: f64,
    refill_rate: f64, // tokens per second
}

#[derive(Clone)]
struct IpTokenBucket {
    bucket: TokenBucket,
    violation_count: u32,
    last_violation: Option<DateTime<Utc>>,
    suspicious_activity: u32,
    first_seen: DateTime<Utc>,
}

impl TokenBucket {
    fn new(requests_per_minute: u32, burst_size: u32) -> Self {
        let capacity = f64::from(burst_size);
        Self {
            tokens: capacity,
            last_refill: Utc::now(),
            capacity,
            refill_rate: f64::from(requests_per_minute) / 60.0, // per second
        }
    }

    fn refill(&mut self) {
        let now = Utc::now();
        let elapsed = (now - self.last_refill).num_milliseconds() as f64 / 1000.0;

        if elapsed > 0.0 {
            let tokens_to_add = elapsed * self.refill_rate;
            self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
            self.last_refill = now;
        }
    }

    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }
}

impl IpTokenBucket {
    fn new(requests_per_minute: u32, burst_size: u32) -> Self {
        Self {
            bucket: TokenBucket::new(requests_per_minute, burst_size),
            violation_count: 0,
            last_violation: None,
            suspicious_activity: 0,
            first_seen: Utc::now(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Global rate limit exceeded")]
    GlobalLimitExceeded,
    #[error("IP rate limit exceeded: {ip}")]
    IpLimitExceeded { ip: IpAddr },
    #[error("Client rate limit exceeded: {client_id}")]
    ClientLimitExceeded { client_id: String },
    #[error("Endpoint rate limit exceeded: {endpoint}")]
    EndpointLimitExceeded { endpoint: String },
    #[error("IP temporarily banned: {ip}")]
    IpBanned { ip: IpAddr },
    #[error("Suspicious activity detected: {ip}")]
    SuspiciousActivity { ip: IpAddr },
}

impl SecureRateLimiter {
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            ip_buckets: Arc::new(RwLock::new(HashMap::new())),
            client_buckets: Arc::new(RwLock::new(HashMap::new())),
            endpoint_buckets: Arc::new(RwLock::new(HashMap::new())),
            global_bucket: Arc::new(RwLock::new(TokenBucket::new(
                config.global_requests_per_minute,
                config.burst_size,
            ))),
            banned_ips: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Comprehensive rate limit check with security monitoring
    pub async fn check_rate_limit(
        &self,
        ip: IpAddr,
        client_id: Option<&str>,
        endpoint: &str,
        user_agent: Option<&str>,
    ) -> Result<(), RateLimitError> {
        // Check if IP is banned first
        self.check_ip_ban(&ip).await?;

        // Check global rate limit
        {
            let mut global = self.global_bucket.write().await;
            if !global.try_consume(1.0) {
                tracing::warn!("Global rate limit exceeded");
                return Err(RateLimitError::GlobalLimitExceeded);
            }
        }

        // Check IP-based rate limit with enhanced tracking
        {
            let mut ip_buckets = self.ip_buckets.write().await;
            let ip_bucket = ip_buckets.entry(ip).or_insert_with(|| {
                IpTokenBucket::new(self.config.ip_requests_per_minute, self.config.burst_size)
            });

            // Detect suspicious patterns
            self.detect_suspicious_activity(ip_bucket, user_agent, ip)
                .await?;

            if !ip_bucket.bucket.try_consume(1.0) {
                // Track violation
                ip_bucket.violation_count += 1;
                ip_bucket.last_violation = Some(Utc::now());

                tracing::warn!(
                    ip = %ip,
                    violations = ip_bucket.violation_count,
                    endpoint = %endpoint,
                    "IP rate limit exceeded"
                );

                // Check if IP should be banned
                if ip_bucket.violation_count >= self.config.ban_threshold {
                    let ban_expiry =
                        Utc::now() + Duration::minutes(i64::from(self.config.ban_duration_minutes));

                    let mut banned_ips = self.banned_ips.write().await;
                    banned_ips.insert(ip, ban_expiry);

                    tracing::warn!(
                        ip = %ip,
                        violations = ip_bucket.violation_count,
                        ban_expiry = %ban_expiry,
                        "IP temporarily banned for repeated violations"
                    );

                    return Err(RateLimitError::IpBanned { ip });
                }

                return Err(RateLimitError::IpLimitExceeded { ip });
            }

            // Reset violation count on successful request
            if ip_bucket.violation_count > 0 {
                ip_bucket.violation_count = 0;
            }
        }

        // Check client-based rate limit
        if let Some(client_id) = client_id {
            let mut client_buckets = self.client_buckets.write().await;
            let bucket = client_buckets
                .entry(client_id.to_string())
                .or_insert_with(|| {
                    TokenBucket::new(
                        self.config.client_requests_per_minute,
                        self.config.burst_size,
                    )
                });

            if !bucket.try_consume(1.0) {
                tracing::warn!(
                    client_id = %client_id,
                    endpoint = %endpoint,
                    "Client rate limit exceeded"
                );
                return Err(RateLimitError::ClientLimitExceeded {
                    client_id: client_id.to_string(),
                });
            }
        }

        // Check endpoint-specific limits
        if let Some(&limit) = self.config.endpoint_limits.get(endpoint) {
            let mut endpoint_buckets = self.endpoint_buckets.write().await;
            let endpoint_map = endpoint_buckets
                .entry(endpoint.to_string())
                .or_insert_with(HashMap::new);
            let bucket = endpoint_map
                .entry(ip)
                .or_insert_with(|| TokenBucket::new(limit, self.config.burst_size));

            if !bucket.try_consume(1.0) {
                tracing::warn!(
                    ip = %ip,
                    endpoint = %endpoint,
                    limit = limit,
                    "Endpoint rate limit exceeded"
                );
                return Err(RateLimitError::EndpointLimitExceeded {
                    endpoint: endpoint.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Detect suspicious activity patterns
    async fn detect_suspicious_activity(
        &self,
        ip_bucket: &mut IpTokenBucket,
        user_agent: Option<&str>,
        ip: IpAddr,
    ) -> Result<(), RateLimitError> {
        let now = Utc::now();

        // Check for rapid requests (potential bot behavior)
        if let Some(last_violation) = ip_bucket.last_violation {
            let time_since_violation = now - last_violation;
            if time_since_violation.num_seconds() < 10 {
                ip_bucket.suspicious_activity += 1;
            }
        }

        // Check for missing or suspicious user agent
        if let Some(ua) = user_agent {
            if ua.is_empty() || ua.len() < 10 || self.is_suspicious_user_agent(ua) {
                ip_bucket.suspicious_activity += 1;
            }
        } else {
            ip_bucket.suspicious_activity += 1;
        }

        // Check if this is a new IP with high activity
        let ip_age = now - ip_bucket.first_seen;
        if ip_age.num_minutes() < 5 && ip_bucket.bucket.tokens < ip_bucket.bucket.capacity * 0.5 {
            ip_bucket.suspicious_activity += 1;
        }

        // Trigger suspicious activity response
        if ip_bucket.suspicious_activity >= self.config.suspicious_threshold {
            tracing::warn!(
                ip = %ip,
                suspicious_score = ip_bucket.suspicious_activity,
                "Suspicious activity detected"
            );

            // Apply stricter rate limiting for suspicious IPs
            ip_bucket.bucket.refill_rate *= 0.5; // Reduce refill rate

            return Err(RateLimitError::SuspiciousActivity { ip });
        }

        Ok(())
    }

    /// Check if user agent appears suspicious
    fn is_suspicious_user_agent(&self, user_agent: &str) -> bool {
        let suspicious_patterns = [
            "bot", "crawler", "spider", "scraper", "curl", "wget", "python", "java", "go-http",
            "okhttp", "axios",
        ];

        let ua_lower = user_agent.to_lowercase();
        suspicious_patterns
            .iter()
            .any(|pattern| ua_lower.contains(pattern))
    }

    /// Clean up expired entries
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();

        // Clean up banned IPs
        {
            let mut banned_ips = self.banned_ips.write().await;
            banned_ips.retain(|_, expiry| now < *expiry);
        }

        // Clean up old IP buckets (older than 1 hour)
        {
            let mut ip_buckets = self.ip_buckets.write().await;
            ip_buckets.retain(|_, bucket| (now - bucket.first_seen).num_hours() < 1);
        }

        // Clean up old client buckets
        {
            let mut client_buckets = self.client_buckets.write().await;
            client_buckets.retain(|_, bucket| (now - bucket.last_refill).num_minutes() < 30);
        }

        // Clean up endpoint buckets
        {
            let mut endpoint_buckets = self.endpoint_buckets.write().await;
            for (_, ip_map) in endpoint_buckets.iter_mut() {
                ip_map.retain(|_, bucket| (now - bucket.last_refill).num_minutes() < 30);
            }
            endpoint_buckets.retain(|_, ip_map| !ip_map.is_empty());
        }
    }

    /// Get rate limiting statistics
    pub async fn get_stats(&self) -> RateLimitStats {
        let ip_buckets = self.ip_buckets.read().await;
        let client_buckets = self.client_buckets.read().await;
        let banned_ips = self.banned_ips.read().await;

        RateLimitStats {
            tracked_ips: ip_buckets.len(),
            tracked_clients: client_buckets.len(),
            banned_ips: banned_ips.len(),
            suspicious_ips: ip_buckets
                .values()
                .filter(|bucket| bucket.suspicious_activity >= self.config.suspicious_threshold)
                .count(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RateLimitStats {
    pub tracked_ips: usize,
    pub tracked_clients: usize,
    pub banned_ips: usize,
    pub suspicious_ips: usize,
}

impl SecureRateLimiter {
    /// Check if an IP is currently banned
    ///
    /// # Errors
    ///
    /// Returns `RateLimitError::IpBanned` if the IP is currently banned.
    async fn check_ip_ban(&self, ip: &IpAddr) -> Result<(), RateLimitError> {
        let mut banned_ips = self.banned_ips.write().await;
        if let Some(ban_expiry) = banned_ips.get(ip) {
            if Utc::now() < *ban_expiry {
                return Err(RateLimitError::IpBanned { ip: *ip });
            }
            // Ban expired, remove it
            banned_ips.remove(ip);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = RateLimitConfig::default();
        let limiter = SecureRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Should allow initial requests
        assert!(limiter
            .check_rate_limit(ip, None, "/test", Some("Mozilla/5.0"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_ip_banning() {
        let mut config = RateLimitConfig::default();
        config.ip_requests_per_minute = 1;
        config.ban_threshold = 2;

        let limiter = SecureRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Exhaust rate limit multiple times to trigger ban
        for _ in 0..3 {
            let _ = limiter
                .check_rate_limit(ip, None, "/test", Some("Mozilla/5.0"))
                .await;
        }

        // Should be banned now
        let result = limiter
            .check_rate_limit(ip, None, "/test", Some("Mozilla/5.0"))
            .await;
        assert!(matches!(result, Err(RateLimitError::IpBanned { .. })));
    }

    #[tokio::test]
    async fn test_suspicious_activity_detection() {
        let config = RateLimitConfig::default();
        let limiter = SecureRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));

        // Request with suspicious user agent
        let _result = limiter
            .check_rate_limit(ip, None, "/test", Some("curl/7.68.0"))
            .await;
        // May trigger suspicious activity detection
    }
}
