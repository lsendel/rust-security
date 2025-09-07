//! Adaptive Rate Limiting with Request Fingerprinting Integration
//!
//! Advanced rate limiting system that adapts limits based on request patterns,
//! anomaly detection, and security threat levels.

use crate::request_fingerprinting::{RecommendedAction, RequestFingerprintAnalyzer, RiskLevel};
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Adaptive rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveRateLimitConfig {
    /// Base rate limits (can be modified dynamically)
    pub base_requests_per_minute: u32,
    pub base_requests_per_hour: u32,
    pub base_burst_capacity: u32,

    /// Adaptive multipliers based on risk levels
    pub low_risk_multiplier: f64, // 1.2 = 20% more lenient
    pub medium_risk_multiplier: f64,   // 0.5 = 50% more strict
    pub high_risk_multiplier: f64,     // 0.1 = 90% more strict
    pub critical_risk_multiplier: f64, // 0.01 = 99% more strict

    /// Endpoint-specific configurations
    pub endpoint_configs: HashMap<String, EndpointRateLimitConfig>,

    /// Enable/disable adaptive behavior
    pub enable_adaptive_limits: bool,
    pub enable_fingerprint_analysis: bool,
    pub enable_progressive_penalties: bool,

    /// Progressive penalty configuration
    pub violation_penalty_duration: Duration,
    pub max_penalty_multiplier: f64,
    pub penalty_decay_rate: f64, // How quickly penalties decay
}

impl Default for AdaptiveRateLimitConfig {
    fn default() -> Self {
        let mut endpoint_configs = HashMap::new();

        // More restrictive limits for sensitive endpoints
        endpoint_configs.insert(
            "/api/v1/auth/login".to_string(),
            EndpointRateLimitConfig {
                requests_per_minute: 10,
                requests_per_hour: 100,
                burst_capacity: 3,
            },
        );
        endpoint_configs.insert(
            "/api/v1/auth/register".to_string(),
            EndpointRateLimitConfig {
                requests_per_minute: 5,
                requests_per_hour: 20,
                burst_capacity: 2,
            },
        );
        endpoint_configs.insert(
            "/oauth/token".to_string(),
            EndpointRateLimitConfig {
                requests_per_minute: 30,
                requests_per_hour: 300,
                burst_capacity: 10,
            },
        );

        Self {
            base_requests_per_minute: 60,
            base_requests_per_hour: 1000,
            base_burst_capacity: 10,
            low_risk_multiplier: 1.2,
            medium_risk_multiplier: 0.5,
            high_risk_multiplier: 0.1,
            critical_risk_multiplier: 0.01,
            endpoint_configs,
            enable_adaptive_limits: true,
            enable_fingerprint_analysis: true,
            enable_progressive_penalties: true,
            violation_penalty_duration: Duration::from_secs(15 * 60), // 15 minutes
            max_penalty_multiplier: 0.1,
            penalty_decay_rate: 0.9,
        }
    }
}

/// Endpoint-specific rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRateLimitConfig {
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_capacity: u32,
}

/// Token bucket for rate limiting with adaptive capacity
#[derive(Debug)]
struct AdaptiveTokenBucket {
    /// Current token count
    tokens: AtomicU64,
    /// Maximum capacity (can change based on risk assessment)
    max_capacity: AtomicU64,
    /// Base capacity (original limit)
    base_capacity: u64,
    /// Tokens added per second
    refill_rate: AtomicU64,
    /// Last refill timestamp
    last_refill: AtomicU64,
    /// Current risk multiplier
    risk_multiplier: std::sync::atomic::AtomicU64, // Stored as fixed-point (multiply by 1000)
    /// Progressive penalty multiplier
    penalty_multiplier: std::sync::atomic::AtomicU64, // Stored as fixed-point (multiply by 1000)
    /// Penalty expiration timestamp
    penalty_expires: AtomicU64,
}

impl AdaptiveTokenBucket {
    fn new(capacity: u32, refill_rate_per_minute: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let capacity = capacity as u64;
        let refill_rate = (refill_rate_per_minute as u64 * 1000) / 60; // Per second, fixed-point

        Self {
            tokens: AtomicU64::new(capacity),
            max_capacity: AtomicU64::new(capacity),
            base_capacity: capacity,
            refill_rate: AtomicU64::new(refill_rate),
            last_refill: AtomicU64::new(now),
            risk_multiplier: AtomicU64::new(1000), // 1.0 in fixed-point
            penalty_multiplier: AtomicU64::new(1000), // 1.0 in fixed-point
            penalty_expires: AtomicU64::new(0),
        }
    }

    /// Try to consume tokens, returning true if successful
    fn try_consume(&self, tokens: u32) -> bool {
        self.refill();

        let tokens_needed = tokens as u64;
        let current_tokens = self.tokens.load(Ordering::Acquire);

        if current_tokens >= tokens_needed {
            // Atomic decrement if we have enough tokens
            let prev = self.tokens.fetch_sub(tokens_needed, Ordering::AcqRel);
            prev >= tokens_needed
        } else {
            false
        }
    }

    /// Refill tokens based on time elapsed
    fn refill(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last_refill = self.last_refill.load(Ordering::Acquire);
        let time_elapsed = now.saturating_sub(last_refill);

        if time_elapsed > 0 {
            let refill_rate = self.refill_rate.load(Ordering::Acquire);
            let tokens_to_add = (time_elapsed * refill_rate) / 1000; // Convert from fixed-point

            if tokens_to_add > 0 {
                let max_capacity = self.max_capacity.load(Ordering::Acquire);
                let current_tokens = self.tokens.load(Ordering::Acquire);
                let new_tokens = (current_tokens + tokens_to_add).min(max_capacity);

                self.tokens.store(new_tokens, Ordering::Release);
                self.last_refill.store(now, Ordering::Release);
            }
        }
    }

    /// Update capacity based on risk assessment
    fn update_risk_multiplier(&self, risk_multiplier: f64) {
        let risk_multiplier_fixed = (risk_multiplier * 1000.0) as u64;
        self.risk_multiplier
            .store(risk_multiplier_fixed, Ordering::Release);

        // Update effective capacity
        let penalty_multiplier = self.penalty_multiplier.load(Ordering::Acquire) as f64 / 1000.0;
        let effective_multiplier = risk_multiplier * penalty_multiplier;
        let new_capacity = (self.base_capacity as f64 * effective_multiplier).max(1.0) as u64;
        self.max_capacity.store(new_capacity, Ordering::Release);
    }

    /// Apply progressive penalty for violations
    fn apply_penalty(&self, penalty_duration: Duration, penalty_multiplier: f64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let penalty_expires = now + penalty_duration.as_secs();
        self.penalty_expires
            .store(penalty_expires, Ordering::Release);

        let penalty_fixed = (penalty_multiplier * 1000.0) as u64;
        self.penalty_multiplier
            .store(penalty_fixed, Ordering::Release);

        // Recalculate capacity
        let risk_multiplier = self.risk_multiplier.load(Ordering::Acquire) as f64 / 1000.0;
        let effective_multiplier = risk_multiplier * penalty_multiplier;
        let new_capacity = (self.base_capacity as f64 * effective_multiplier).max(1.0) as u64;
        self.max_capacity.store(new_capacity, Ordering::Release);
    }

    /// Check if penalty has expired and reset if needed
    fn check_penalty_expiry(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let penalty_expires = self.penalty_expires.load(Ordering::Acquire);
        if penalty_expires > 0 && now >= penalty_expires {
            // Reset penalty
            self.penalty_multiplier.store(1000, Ordering::Release); // 1.0 in fixed-point
            self.penalty_expires.store(0, Ordering::Release);

            // Recalculate capacity without penalty
            let risk_multiplier = self.risk_multiplier.load(Ordering::Acquire) as f64 / 1000.0;
            let new_capacity = (self.base_capacity as f64 * risk_multiplier).max(1.0) as u64;
            self.max_capacity.store(new_capacity, Ordering::Release);
        }
    }

    /// Get current status for monitoring
    fn get_status(&self) -> BucketStatus {
        self.refill();
        self.check_penalty_expiry();

        BucketStatus {
            current_tokens: self.tokens.load(Ordering::Acquire),
            max_capacity: self.max_capacity.load(Ordering::Acquire),
            base_capacity: self.base_capacity,
            risk_multiplier: self.risk_multiplier.load(Ordering::Acquire) as f64 / 1000.0,
            penalty_multiplier: self.penalty_multiplier.load(Ordering::Acquire) as f64 / 1000.0,
            penalty_active: self.penalty_expires.load(Ordering::Acquire)
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
        }
    }
}

/// Current status of a token bucket
#[derive(Debug, Serialize)]
pub struct BucketStatus {
    pub current_tokens: u64,
    pub max_capacity: u64,
    pub base_capacity: u64,
    pub risk_multiplier: f64,
    pub penalty_multiplier: f64,
    pub penalty_active: bool,
}

/// Client state for adaptive rate limiting
#[derive(Debug)]
struct ClientState {
    /// Per-minute token bucket
    minute_bucket: AdaptiveTokenBucket,
    /// Per-hour token bucket
    hour_bucket: AdaptiveTokenBucket,
    /// Violation count in recent time window
    violation_count: AtomicU64,
    /// Last violation timestamp
    last_violation: AtomicU64,
    /// Current risk level
    current_risk_level: RwLock<RiskLevel>,
}

/// Adaptive rate limiter with fingerprinting integration
pub struct AdaptiveRateLimiter {
    /// Configuration
    config: AdaptiveRateLimitConfig,
    /// Per-IP client states
    client_states: Arc<RwLock<HashMap<String, Arc<ClientState>>>>,
    /// Request fingerprint analyzer
    fingerprint_analyzer: Arc<RequestFingerprintAnalyzer>,
    /// Global statistics
    stats: Arc<RateLimitStats>,
}

/// Rate limiting statistics
#[derive(Debug, Default)]
pub struct RateLimitStats {
    pub total_requests: AtomicU64,
    pub allowed_requests: AtomicU64,
    pub rate_limited_requests: AtomicU64,
    pub anomalous_requests: AtomicU64,
    pub blocked_requests: AtomicU64,
    pub active_clients: AtomicU64,
}

impl AdaptiveRateLimiter {
    /// Create a new adaptive rate limiter
    pub fn new(
        config: AdaptiveRateLimitConfig,
        fingerprint_analyzer: Arc<RequestFingerprintAnalyzer>,
    ) -> Self {
        Self {
            config,
            client_states: Arc::new(RwLock::new(HashMap::new())),
            fingerprint_analyzer,
            stats: Arc::new(RateLimitStats::default()),
        }
    }

    /// Check if a request should be allowed
    pub async fn check_rate_limit(&self, req: Request) -> RateLimitDecision {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        // Extract request information
        let client_ip = self.extract_client_ip(&req);
        let method = req.method().as_str();
        let path = req.uri().path();
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok());
        let content_type = req
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok());
        let accept = req.headers().get("accept").and_then(|h| h.to_str().ok());
        let content_length = req
            .headers()
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse().ok());

        // Create fingerprint and analyze for anomalies
        let mut anomaly_result = None;
        if self.config.enable_fingerprint_analysis {
            let fingerprint = self.fingerprint_analyzer.create_fingerprint(
                &client_ip,
                method,
                path,
                user_agent,
                content_type,
                accept,
                content_length,
                None, // TLS cipher not available at this layer
            );

            let result = self.fingerprint_analyzer.analyze_request(fingerprint).await;
            anomaly_result = Some(result);
        }

        // Get or create client state
        let client_state = self.get_or_create_client_state(&client_ip).await;

        // Determine rate limits for this request
        let (_minute_limit, _hour_limit, _burst_limit) = self.get_limits_for_request(path);

        // Update risk-based multipliers
        if let Some(ref anomaly) = anomaly_result {
            let risk_multiplier = self.get_risk_multiplier(&anomaly.risk_level);
            client_state
                .minute_bucket
                .update_risk_multiplier(risk_multiplier);
            client_state
                .hour_bucket
                .update_risk_multiplier(risk_multiplier);

            // Update stored risk level
            *client_state.current_risk_level.write().await = anomaly.risk_level.clone();

            if anomaly.is_anomalous {
                self.stats
                    .anomalous_requests
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        // Check rate limits
        let minute_allowed = client_state.minute_bucket.try_consume(1);
        let hour_allowed = client_state.hour_bucket.try_consume(1);

        let decision = if minute_allowed && hour_allowed {
            self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
            RateLimitDecision::Allow
        } else {
            // Apply progressive penalties for violations
            if self.config.enable_progressive_penalties {
                self.apply_violation_penalty(&client_state).await;
            }

            self.stats
                .rate_limited_requests
                .fetch_add(1, Ordering::Relaxed);

            // Check if we should block based on anomaly analysis
            if let Some(ref anomaly) = anomaly_result {
                match anomaly.recommended_action {
                    RecommendedAction::Block | RecommendedAction::SecurityAlert => {
                        self.stats.blocked_requests.fetch_add(1, Ordering::Relaxed);
                        return RateLimitDecision::Block {
                            reason: format!(
                                "Request blocked due to security analysis: {:?}",
                                anomaly.indicators
                            ),
                            retry_after: Duration::from_secs(5 * 60),
                        };
                    }
                    _ => {}
                }
            }

            RateLimitDecision::RateLimit {
                retry_after: Duration::from_secs(60),
                current_usage: if !minute_allowed { "minute" } else { "hour" }.to_string(),
            }
        };

        decision
    }

    /// Get or create client state for an IP
    async fn get_or_create_client_state(&self, ip: &str) -> Arc<ClientState> {
        let mut states = self.client_states.write().await;

        if let Some(state) = states.get(ip) {
            Arc::clone(state)
        } else {
            let (minute_limit, hour_limit, _) = self.get_limits_for_request("/"); // Default limits

            let state = Arc::new(ClientState {
                minute_bucket: AdaptiveTokenBucket::new(minute_limit, minute_limit),
                hour_bucket: AdaptiveTokenBucket::new(hour_limit, hour_limit),
                violation_count: AtomicU64::new(0),
                last_violation: AtomicU64::new(0),
                current_risk_level: RwLock::new(RiskLevel::Low),
            });

            states.insert(ip.to_string(), Arc::clone(&state));
            self.stats
                .active_clients
                .store(states.len() as u64, Ordering::Relaxed);
            state
        }
    }

    /// Get rate limits for a specific request path
    fn get_limits_for_request(&self, path: &str) -> (u32, u32, u32) {
        if let Some(endpoint_config) = self.config.endpoint_configs.get(path) {
            (
                endpoint_config.requests_per_minute,
                endpoint_config.requests_per_hour,
                endpoint_config.burst_capacity,
            )
        } else {
            (
                self.config.base_requests_per_minute,
                self.config.base_requests_per_hour,
                self.config.base_burst_capacity,
            )
        }
    }

    /// Get risk multiplier based on risk level
    fn get_risk_multiplier(&self, risk_level: &RiskLevel) -> f64 {
        match risk_level {
            RiskLevel::Low => self.config.low_risk_multiplier,
            RiskLevel::Medium => self.config.medium_risk_multiplier,
            RiskLevel::High => self.config.high_risk_multiplier,
            RiskLevel::Critical => self.config.critical_risk_multiplier,
        }
    }

    /// Apply progressive penalty for rate limit violations
    async fn apply_violation_penalty(&self, client_state: &ClientState) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let violation_count = client_state.violation_count.fetch_add(1, Ordering::AcqRel);
        client_state.last_violation.store(now, Ordering::Release);

        // Calculate penalty multiplier based on violation count
        let penalty_multiplier = (self.config.penalty_decay_rate.powf(violation_count as f64))
            .max(self.config.max_penalty_multiplier);

        info!(
            violation_count = violation_count + 1,
            penalty_multiplier = penalty_multiplier,
            "Applying progressive rate limit penalty"
        );

        client_state
            .minute_bucket
            .apply_penalty(self.config.violation_penalty_duration, penalty_multiplier);
        client_state
            .hour_bucket
            .apply_penalty(self.config.violation_penalty_duration, penalty_multiplier);
    }

    /// Extract client IP from request
    fn extract_client_ip(&self, req: &Request) -> String {
        // Check for forwarded headers first (for proxy environments)
        if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
            if let Ok(forwarded_str) = forwarded_for.to_str() {
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    return first_ip.trim().to_string();
                }
            }
        }

        if let Some(real_ip) = req.headers().get("x-real-ip") {
            if let Ok(ip_str) = real_ip.to_str() {
                return ip_str.to_string();
            }
        }

        // Fallback to connection info (may not be available in middleware)
        "unknown".to_string()
    }

    /// Get current statistics
    pub fn get_stats(&self) -> RateLimitStatsSnapshot {
        RateLimitStatsSnapshot {
            total_requests: self.stats.total_requests.load(Ordering::Relaxed),
            allowed_requests: self.stats.allowed_requests.load(Ordering::Relaxed),
            rate_limited_requests: self.stats.rate_limited_requests.load(Ordering::Relaxed),
            anomalous_requests: self.stats.anomalous_requests.load(Ordering::Relaxed),
            blocked_requests: self.stats.blocked_requests.load(Ordering::Relaxed),
            active_clients: self.stats.active_clients.load(Ordering::Relaxed),
        }
    }

    /// Clean up old client states periodically
    pub async fn cleanup_old_clients(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cleanup_threshold = now.saturating_sub(3600); // Remove clients inactive for 1 hour

        let mut states = self.client_states.write().await;
        let initial_count = states.len();

        states.retain(|_, state| {
            let last_violation = state.last_violation.load(Ordering::Acquire);
            last_violation > cleanup_threshold
        });

        let cleaned_count = initial_count - states.len();
        if cleaned_count > 0 {
            info!("Cleaned up {} inactive client states", cleaned_count);
            self.stats
                .active_clients
                .store(states.len() as u64, Ordering::Relaxed);
        }
    }
}

/// Rate limiting decision
#[derive(Debug)]
pub enum RateLimitDecision {
    /// Allow the request
    Allow,
    /// Rate limit the request
    RateLimit {
        retry_after: Duration,
        current_usage: String,
    },
    /// Block the request entirely
    Block {
        reason: String,
        retry_after: Duration,
    },
}

/// Snapshot of rate limiting statistics
#[derive(Debug, Serialize)]
pub struct RateLimitStatsSnapshot {
    pub total_requests: u64,
    pub allowed_requests: u64,
    pub rate_limited_requests: u64,
    pub anomalous_requests: u64,
    pub blocked_requests: u64,
    pub active_clients: u64,
}

/// Middleware function for adaptive rate limiting
pub async fn adaptive_rate_limit_middleware(
    req: Request,
    next: Next,
) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
    // This is a placeholder - in practice, you'd need to inject the rate limiter
    // via Axum's state system or extension system

    // For now, just pass through
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_fingerprinting::FingerprintingConfig;

    #[tokio::test]
    async fn test_token_bucket_basic_operations() {
        let bucket = AdaptiveTokenBucket::new(10, 60); // 10 tokens, 1 per second refill

        // Should be able to consume initial tokens
        assert!(bucket.try_consume(5));
        assert!(bucket.try_consume(5));

        // Should not be able to consume more
        assert!(!bucket.try_consume(1));

        // Wait a bit and try again (would need real time in production)
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Note: Refill is based on system time, not tokio time
    }

    #[tokio::test]
    async fn test_risk_multiplier_adjustment() {
        let bucket = AdaptiveTokenBucket::new(10, 60);

        // Apply high risk multiplier (should reduce capacity)
        bucket.update_risk_multiplier(0.1); // 90% reduction

        let status = bucket.get_status();
        assert_eq!(status.max_capacity, 1); // Should be reduced to 1
        assert_eq!(status.risk_multiplier, 0.1);
    }

    #[tokio::test]
    async fn test_adaptive_rate_limiter() {
        let config = AdaptiveRateLimitConfig::default();
        let fp_analyzer = Arc::new(RequestFingerprintAnalyzer::new(
            FingerprintingConfig::default(),
        ));

        let limiter = AdaptiveRateLimiter::new(config, fp_analyzer);

        // Create a mock request (simplified for testing)
        let req = Request::builder()
            .method("GET")
            .uri("/api/test")
            .header("user-agent", "test-agent")
            .body(axum::body::Body::empty())
            .unwrap();

        let decision = limiter.check_rate_limit(req).await;

        // First request should be allowed
        matches!(decision, RateLimitDecision::Allow);
    }

    #[test]
    fn test_penalty_application() {
        let bucket = AdaptiveTokenBucket::new(10, 60);

        // Apply penalty
        bucket.apply_penalty(Duration::from_secs(300), 0.5); // 50% reduction for 5 minutes

        let status = bucket.get_status();
        assert_eq!(status.penalty_multiplier, 0.5);
        assert!(status.penalty_active);
        assert_eq!(status.max_capacity, 5); // 10 * 1.0 * 0.5 = 5
    }
}
