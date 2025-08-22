// Enhanced Rate Limiting Implementation
// Comprehensive DoS protection with multiple strategies

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use serde::{Deserialize, Serialize};

/// Configuration for rate limiting
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per minute per IP
    pub per_ip_rpm: u32,
    /// Requests per minute per user
    pub per_user_rpm: u32,
    /// Global requests per minute
    pub global_rpm: u32,
    /// Burst allowance (requests above rate limit)
    pub burst_allowance: u32,
    /// Window size for sliding window algorithm
    pub window_size: Duration,
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
    /// Enable adaptive rate limiting
    pub adaptive_enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_ip_rpm: 100,
            per_user_rpm: 200,
            global_rpm: 10000,
            burst_allowance: 10,
            window_size: Duration::from_secs(60),
            cleanup_interval: Duration::from_secs(300),
            adaptive_enabled: true,
        }
    }
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            capacity,
            refill_rate,
        }
    }

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
}

/// Sliding window rate limiter
#[derive(Debug)]
pub struct SlidingWindow {
    requests: Vec<Instant>,
    window_size: Duration,
    max_requests: usize,
}

impl SlidingWindow {
    pub fn new(max_requests: usize, window_size: Duration) -> Self {
        Self {
            requests: Vec::new(),
            window_size,
            max_requests,
        }
    }

    pub fn try_request(&mut self) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window_size;
        
        // Remove old requests
        self.requests.retain(|&time| time > cutoff);
        
        if self.requests.len() < self.max_requests {
            self.requests.push(now);
            true
        } else {
            false
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
        self.current_rate = self.current_rate.max(self.base_rate * 0.1).min(self.base_rate * 2.0);
        self.last_adjustment = now;
    }

    pub fn current_rate(&self) -> f64 {
        self.current_rate
    }
}

/// Rate limiting errors
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded for IP: {ip}")]
    IpRateLimitExceeded { ip: IpAddr },
    #[error("Rate limit exceeded for user: {user_id}")]
    UserRateLimitExceeded { user_id: String },
    #[error("Global rate limit exceeded")]
    GlobalRateLimitExceeded,
    #[error("Burst limit exceeded")]
    BurstLimitExceeded,
}

/// Advanced rate limiter with multiple strategies
pub struct AdvancedRateLimiter {
    per_ip_limits: Arc<RwLock<HashMap<IpAddr, TokenBucket>>>,
    per_user_limits: Arc<RwLock<HashMap<String, TokenBucket>>>,
    global_limiter: Arc<RwLock<TokenBucket>>,
    sliding_windows: Arc<RwLock<HashMap<String, SlidingWindow>>>,
    adaptive_limiter: Arc<RwLock<AdaptiveLimiter>>,
    config: RateLimitConfig,
    metrics: RateLimitMetrics,
}

/// Rate limiting metrics
#[derive(Debug, Default, Clone)]
pub struct RateLimitMetrics {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub ip_blocks: u64,
    pub user_blocks: u64,
    pub global_blocks: u64,
}

impl AdvancedRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let global_capacity = config.global_rpm as f64;
        let global_refill_rate = global_capacity / 60.0; // per second
        
        Self {
            per_ip_limits: Arc::new(RwLock::new(HashMap::new())),
            per_user_limits: Arc::new(RwLock::new(HashMap::new())),
            global_limiter: Arc::new(RwLock::new(TokenBucket::new(global_capacity, global_refill_rate))),
            sliding_windows: Arc::new(RwLock::new(HashMap::new())),
            adaptive_limiter: Arc::new(RwLock::new(AdaptiveLimiter::new(global_capacity))),
            config,
            metrics: RateLimitMetrics::default(),
        }
    }

    /// Check rate limit for a request
    pub async fn check_rate_limit(
        &self,
        ip: IpAddr,
        user_id: Option<&str>,
        endpoint: &str,
    ) -> Result<(), RateLimitError> {
        // Update metrics
        let mut metrics = self.metrics.clone();
        metrics.total_requests += 1;

        // Check global rate limit first
        {
            let mut global = self.global_limiter.write().await;
            if !global.try_consume(1.0) {
                metrics.blocked_requests += 1;
                metrics.global_blocks += 1;
                warn!("Global rate limit exceeded");
                return Err(RateLimitError::GlobalRateLimitExceeded);
            }
        }

        // Check IP-based rate limit
        {
            let mut ip_limits = self.per_ip_limits.write().await;
            let ip_bucket = ip_limits.entry(ip).or_insert_with(|| {
                let capacity = self.config.per_ip_rpm as f64;
                let refill_rate = capacity / 60.0;
                TokenBucket::new(capacity, refill_rate)
            });

            if !ip_bucket.try_consume(1.0) {
                metrics.blocked_requests += 1;
                metrics.ip_blocks += 1;
                warn!("IP rate limit exceeded for {}", ip);
                return Err(RateLimitError::IpRateLimitExceeded { ip });
            }
        }

        // Check user-based rate limit if user is authenticated
        if let Some(user_id) = user_id {
            let mut user_limits = self.per_user_limits.write().await;
            let user_bucket = user_limits.entry(user_id.to_string()).or_insert_with(|| {
                let capacity = self.config.per_user_rpm as f64;
                let refill_rate = capacity / 60.0;
                TokenBucket::new(capacity, refill_rate)
            });

            if !user_bucket.try_consume(1.0) {
                metrics.blocked_requests += 1;
                metrics.user_blocks += 1;
                warn!("User rate limit exceeded for {}", user_id);
                return Err(RateLimitError::UserRateLimitExceeded {
                    user_id: user_id.to_string(),
                });
            }
        }

        // Check sliding window for burst protection
        {
            let key = format!("{}:{}", ip, endpoint);
            let mut windows = self.sliding_windows.write().await;
            let window = windows.entry(key).or_insert_with(|| {
                SlidingWindow::new(
                    self.config.burst_allowance as usize,
                    Duration::from_secs(10), // 10-second burst window
                )
            });

            if !window.try_request() {
                metrics.blocked_requests += 1;
                warn!("Burst limit exceeded for {} on {}", ip, endpoint);
                return Err(RateLimitError::BurstLimitExceeded);
            }
        }

        info!("Rate limit check passed for {} on {}", ip, endpoint);
        Ok(())
    }

    /// Update adaptive rate limiting based on system metrics
    pub async fn update_adaptive_limits(&self, error_rate: f64) {
        if self.config.adaptive_enabled {
            let mut adaptive = self.adaptive_limiter.write().await;
            adaptive.adjust_rate(error_rate);
            
            // Update global limiter with new rate
            let new_rate = adaptive.current_rate();
            let mut global = self.global_limiter.write().await;
            *global = TokenBucket::new(new_rate, new_rate / 60.0);
            
            info!("Adaptive rate limit updated to {:.2} RPM", new_rate);
        }
    }

    /// Cleanup expired entries
    pub async fn cleanup_expired(&self) {
        let cutoff = Instant::now() - self.config.cleanup_interval;
        
        // Clean up sliding windows
        {
            let mut windows = self.sliding_windows.write().await;
            windows.retain(|_, window| {
                window.requests.retain(|&time| time > cutoff);
                !window.requests.is_empty()
            });
        }
        
        info!("Cleaned up expired rate limit entries");
    }

    /// Get current metrics
    pub fn get_metrics(&self) -> RateLimitMetrics {
        self.metrics.clone()
    }

    /// Reset metrics
    pub fn reset_metrics(&mut self) {
        self.metrics = RateLimitMetrics::default();
    }
}

/// Middleware for rate limiting
pub async fn rate_limit_middleware(
    limiter: Arc<AdvancedRateLimiter>,
    ip: IpAddr,
    user_id: Option<String>,
    endpoint: String,
) -> Result<(), RateLimitError> {
    limiter.check_rate_limit(ip, user_id.as_deref(), &endpoint).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10.0, 1.0); // 10 tokens, 1 per second
        
        // Should be able to consume initial tokens
        assert!(bucket.try_consume(5.0));
        assert!(bucket.try_consume(5.0));
        
        // Should fail when empty
        assert!(!bucket.try_consume(1.0));
    }

    #[test]
    fn test_sliding_window() {
        let mut window = SlidingWindow::new(3, Duration::from_secs(1));
        
        // Should allow up to max requests
        assert!(window.try_request());
        assert!(window.try_request());
        assert!(window.try_request());
        
        // Should block additional requests
        assert!(!window.try_request());
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let config = RateLimitConfig {
            per_ip_rpm: 60,
            per_user_rpm: 120,
            global_rpm: 1000,
            burst_allowance: 5,
            ..Default::default()
        };
        
        let limiter = AdvancedRateLimiter::new(config);
        let ip = "127.0.0.1".parse().unwrap();
        
        // Should allow initial requests
        assert!(limiter.check_rate_limit(ip, None, "test").await.is_ok());
        
        // Test metrics
        let metrics = limiter.get_metrics();
        assert_eq!(metrics.total_requests, 1);
    }

    #[tokio::test]
    async fn test_adaptive_limiter() {
        let mut limiter = AdaptiveLimiter::new(100.0);
        
        // High error rate should reduce limit
        limiter.adjust_rate(0.1);
        assert!(limiter.current_rate() < 100.0);
        
        // Low error rate should increase limit
        limiter.adjust_rate(0.001);
        // Note: May not increase immediately due to adjustment interval
    }
}
