//! DoS protection module for preventing resource exhaustion attacks
//!
//! Provides rate limiting, input size limits, and resource guards

use crate::error_handling::{SecureResult, SecurityError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::sleep;

/// DoS protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoSConfig {
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,

    /// Input size limits
    pub size_limits: SizeLimitConfig,

    /// Resource limits
    pub resource_limits: ResourceLimitConfig,

    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,

    /// Whether to enable adaptive limits
    pub adaptive_limits: bool,

    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per window per IP
    pub requests_per_window: u32,

    /// Time window duration
    pub window_duration: Duration,

    /// Burst allowance
    pub burst_allowance: u32,

    /// Global requests per second limit
    pub global_rps_limit: Option<u32>,

    /// Per-endpoint specific limits
    pub endpoint_limits: HashMap<String, u32>,

    /// User-based limits (higher limits for authenticated users)
    pub user_limits: HashMap<String, u32>,
}

/// Input size limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeLimitConfig {
    /// Maximum request body size
    pub max_body_size: usize,

    /// Maximum individual field size
    pub max_field_size: usize,

    /// Maximum number of fields
    pub max_field_count: usize,

    /// Maximum JSON/XML nesting depth
    pub max_nesting_depth: usize,

    /// Maximum array/collection size
    pub max_collection_size: usize,

    /// Maximum header size
    pub max_header_size: usize,

    /// Maximum URL length
    pub max_url_length: usize,
}

/// Resource limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitConfig {
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,

    /// Maximum validation operations per request
    pub max_validation_ops: usize,

    /// Maximum processing time per request
    pub max_processing_time: Duration,

    /// Maximum memory usage per request (bytes)
    pub max_memory_per_request: usize,

    /// Maximum CPU time per request (milliseconds)
    pub max_cpu_time: Duration,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open circuit
    pub failure_threshold: u32,

    /// Time window for failure counting
    pub failure_window: Duration,

    /// Recovery timeout (half-open state)
    pub recovery_timeout: Duration,

    /// Success threshold to close circuit
    pub success_threshold: u32,
}

impl Default for DoSConfig {
    fn default() -> Self {
        Self::production()
    }
}

impl DoSConfig {
    /// Production configuration with strict limits
    pub fn production() -> Self {
        Self {
            rate_limit: RateLimitConfig {
                requests_per_window: 100,
                window_duration: Duration::from_secs(60),
                burst_allowance: 20,
                global_rps_limit: Some(1000),
                endpoint_limits: HashMap::new(),
                user_limits: HashMap::new(),
            },
            size_limits: SizeLimitConfig {
                max_body_size: 1024 * 1024, // 1MB
                max_field_size: 64 * 1024,  // 64KB
                max_field_count: 100,
                max_nesting_depth: 10,
                max_collection_size: 1000,
                max_header_size: 8192,
                max_url_length: 2048,
            },
            resource_limits: ResourceLimitConfig {
                max_concurrent_requests: 1000,
                max_validation_ops: 100,
                max_processing_time: Duration::from_secs(10),
                max_memory_per_request: 10 * 1024 * 1024, // 10MB
                max_cpu_time: Duration::from_millis(1000),
            },
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 50,
                failure_window: Duration::from_secs(60),
                recovery_timeout: Duration::from_secs(30),
                success_threshold: 10,
            },
            adaptive_limits: true,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Development configuration with relaxed limits
    pub fn development() -> Self {
        let mut config = Self::production();
        config.rate_limit.requests_per_window = 1000;
        config.size_limits.max_body_size = 10 * 1024 * 1024; // 10MB
        config.resource_limits.max_concurrent_requests = 10000;
        config.resource_limits.max_processing_time = Duration::from_secs(60);
        config
    }
}

/// Rate limiter implementation using token bucket algorithm
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<DashMap<String, TokenBucket>>,
    global_bucket: Arc<Mutex<TokenBucket>>,
    last_cleanup: Arc<Mutex<Instant>>,
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: f64,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: Instant::now(),
            capacity: capacity as f64,
            refill_rate,
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

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let global_bucket = if let Some(global_limit) = config.global_rps_limit {
            TokenBucket::new(global_limit, global_limit as f64)
        } else {
            TokenBucket::new(u32::MAX, f64::MAX)
        };

        Self {
            config,
            buckets: Arc::new(DashMap::new()),
            global_bucket: Arc::new(Mutex::new(global_bucket)),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Check if request is allowed for the given identifier
    pub async fn check_rate_limit(&self, identifier: &str) -> SecureResult<()> {
        // Check global rate limit first
        {
            let mut global_bucket = self.global_bucket.lock().await;
            if !global_bucket.try_consume(1.0) {
                return Err(SecurityError::RateLimitExceeded);
            }
        }

        // Check per-identifier limit
        let rate =
            self.config.requests_per_window as f64 / self.config.window_duration.as_secs_f64();
        let capacity = self.config.requests_per_window + self.config.burst_allowance;

        let mut bucket = self
            .buckets
            .entry(identifier.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, rate));

        if bucket.try_consume(1.0) {
            Ok(())
        } else {
            Err(SecurityError::RateLimitExceeded)
        }
    }

    /// Check rate limit with custom token cost
    pub async fn check_rate_limit_with_cost(
        &self,
        identifier: &str,
        cost: f64,
    ) -> SecureResult<()> {
        // Check global rate limit
        {
            let mut global_bucket = self.global_bucket.lock().await;
            if !global_bucket.try_consume(cost) {
                return Err(SecurityError::RateLimitExceeded);
            }
        }

        // Check per-identifier limit
        let rate =
            self.config.requests_per_window as f64 / self.config.window_duration.as_secs_f64();
        let capacity = self.config.requests_per_window + self.config.burst_allowance;

        let mut bucket = self
            .buckets
            .entry(identifier.to_string())
            .or_insert_with(|| TokenBucket::new(capacity, rate));

        if bucket.try_consume(cost) {
            Ok(())
        } else {
            Err(SecurityError::RateLimitExceeded)
        }
    }

    /// Get remaining tokens for identifier
    pub async fn get_remaining_tokens(&self, identifier: &str) -> f64 {
        if let Some(mut bucket) = self.buckets.get_mut(identifier) {
            bucket.refill();
            bucket.tokens
        } else {
            self.config.requests_per_window as f64
        }
    }

    /// Cleanup expired buckets
    pub async fn cleanup_expired(&self) {
        let mut last_cleanup = self.last_cleanup.lock().await;
        if last_cleanup.elapsed() < Duration::from_secs(300) {
            return;
        }

        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_refill) < self.config.window_duration * 2
        });

        *last_cleanup = now;
    }
}

/// Input size limiter
#[derive(Debug)]
pub struct InputSizeLimiter {
    config: SizeLimitConfig,
}

impl InputSizeLimiter {
    pub fn new(config: SizeLimitConfig) -> Self {
        Self { config }
    }

    /// Check if body size is within limits
    pub fn check_body_size(&self, size: usize) -> SecureResult<()> {
        if size > self.config.max_body_size {
            Err(SecurityError::SizeLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Check if field size is within limits
    pub fn check_field_size(&self, size: usize) -> SecureResult<()> {
        if size > self.config.max_field_size {
            Err(SecurityError::SizeLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Check if field count is within limits
    pub fn check_field_count(&self, count: usize) -> SecureResult<()> {
        if count > self.config.max_field_count {
            Err(SecurityError::SizeLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Check nesting depth for structured data
    pub fn check_nesting_depth(&self, depth: usize) -> SecureResult<()> {
        if depth > self.config.max_nesting_depth {
            Err(SecurityError::SizeLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Check collection size
    pub fn check_collection_size(&self, size: usize) -> SecureResult<()> {
        if size > self.config.max_collection_size {
            Err(SecurityError::SizeLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Check URL length
    pub fn check_url_length(&self, length: usize) -> SecureResult<()> {
        if length > self.config.max_url_length {
            Err(SecurityError::SizeLimitExceeded)
        } else {
            Ok(())
        }
    }

    /// Validate JSON structure size and depth
    pub fn validate_json_structure(&self, json_str: &str) -> SecureResult<()> {
        let value: serde_json::Value =
            serde_json::from_str(json_str).map_err(|_| SecurityError::MalformedInput)?;

        self.check_json_depth(&value, 0)?;
        self.check_json_size(&value)?;

        Ok(())
    }

    fn check_json_depth(
        &self,
        value: &serde_json::Value,
        current_depth: usize,
    ) -> SecureResult<()> {
        if current_depth > self.config.max_nesting_depth {
            return Err(SecurityError::SizeLimitExceeded);
        }

        match value {
            serde_json::Value::Object(obj) => {
                for (_, v) in obj {
                    self.check_json_depth(v, current_depth + 1)?;
                }
            }
            serde_json::Value::Array(arr) => {
                self.check_collection_size(arr.len())?;
                for v in arr {
                    self.check_json_depth(v, current_depth + 1)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn check_json_size(&self, value: &serde_json::Value) -> SecureResult<()> {
        match value {
            serde_json::Value::String(s) => self.check_field_size(s.len())?,
            serde_json::Value::Object(obj) => {
                self.check_field_count(obj.len())?;
                for (key, val) in obj {
                    self.check_field_size(key.len())?;
                    self.check_json_size(val)?;
                }
            }
            serde_json::Value::Array(arr) => {
                self.check_collection_size(arr.len())?;
                for val in arr {
                    self.check_json_size(val)?;
                }
            }
            _ => {}
        }

        Ok(())
    }
}

/// Resource guard for managing concurrent resources
#[derive(Debug)]
pub struct ResourceGuard {
    config: ResourceLimitConfig,
    request_semaphore: Arc<Semaphore>,
    validation_semaphore: Arc<Semaphore>,
    active_requests: Arc<AtomicU64>,
}

impl ResourceGuard {
    pub fn new(config: ResourceLimitConfig) -> Self {
        Self {
            request_semaphore: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            validation_semaphore: Arc::new(Semaphore::new(config.max_validation_ops)),
            active_requests: Arc::new(AtomicU64::new(0)),
            config,
        }
    }

    /// Acquire a request permit
    pub async fn acquire_request_permit(&self) -> SecureResult<RequestPermit> {
        let permit = self
            .request_semaphore
            .acquire()
            .await
            .map_err(|_| SecurityError::ResourceExhaustion)?;

        self.active_requests.fetch_add(1, Ordering::Relaxed);

        Ok(RequestPermit {
            _permit: permit,
            active_requests: Arc::clone(&self.active_requests),
            max_processing_time: self.config.max_processing_time,
            start_time: Instant::now(),
        })
    }

    /// Acquire a validation permit
    pub async fn acquire_validation_permit(&self) -> SecureResult<ValidationPermit> {
        let permit = self
            .validation_semaphore
            .acquire()
            .await
            .map_err(|_| SecurityError::ResourceExhaustion)?;

        Ok(ValidationPermit {
            _permit: permit,
            max_cpu_time: self.config.max_cpu_time,
            start_time: Instant::now(),
        })
    }

    /// Get current resource usage statistics
    pub fn get_stats(&self) -> ResourceStats {
        ResourceStats {
            active_requests: self.active_requests.load(Ordering::Relaxed),
            available_request_permits: self.request_semaphore.available_permits(),
            available_validation_permits: self.validation_semaphore.available_permits(),
        }
    }
}

/// Request processing permit
pub struct RequestPermit {
    _permit: tokio::sync::SemaphorePermit<'static>,
    active_requests: Arc<AtomicU64>,
    max_processing_time: Duration,
    start_time: Instant,
}

impl RequestPermit {
    /// Check if processing time limit is exceeded
    pub fn check_time_limit(&self) -> SecureResult<()> {
        if self.start_time.elapsed() > self.max_processing_time {
            Err(SecurityError::ResourceExhaustion)
        } else {
            Ok(())
        }
    }

    /// Get elapsed processing time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        self.active_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Validation operation permit
pub struct ValidationPermit {
    _permit: tokio::sync::SemaphorePermit<'static>,
    max_cpu_time: Duration,
    start_time: Instant,
}

impl ValidationPermit {
    /// Check if CPU time limit is exceeded
    pub fn check_cpu_time_limit(&self) -> SecureResult<()> {
        if self.start_time.elapsed() > self.max_cpu_time {
            Err(SecurityError::ResourceExhaustion)
        } else {
            Ok(())
        }
    }
}

/// Resource usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceStats {
    pub active_requests: u64,
    pub available_request_permits: usize,
    pub available_validation_permits: usize,
}

/// Circuit breaker for preventing cascade failures
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitState>>,
    failure_count: Arc<AtomicU64>,
    success_count: Arc<AtomicU64>,
    last_failure_time: Arc<Mutex<Option<Instant>>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing, rejecting requests
    HalfOpen, // Testing if service recovered
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: Arc::new(AtomicU64::new(0)),
            success_count: Arc::new(AtomicU64::new(0)),
            last_failure_time: Arc::new(Mutex::new(None)),
        }
    }

    /// Check if request should be allowed
    pub async fn check_request(&self) -> SecureResult<()> {
        let state = *self.state.read().await;

        match state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if we should transition to half-open
                if let Some(last_failure) = *self.last_failure_time.lock().await {
                    if last_failure.elapsed() > self.config.recovery_timeout {
                        *self.state.write().await = CircuitState::HalfOpen;
                        self.success_count.store(0, Ordering::Relaxed);
                        Ok(())
                    } else {
                        Err(SecurityError::ResourceExhaustion)
                    }
                } else {
                    Err(SecurityError::ResourceExhaustion)
                }
            }
            CircuitState::HalfOpen => Ok(()),
        }
    }

    /// Record a successful operation
    pub async fn record_success(&self) {
        let state = *self.state.read().await;

        match state {
            CircuitState::HalfOpen => {
                let success_count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if success_count >= self.config.success_threshold as u64 {
                    *self.state.write().await = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::Relaxed);
                }
            }
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Record a failed operation
    pub async fn record_failure(&self) {
        let failure_count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        *self.last_failure_time.lock().await = Some(Instant::now());

        if failure_count >= self.config.failure_threshold as u64 {
            *self.state.write().await = CircuitState::Open;
        }
    }

    /// Get current circuit state
    pub async fn get_state(&self) -> CircuitState {
        *self.state.read().await
    }
}

/// DoS protection metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionMetrics {
    pub rate_limit_violations: u64,
    pub size_limit_violations: u64,
    pub resource_exhaustion_events: u64,
    pub circuit_breaker_trips: u64,
    pub active_requests: u64,
    pub total_requests: u64,
    pub avg_response_time_ms: f64,
}

/// Main DoS protection coordinator
#[derive(Debug)]
pub struct DoSProtection {
    config: DoSConfig,
    rate_limiter: RateLimiter,
    size_limiter: InputSizeLimiter,
    resource_guard: ResourceGuard,
    circuit_breaker: CircuitBreaker,
    metrics: Arc<Mutex<ProtectionMetrics>>,
}

impl DoSProtection {
    pub fn new(config: DoSConfig) -> Self {
        Self {
            rate_limiter: RateLimiter::new(config.rate_limit.clone()),
            size_limiter: InputSizeLimiter::new(config.size_limits.clone()),
            resource_guard: ResourceGuard::new(config.resource_limits.clone()),
            circuit_breaker: CircuitBreaker::new(config.circuit_breaker.clone()),
            metrics: Arc::new(Mutex::new(ProtectionMetrics {
                rate_limit_violations: 0,
                size_limit_violations: 0,
                resource_exhaustion_events: 0,
                circuit_breaker_trips: 0,
                active_requests: 0,
                total_requests: 0,
                avg_response_time_ms: 0.0,
            })),
            config,
        }
    }

    /// Check all DoS protection rules for a request
    pub async fn check_request(
        &self,
        identifier: &str,
        body_size: usize,
    ) -> SecureResult<RequestGuard> {
        // Check circuit breaker first
        self.circuit_breaker.check_request().await?;

        // Check rate limits
        if let Err(e) = self.rate_limiter.check_rate_limit(identifier).await {
            let mut metrics = self.metrics.lock().await;
            metrics.rate_limit_violations += 1;
            return Err(e);
        }

        // Check size limits
        if let Err(e) = self.size_limiter.check_body_size(body_size) {
            let mut metrics = self.metrics.lock().await;
            metrics.size_limit_violations += 1;
            return Err(e);
        }

        // Acquire resource permits
        let request_permit = match self.resource_guard.acquire_request_permit().await {
            Ok(permit) => permit,
            Err(e) => {
                let mut metrics = self.metrics.lock().await;
                metrics.resource_exhaustion_events += 1;
                return Err(e);
            }
        };

        // Update metrics
        {
            let mut metrics = self.metrics.lock().await;
            metrics.total_requests += 1;
            metrics.active_requests = self.resource_guard.get_stats().active_requests;
        }

        Ok(RequestGuard {
            request_permit,
            circuit_breaker: Arc::clone(&self.circuit_breaker),
            metrics: Arc::clone(&self.metrics),
            start_time: Instant::now(),
        })
    }

    /// Get current protection metrics
    pub async fn get_metrics(&self) -> ProtectionMetrics {
        self.metrics.lock().await.clone()
    }

    /// Cleanup expired rate limit entries
    pub async fn cleanup(&self) {
        self.rate_limiter.cleanup_expired().await;
    }

    /// Get rate limiter
    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }

    /// Get size limiter
    pub fn size_limiter(&self) -> &InputSizeLimiter {
        &self.size_limiter
    }

    /// Get resource guard
    pub fn resource_guard(&self) -> &ResourceGuard {
        &self.resource_guard
    }
}

/// Request guard that tracks request lifecycle
pub struct RequestGuard {
    request_permit: RequestPermit,
    circuit_breaker: Arc<CircuitBreaker>,
    metrics: Arc<Mutex<ProtectionMetrics>>,
    start_time: Instant,
}

impl RequestGuard {
    /// Record successful completion
    pub async fn record_success(self) {
        let duration = self.start_time.elapsed();
        self.circuit_breaker.record_success().await;

        let mut metrics = self.metrics.lock().await;
        let total = metrics.total_requests as f64;
        metrics.avg_response_time_ms =
            (metrics.avg_response_time_ms * (total - 1.0) + duration.as_millis() as f64) / total;
    }

    /// Record failed completion
    pub async fn record_failure(self) {
        let duration = self.start_time.elapsed();
        self.circuit_breaker.record_failure().await;

        let mut metrics = self.metrics.lock().await;
        let total = metrics.total_requests as f64;
        metrics.avg_response_time_ms =
            (metrics.avg_response_time_ms * (total - 1.0) + duration.as_millis() as f64) / total;
    }

    /// Check if time limit is exceeded
    pub fn check_time_limit(&self) -> SecureResult<()> {
        self.request_permit.check_time_limit()
    }

    /// Get elapsed processing time
    pub fn elapsed(&self) -> Duration {
        self.request_permit.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let prod_config = DoSConfig::production();
        let dev_config = DoSConfig::development();

        assert!(
            prod_config.rate_limit.requests_per_window < dev_config.rate_limit.requests_per_window
        );
        assert!(prod_config.size_limits.max_body_size < dev_config.size_limits.max_body_size);
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let config = RateLimitConfig {
            requests_per_window: 5,
            window_duration: Duration::from_secs(1),
            burst_allowance: 2,
            global_rps_limit: None,
            endpoint_limits: HashMap::new(),
            user_limits: HashMap::new(),
        };

        let _limiter = RateLimiter::new(config);

        // Should allow initial requests
        for _ in 0..7 {
            assert!(limiter.check_rate_limit("test_ip").await.is_ok());
        }

        // Should reject after limit exceeded
        assert!(limiter.check_rate_limit("test_ip").await.is_err());
    }

    #[test]
    fn test_size_limiter() {
        let config = SizeLimitConfig {
            max_body_size: 1000,
            max_field_size: 100,
            max_field_count: 10,
            max_nesting_depth: 5,
            max_collection_size: 20,
            max_header_size: 500,
            max_url_length: 200,
        };

        let _limiter = InputSizeLimiter::new(config);

        assert!(limiter.check_body_size(500).is_ok());
        assert!(limiter.check_body_size(1500).is_err());

        assert!(limiter.check_field_count(5).is_ok());
        assert!(limiter.check_field_count(15).is_err());
    }

    #[tokio::test]
    async fn test_resource_guard() {
        let config = ResourceLimitConfig {
            max_concurrent_requests: 2,
            max_validation_ops: 5,
            max_processing_time: Duration::from_secs(1),
            max_memory_per_request: 1024,
            max_cpu_time: Duration::from_millis(100),
        };

        let guard = ResourceGuard::new(config);

        let permit1 = guard.acquire_request_permit().await.unwrap();
        let permit2 = guard.acquire_request_permit().await.unwrap();

        // Third request should succeed but will be waiting
        let permit3_future = guard.acquire_request_permit();

        // Drop first permit to allow third request
        drop(permit1);
        let _permit3 = permit3_future.await.unwrap();

        let stats = guard.get_stats();
        assert_eq!(stats.active_requests, 2);
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            failure_window: Duration::from_secs(60),
            recovery_timeout: Duration::from_millis(100),
            success_threshold: 2,
        };

        let breaker = CircuitBreaker::new(config);

        // Should allow requests initially
        assert!(breaker.check_request().await.is_ok());

        // Record failures to trip the breaker
        for _ in 0..3 {
            breaker.record_failure().await;
        }

        // Should reject requests when open
        assert!(breaker.check_request().await.is_err());

        // Wait for recovery timeout
        sleep(Duration::from_millis(150)).await;

        // Should allow one request in half-open state
        assert!(breaker.check_request().await.is_ok());
    }

    #[tokio::test]
    async fn test_dos_protection_integration() {
        let config = DoSConfig::development();
        let protection = DoSProtection::new(config);

        let guard = protection.check_request("test_ip", 500).await.unwrap();
        assert!(guard.check_time_limit().is_ok());

        guard.record_success().await;

        let metrics = protection.get_metrics().await;
        assert_eq!(metrics.total_requests, 1);
    }
}
