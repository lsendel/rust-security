use axum::{extract::Request, middleware::Next, response::Response};
#[cfg(feature = "monitoring")]
use prometheus::{
    register_histogram, register_int_counter, register_int_gauge, Histogram, IntCounter, IntGauge,
};
use rand::RngCore;
use std::collections::HashMap;
#[cfg(feature = "monitoring")]
use std::sync::LazyLock;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tower::ServiceBuilder;
use tower_http::timeout::TimeoutLayer;

// Configuration constants
#[derive(Debug, Clone)]
pub struct BackpressureConfig {
    // Request body limits per endpoint type
    pub oauth_request_limit: usize,
    pub scim_request_limit: usize,
    pub admin_request_limit: usize,
    pub default_request_limit: usize,

    // Response body limits
    pub max_response_size: usize,

    // Timeout configuration
    pub request_timeout: Duration,
    pub slow_request_threshold: Duration,

    // Concurrency limits
    pub max_concurrent_requests: usize,
    pub max_concurrent_per_ip: usize,

    // Backpressure thresholds
    pub memory_pressure_threshold: usize, // bytes
    pub queue_depth_threshold: usize,

    // Load shedding configuration
    pub load_shed_threshold: f64,   // 0.0 to 1.0
    pub admission_sample_rate: f64, // 0.0 to 1.0
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            oauth_request_limit: 64 * 1024,     // 64KB for OAuth requests
            scim_request_limit: 512 * 1024,     // 512KB for SCIM operations
            admin_request_limit: 128 * 1024,    // 128KB for admin operations
            default_request_limit: 32 * 1024,   // 32KB default
            max_response_size: 2 * 1024 * 1024, // 2MB response limit
            request_timeout: Duration::from_secs(30),
            slow_request_threshold: Duration::from_secs(5),
            max_concurrent_requests: 1000,
            max_concurrent_per_ip: 10,
            memory_pressure_threshold: 100 * 1024 * 1024, // 100MB
            queue_depth_threshold: 100,
            load_shed_threshold: 0.95,
            admission_sample_rate: 1.0,
        }
    }
}

impl BackpressureConfig {
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("OAUTH_REQUEST_LIMIT_KB") {
            if let Ok(kb) = val.parse::<usize>() {
                config.oauth_request_limit = kb * 1024;
            }
        }

        if let Ok(val) = std::env::var("SCIM_REQUEST_LIMIT_KB") {
            if let Ok(kb) = val.parse::<usize>() {
                config.scim_request_limit = kb * 1024;
            }
        }

        if let Ok(val) = std::env::var("DEFAULT_REQUEST_LIMIT_KB") {
            if let Ok(kb) = val.parse::<usize>() {
                config.default_request_limit = kb * 1024;
            }
        }

        if let Ok(val) = std::env::var("MAX_CONCURRENT_REQUESTS") {
            if let Ok(max) = val.parse() {
                config.max_concurrent_requests = max;
            }
        }

        if let Ok(val) = std::env::var("MAX_CONCURRENT_PER_IP") {
            if let Ok(max) = val.parse() {
                config.max_concurrent_per_ip = max;
            }
        }

        if let Ok(val) = std::env::var("REQUEST_TIMEOUT_SECS") {
            if let Ok(secs) = val.parse::<u64>() {
                config.request_timeout = Duration::from_secs(secs);
            }
        }

        if let Ok(val) = std::env::var("LOAD_SHED_THRESHOLD") {
            if let Ok(threshold) = val.parse::<f64>() {
                if (0.0..=1.0).contains(&threshold) {
                    config.load_shed_threshold = threshold;
                }
            }
        }

        config
    }
}

// Metrics (feature-gated)
#[cfg(feature = "monitoring")]
#[allow(dead_code)]
static REQUESTS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!("auth_requests_total", "Total number of requests")
        .expect("Failed to create requests_total counter")
});

#[cfg(feature = "monitoring")]
#[allow(dead_code)]
static REQUESTS_REJECTED_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "auth_requests_rejected_total",
        "Total number of rejected requests"
    )
    .unwrap()
});

#[cfg(feature = "monitoring")]
#[allow(dead_code)]
static CONCURRENT_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "auth_concurrent_requests",
        "Current number of concurrent requests"
    )
    .unwrap()
});

#[cfg(feature = "monitoring")]
#[allow(dead_code)]
static REQUEST_BODY_SIZE: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!("auth_request_body_size_bytes", "Request body size in bytes").unwrap()
});

#[cfg(feature = "monitoring")]
static REQUEST_DURATION: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "auth_request_duration_seconds",
        "Request duration in seconds"
    )
    .unwrap()
});

#[cfg(feature = "monitoring")]
#[allow(dead_code)]
static QUEUE_DEPTH: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!("auth_request_queue_depth", "Current request queue depth").unwrap()
});

// Metrics helper functions
#[cfg(feature = "monitoring")]
#[inline]
const fn inc_requests_total() {
    // TODO: Implement actual metrics increment
    // METRICS.requests_total.inc();
}
#[cfg(not(feature = "monitoring"))]
#[inline]
const fn inc_requests_total() {}

#[cfg(feature = "monitoring")]
#[inline]
const fn inc_requests_rejected_total() {
    // TODO: Implement actual metrics increment
    // METRICS.requests_rejected_total.inc();
}
#[cfg(not(feature = "monitoring"))]
#[inline]
const fn inc_requests_rejected_total() {}

#[cfg(feature = "monitoring")]
#[inline]
const fn inc_concurrent_requests() {
    // TODO: Implement actual metrics increment
    // METRICS.concurrent_requests.inc();
}
#[cfg(not(feature = "monitoring"))]
#[inline]
const fn inc_concurrent_requests() {}

#[cfg(feature = "monitoring")]
#[inline]
const fn dec_concurrent_requests() {
    // TODO: Implement actual metrics decrement
    // METRICS.concurrent_requests.dec();
}
#[cfg(not(feature = "monitoring"))]
#[inline]
const fn dec_concurrent_requests() {}

#[cfg(feature = "monitoring")]
#[inline]
const fn observe_request_body_size(_size: f64) {
    // TODO: Implement actual metrics observation
    // METRICS.request_body_size.observe(size);
}
#[cfg(not(feature = "monitoring"))]
#[inline]
const fn observe_request_body_size(_size: f64) {}

#[cfg(feature = "monitoring")]
#[inline]
fn observe_request_duration(duration: f64) {
    REQUEST_DURATION.observe(duration);
}
#[cfg(not(feature = "monitoring"))]
#[inline]
const fn observe_request_duration(_duration: f64) {}

// Backpressure state tracking
#[derive(Debug)]
pub struct BackpressureState {
    concurrent_requests: AtomicUsize,
    queue_depth: AtomicUsize,
    memory_usage: AtomicUsize,
    last_load_check: Mutex<Instant>,
    per_ip_counters: Mutex<HashMap<String, AtomicUsize>>,
    config: BackpressureConfig,
}

impl BackpressureState {
    #[must_use]
    pub fn new(config: BackpressureConfig) -> Self {
        Self {
            concurrent_requests: AtomicUsize::new(0),
            queue_depth: AtomicUsize::new(0),
            memory_usage: AtomicUsize::new(0),
            last_load_check: Mutex::new(Instant::now()),
            per_ip_counters: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Determine if a request should be admitted based on backpressure policies
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError` if:
    /// - Server is at maximum concurrent request capacity
    /// - Client IP has exceeded per-IP rate limits
    /// - Request should be rejected due to backpressure
    pub fn should_admit_request(
        &self,
        client_ip: &str,
    ) -> Result<(), crate::shared::error::AppError> {
        // Check global concurrent request limit
        let current_concurrent = self.concurrent_requests.load(Ordering::Relaxed);
        if current_concurrent >= self.config.max_concurrent_requests {
            inc_requests_rejected_total();
            return Err(crate::shared::error::AppError::ServiceUnavailable {
                reason: "Server is at capacity".to_string(),
            });
        }

        // Check per-IP limit
        {
            let mut counters = self.per_ip_counters.lock().unwrap();
            let ip_counter = counters
                .entry(client_ip.to_string())
                .or_insert_with(|| AtomicUsize::new(0));

            let ip_concurrent = ip_counter.load(Ordering::Relaxed);
            if ip_concurrent >= self.config.max_concurrent_per_ip {
                inc_requests_rejected_total();
                return Err(crate::shared::error::AppError::ServiceUnavailable {
                    reason: "Too many concurrent requests from this IP".to_string(),
                });
            }
        }

        // Check queue depth
        let queue_depth = self.queue_depth.load(Ordering::Relaxed);
        if queue_depth >= self.config.queue_depth_threshold {
            inc_requests_rejected_total();
            return Err(crate::shared::error::AppError::ServiceUnavailable {
                reason: "Request queue is full".to_string(),
            });
        }

        // Check memory pressure
        let memory_usage = self.memory_usage.load(Ordering::Relaxed);
        if memory_usage >= self.config.memory_pressure_threshold {
            inc_requests_rejected_total();
            return Err(crate::shared::error::AppError::ServiceUnavailable {
                reason: "Server memory pressure".to_string(),
            });
        }

        // Load shedding with sampling
        let load_ratio = current_concurrent as f64 / self.config.max_concurrent_requests as f64;
        if load_ratio >= self.config.load_shed_threshold {
            // Probabilistic admission control
            let admit_probability = 1.0
                - ((load_ratio - self.config.load_shed_threshold)
                    / (1.0 - self.config.load_shed_threshold));

            // Use cryptographically secure random for security-critical load shedding decisions
            let mut rng = rand::rngs::OsRng;
            let random_value = rng.next_u64() as f64 / u64::MAX as f64;
            if random_value > admit_probability {
                inc_requests_rejected_total();
                return Err(crate::shared::error::AppError::ServiceUnavailable {
                    reason: "Load shedding active".to_string(),
                });
            }
        }

        Ok(())
    }

    pub fn on_request_start(&self, client_ip: &str) {
        self.concurrent_requests.fetch_add(1, Ordering::Relaxed);
        inc_concurrent_requests();
        inc_requests_total();

        // Increment per-IP counter
        let mut counters = self.per_ip_counters.lock().unwrap();
        let ip_counter = counters
            .entry(client_ip.to_string())
            .or_insert_with(|| AtomicUsize::new(0));
        ip_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_request_end(&self, client_ip: &str) {
        self.concurrent_requests.fetch_sub(1, Ordering::Relaxed);
        dec_concurrent_requests();

        // Decrement per-IP counter
        let mut counters = self.per_ip_counters.lock().unwrap();
        if let Some(ip_counter) = counters.get(client_ip) {
            ip_counter.fetch_sub(1, Ordering::Relaxed);
        }

        // Cleanup IP counters periodically (simple cleanup)
        let mut last_check = self.last_load_check.lock().unwrap();
        if last_check.elapsed() > Duration::from_secs(300) {
            // 5 minutes
            counters.retain(|_, counter| counter.load(Ordering::Relaxed) > 0);
            *last_check = Instant::now();
        }
    }

    pub fn update_memory_usage(&self, bytes: usize) {
        self.memory_usage.store(bytes, Ordering::Relaxed);
    }

    pub fn stats(&self) -> BackpressureStats {
        BackpressureStats {
            concurrent_requests: self.concurrent_requests.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            memory_usage: self.memory_usage.load(Ordering::Relaxed),
            per_ip_active_connections: {
                let counters = self.per_ip_counters.lock().unwrap();
                counters.len()
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackpressureStats {
    pub concurrent_requests: usize,
    pub queue_depth: usize,
    pub memory_usage: usize,
    pub per_ip_active_connections: usize,
}

// Middleware for backpressure and limits
pub async fn backpressure_middleware(
    axum::extract::State(state): axum::extract::State<Arc<BackpressureState>>,
    request: Request,
    next: Next,
) -> Result<Response, crate::shared::error::AppError> {
    let start_time = Instant::now();

    // Extract client IP (simplified - in production, use proper IP extraction)
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .split(',')
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_string();

    // Admission control
    state.should_admit_request(&client_ip)?;

    // Track request start
    state.on_request_start(&client_ip);

    // Record request body size if present
    if let Some(content_length) = request.headers().get("content-length") {
        if let Ok(size_str) = content_length.to_str() {
            if let Ok(size) = size_str.parse::<f64>() {
                observe_request_body_size(size);
            }
        }
    }

    // Process request with timeout
    let result = timeout(state.config.request_timeout, next.run(request)).await;

    // Track request end
    state.on_request_end(&client_ip);

    // Record metrics
    let duration = start_time.elapsed();
    observe_request_duration(duration.as_secs_f64());

    // Log slow requests
    if duration >= state.config.slow_request_threshold {
        tracing::warn!(
            duration = ?duration,
            client_ip = %client_ip,
            "Slow request detected"
        );
    }

    match result {
        Ok(response) => Ok(response),
        Err(_) => Err(crate::shared::error::AppError::TimeoutError),
    }
}

// Request body size limit based on endpoint
#[must_use]
pub fn get_request_body_limit(path: &str, config: &BackpressureConfig) -> usize {
    if path.starts_with("/oauth") || path.starts_with("/auth") {
        config.oauth_request_limit
    } else if path.starts_with("/scim") {
        config.scim_request_limit
    } else if path.starts_with("/admin") {
        config.admin_request_limit
    } else {
        config.default_request_limit
    }
}

// Create comprehensive backpressure middleware stack
#[must_use]
pub fn create_backpressure_middleware(
    config: BackpressureConfig,
) -> (
    ServiceBuilder<tower::layer::util::Stack<TimeoutLayer, tower::layer::util::Identity>>,
    Arc<BackpressureState>,
) {
    let state = Arc::new(BackpressureState::new(config.clone()));

    let middleware = ServiceBuilder::new().layer(TimeoutLayer::new(config.request_timeout));

    (middleware, state)
}

// Adaptive request body limit middleware
pub async fn adaptive_body_limit_middleware(
    request: Request,
    next: Next,
) -> Result<Response, crate::shared::error::AppError> {
    let config = BackpressureConfig::from_env();
    let path = request.uri().path();

    let limit = get_request_body_limit(path, &config);

    // Check content-length header
    if let Some(content_length) = request.headers().get("content-length") {
        if let Ok(size_str) = content_length.to_str() {
            if let Ok(size) = size_str.parse::<usize>() {
                if size > limit {
                    return Err(crate::shared::error::AppError::ValidationError);
                }
            }
        }
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_backpressure_config_defaults() {
        let config = BackpressureConfig::default();
        assert_eq!(config.oauth_request_limit, 64 * 1024);
        assert_eq!(config.scim_request_limit, 512 * 1024);
        assert_eq!(config.max_concurrent_requests, 1000);
        assert!((0.0..=1.0).contains(&config.load_shed_threshold));
    }

    #[tokio::test]
    async fn test_admission_control() {
        let config = BackpressureConfig {
            max_concurrent_requests: 2,
            max_concurrent_per_ip: 1,
            ..Default::default()
        };

        let state = BackpressureState::new(config);

        // First request should be admitted
        assert!(state.should_admit_request("192.168.1.1").is_ok());
        state.on_request_start("192.168.1.1");

        // Second request from same IP should be rejected
        assert!(state.should_admit_request("192.168.1.1").is_err());

        // Request from different IP should be admitted
        assert!(state.should_admit_request("192.168.1.2").is_ok());
        state.on_request_start("192.168.1.2");

        // Third request should be rejected (global limit)
        assert!(state.should_admit_request("192.168.1.3").is_err());

        // Clean up
        state.on_request_end("192.168.1.1");
        state.on_request_end("192.168.1.2");
    }

    #[test]
    fn test_request_body_limits() {
        let config = BackpressureConfig::default();

        assert_eq!(
            get_request_body_limit("/oauth/token", &config),
            config.oauth_request_limit
        );
        assert_eq!(
            get_request_body_limit("/scim/Users", &config),
            config.scim_request_limit
        );
        assert_eq!(
            get_request_body_limit("/admin/metrics", &config),
            config.admin_request_limit
        );
        assert_eq!(
            get_request_body_limit("/health", &config),
            config.default_request_limit
        );
    }

    #[tokio::test]
    async fn test_state_stats() {
        let config = BackpressureConfig::default();
        let state = BackpressureState::new(config);

        state.on_request_start("192.168.1.1");
        state.on_request_start("192.168.1.2");

        let backpressure_stats = state.stats();
        assert_eq!(backpressure_stats.concurrent_requests, 2);
        assert_eq!(backpressure_stats.per_ip_active_connections, 2);

        state.on_request_end("192.168.1.1");
        let updated_backpressure_stats = state.stats();
        assert_eq!(updated_backpressure_stats.concurrent_requests, 1);
    }
}
