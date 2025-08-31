//! Metrics Collection and Management
//!
//! Provides comprehensive metrics collection for the authentication service,
//! including HTTP metrics, business metrics, and system health indicators.

// use prometheus::{Counter, Encoder, Gauge, Histogram, IntCounter, IntGauge, Registry, TextEncoder};  // Temporarily disabled
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::shared::error::AppError;

/// Metrics collector for the authentication service
#[derive(Clone)]
pub struct MetricsCollector {
    registry: Arc<Registry>,
    start_time: Instant,

    // HTTP metrics
    pub http_requests_total: prometheus::IntCounterVec,
    pub http_request_duration: prometheus::HistogramVec,
    pub http_response_status: prometheus::IntCounterVec,
    pub active_connections: IntGauge,

    // Authentication metrics
    pub auth_attempts_total: IntCounter,
    pub auth_success_total: IntCounter,
    pub auth_failures_total: IntCounter,
    pub auth_duration: Histogram,

    // Authorization metrics
    pub authz_requests_total: IntCounter,
    pub authz_allow_total: IntCounter,
    pub authz_deny_total: IntCounter,
    pub authz_duration: Histogram,

    // Business metrics
    pub users_registered_total: IntCounter,
    pub sessions_created_total: IntCounter,
    pub tokens_issued_total: IntCounter,
    pub tokens_revoked_total: IntCounter,

    // Security metrics
    pub suspicious_activity_total: IntCounter,
    pub rate_limit_exceeded_total: IntCounter,
    pub brute_force_attempts_total: IntCounter,

    // Database metrics
    pub db_connections_active: IntGauge,
    pub db_query_duration: Histogram,
    pub db_errors_total: IntCounter,

    // Cache metrics
    pub cache_hits_total: IntCounter,
    pub cache_misses_total: IntCounter,
    pub cache_evictions_total: IntCounter,

    // System metrics
    pub memory_usage_bytes: IntGauge,
    pub cpu_usage_percent: Gauge,
    pub goroutines_active: IntGauge,

    // Custom metrics storage for dynamic metrics
    custom_metrics: Arc<RwLock<HashMap<String, Box<dyn prometheus::core::Collector>>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Result<Self, AppError> {
        let registry = Arc::new(Registry::new());

        // HTTP metrics
        let http_requests_total = prometheus::IntCounterVec::new(
            prometheus::Opts::new("http_requests_total", "Total number of HTTP requests"),
            &["method", "endpoint", "status"],
        )?;
        registry.register(Box::new(http_requests_total.clone()))?;

        let http_request_duration = prometheus::HistogramVec::new(
            prometheus::HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ]),
            &["method", "endpoint", "status"],
        )?;
        registry.register(Box::new(http_request_duration.clone()))?;

        let http_response_status = prometheus::IntCounterVec::new(
            prometheus::Opts::new("http_response_status_total", "HTTP response status codes"),
            &["status"],
        )?;
        registry.register(Box::new(http_response_status.clone()))?;

        let active_connections =
            IntGauge::new("active_connections", "Number of active client connections")?;
        registry.register(Box::new(active_connections.clone()))?;

        // Authentication metrics
        let auth_attempts_total = IntCounter::new(
            "auth_attempts_total",
            "Total number of authentication attempts",
        )?;
        registry.register(Box::new(auth_attempts_total.clone()))?;

        let auth_success_total = IntCounter::new(
            "auth_success_total",
            "Total number of successful authentications",
        )?;
        registry.register(Box::new(auth_success_total.clone()))?;

        let auth_failures_total = IntCounter::new(
            "auth_failures_total",
            "Total number of failed authentications",
        )?;
        registry.register(Box::new(auth_failures_total.clone()))?;

        let auth_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "auth_duration_seconds",
                "Authentication duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]),
        )?;
        registry.register(Box::new(auth_duration.clone()))?;

        // Authorization metrics
        let authz_requests_total = IntCounter::new(
            "authz_requests_total",
            "Total number of authorization requests",
        )?;
        registry.register(Box::new(authz_requests_total.clone()))?;

        let authz_allow_total = IntCounter::new(
            "authz_allow_total",
            "Total number of allowed authorizations",
        )?;
        registry.register(Box::new(authz_allow_total.clone()))?;

        let authz_deny_total =
            IntCounter::new("authz_deny_total", "Total number of denied authorizations")?;
        registry.register(Box::new(authz_deny_total.clone()))?;

        let authz_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "authz_duration_seconds",
                "Authorization duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25]),
        )?;
        registry.register(Box::new(authz_duration.clone()))?;

        // Business metrics
        let users_registered_total =
            IntCounter::new("users_registered_total", "Total number of users registered")?;
        registry.register(Box::new(users_registered_total.clone()))?;

        let sessions_created_total =
            IntCounter::new("sessions_created_total", "Total number of sessions created")?;
        registry.register(Box::new(sessions_created_total.clone()))?;

        let tokens_issued_total =
            IntCounter::new("tokens_issued_total", "Total number of tokens issued")?;
        registry.register(Box::new(tokens_issued_total.clone()))?;

        let tokens_revoked_total =
            IntCounter::new("tokens_revoked_total", "Total number of tokens revoked")?;
        registry.register(Box::new(tokens_revoked_total.clone()))?;

        // Security metrics
        let suspicious_activity_total = IntCounter::new(
            "suspicious_activity_total",
            "Total number of suspicious activities detected",
        )?;
        registry.register(Box::new(suspicious_activity_total.clone()))?;

        let rate_limit_exceeded_total = IntCounter::new(
            "rate_limit_exceeded_total",
            "Total number of rate limit violations",
        )?;
        registry.register(Box::new(rate_limit_exceeded_total.clone()))?;

        let brute_force_attempts_total = IntCounter::new(
            "brute_force_attempts_total",
            "Total number of brute force attempts detected",
        )?;
        registry.register(Box::new(brute_force_attempts_total.clone()))?;

        // Database metrics
        let db_connections_active = IntGauge::new(
            "db_connections_active",
            "Number of active database connections",
        )?;
        registry.register(Box::new(db_connections_active.clone()))?;

        let db_query_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "db_query_duration_seconds",
                "Database query duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]),
        )?;
        registry.register(Box::new(db_query_duration.clone()))?;

        let db_errors_total =
            IntCounter::new("db_errors_total", "Total number of database errors")?;
        registry.register(Box::new(db_errors_total.clone()))?;

        // Cache metrics
        let cache_hits_total = IntCounter::new("cache_hits_total", "Total number of cache hits")?;
        registry.register(Box::new(cache_hits_total.clone()))?;

        let cache_misses_total =
            IntCounter::new("cache_misses_total", "Total number of cache misses")?;
        registry.register(Box::new(cache_misses_total.clone()))?;

        let cache_evictions_total =
            IntCounter::new("cache_evictions_total", "Total number of cache evictions")?;
        registry.register(Box::new(cache_evictions_total.clone()))?;

        // System metrics
        let memory_usage_bytes = IntGauge::new("memory_usage_bytes", "Memory usage in bytes")?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;

        let cpu_usage_percent = Gauge::new("cpu_usage_percent", "CPU usage percentage")?;
        registry.register(Box::new(cpu_usage_percent.clone()))?;

        let goroutines_active = IntGauge::new("goroutines_active", "Number of active goroutines")?;
        registry.register(Box::new(goroutines_active.clone()))?;

        Ok(Self {
            registry,
            start_time: Instant::now(),
            http_requests_total,
            http_request_duration,
            http_response_status,
            active_connections,
            auth_attempts_total,
            auth_success_total,
            auth_failures_total,
            auth_duration,
            authz_requests_total,
            authz_allow_total,
            authz_deny_total,
            authz_duration,
            users_registered_total,
            sessions_created_total,
            tokens_issued_total,
            tokens_revoked_total,
            suspicious_activity_total,
            rate_limit_exceeded_total,
            brute_force_attempts_total,
            db_connections_active,
            db_query_duration,
            db_errors_total,
            cache_hits_total,
            cache_misses_total,
            cache_evictions_total,
            memory_usage_bytes,
            cpu_usage_percent,
            goroutines_active,
            custom_metrics: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Record HTTP request metrics
    pub fn record_http_request(
        &self,
        method: &str,
        endpoint: &str,
        status: &str,
        duration: Duration,
    ) {
        self.http_requests_total
            .with_label_values(&[method, endpoint, status])
            .inc();
        self.http_request_duration
            .with_label_values(&[method, endpoint, status])
            .observe(duration.as_secs_f64());
        self.http_response_status.with_label_values(&[status]).inc();

        debug!(
            "HTTP request recorded: {} {} {} ({}ms)",
            method,
            endpoint,
            status,
            duration.as_millis()
        );
    }

    /// Record authentication attempt
    pub fn record_auth_attempt(&self, success: bool, duration: Duration) {
        self.auth_attempts_total.inc();
        self.auth_duration.observe(duration.as_secs_f64());

        if success {
            self.auth_success_total.inc();
        } else {
            self.auth_failures_total.inc();
        }

        debug!(
            "Auth attempt recorded: success={}, duration={}ms",
            success,
            duration.as_millis()
        );
    }

    /// Record authorization request
    pub fn record_authz_request(&self, allowed: bool, duration: Duration) {
        self.authz_requests_total.inc();
        self.authz_duration.observe(duration.as_secs_f64());

        if allowed {
            self.authz_allow_total.inc();
        } else {
            self.authz_deny_total.inc();
        }

        debug!(
            "Authz request recorded: allowed={}, duration={}ms",
            allowed,
            duration.as_millis()
        );
    }

    /// Record business metrics
    pub fn record_user_registered(&self) {
        self.users_registered_total.inc();
    }

    pub fn record_session_created(&self) {
        self.sessions_created_total.inc();
    }

    pub fn record_token_issued(&self) {
        self.tokens_issued_total.inc();
    }

    pub fn record_token_revoked(&self) {
        self.tokens_revoked_total.inc();
    }

    /// Record security events
    pub fn record_suspicious_activity(&self) {
        self.suspicious_activity_total.inc();
    }

    pub fn record_rate_limit_exceeded(&self) {
        self.rate_limit_exceeded_total.inc();
    }

    pub fn record_brute_force_attempt(&self) {
        self.brute_force_attempts_total.inc();
    }

    /// Record database metrics
    pub fn record_db_query(&self, duration: Duration) {
        self.db_query_duration.observe(duration.as_secs_f64());
    }

    pub fn record_db_error(&self) {
        self.db_errors_total.inc();
    }

    /// Record cache metrics
    pub fn record_cache_hit(&self) {
        self.cache_hits_total.inc();
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses_total.inc();
    }

    pub fn record_cache_eviction(&self) {
        self.cache_evictions_total.inc();
    }

    /// Update system metrics
    pub fn update_memory_usage(&self, bytes: i64) {
        self.memory_usage_bytes.set(bytes);
    }

    pub fn update_cpu_usage(&self, percent: f64) {
        self.cpu_usage_percent.set(percent);
    }

    pub fn update_active_connections(&self, count: i64) {
        self.active_connections.set(count);
    }

    pub fn update_db_connections(&self, count: i64) {
        self.db_connections_active.set(count);
    }

    /// Get metrics in Prometheus format
    pub fn gather_metrics(&self) -> Result<String, AppError> {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(|e| AppError::Internal(format!("Failed to encode metrics: {}", e)))?;

        String::from_utf8(buffer)
            .map_err(|e| AppError::Internal(format!("Failed to convert metrics to string: {}", e)))
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Get metrics summary for logging
    pub fn get_summary(&self) -> HashMap<String, serde_json::Value> {
        let mut summary = HashMap::new();

        summary.insert("uptime_seconds".to_string(), self.uptime_seconds().into());
        summary.insert(
            "http_requests_total".to_string(),
            self.http_requests_total.get() as i64,
        );
        summary.insert(
            "auth_attempts_total".to_string(),
            self.auth_attempts_total.get() as i64,
        );
        summary.insert(
            "auth_success_total".to_string(),
            self.auth_success_total.get() as i64,
        );
        summary.insert(
            "auth_failures_total".to_string(),
            self.auth_failures_total.get() as i64,
        );
        summary.insert(
            "active_connections".to_string(),
            self.active_connections.get() as i64,
        );

        summary
    }

    /// Register a custom metric
    pub async fn register_custom_metric(
        &self,
        name: String,
        metric: Box<dyn prometheus::core::Collector>,
    ) -> Result<(), AppError> {
        let mut custom_metrics = self.custom_metrics.write().await;

        if custom_metrics.contains_key(&name) {
            return Err(AppError::Validation(format!(
                "Custom metric '{}' already exists",
                name
            )));
        }

        self.registry
            .register(metric.clone())
            .map_err(|e| AppError::Internal(format!("Failed to register custom metric: {}", e)))?;
        custom_metrics.insert(name, metric);

        Ok(())
    }

    /// Unregister a custom metric
    pub async fn unregister_custom_metric(&self, name: &str) -> Result<(), AppError> {
        let mut custom_metrics = self.custom_metrics.write().await;

        if let Some(metric) = custom_metrics.remove(name) {
            // Note: Prometheus doesn't provide a way to unregister metrics
            // The metric will remain in the registry but won't be updated
            debug!(
                "Removed custom metric '{}' from tracking (still registered)",
                name
            );
        }

        Ok(())
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new().expect("Failed to create default metrics collector")
    }
}

/// Middleware for automatic metrics collection
pub struct MetricsMiddleware {
    collector: MetricsCollector,
}

impl MetricsMiddleware {
    pub fn new(collector: MetricsCollector) -> Self {
        Self { collector }
    }

    pub fn collector(&self) -> &MetricsCollector {
        &self.collector
    }
}

/// Helper trait for recording metrics in services
pub trait MetricsRecorder {
    fn record_operation(&self, operation: &str, success: bool, duration: Duration);
    fn increment_counter(&self, metric: &str);
    fn record_histogram(&self, metric: &str, value: f64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_collection() {
        let collector = MetricsCollector::new().unwrap();

        // Test HTTP metrics
        collector.record_http_request("GET", "/health", "200", Duration::from_millis(50));
        collector.record_http_request("POST", "/auth/login", "401", Duration::from_millis(150));

        // Test auth metrics
        collector.record_auth_attempt(true, Duration::from_millis(100));
        collector.record_auth_attempt(false, Duration::from_millis(200));

        // Test authz metrics
        collector.record_authz_request(true, Duration::from_millis(10));
        collector.record_authz_request(false, Duration::from_millis(25));

        // Verify metrics were recorded
        assert_eq!(collector.http_requests_total.get(), 2);
        assert_eq!(collector.auth_attempts_total.get(), 2);
        assert_eq!(collector.auth_success_total.get(), 1);
        assert_eq!(collector.auth_failures_total.get(), 1);
        assert_eq!(collector.authz_requests_total.get(), 2);
        assert_eq!(collector.authz_allow_total.get(), 1);
        assert_eq!(collector.authz_deny_total.get(), 1);
    }

    #[test]
    fn test_business_metrics() {
        let collector = MetricsCollector::new().unwrap();

        collector.record_user_registered();
        collector.record_session_created();
        collector.record_token_issued();
        collector.record_token_revoked();

        assert_eq!(collector.users_registered_total.get(), 1);
        assert_eq!(collector.sessions_created_total.get(), 1);
        assert_eq!(collector.tokens_issued_total.get(), 1);
        assert_eq!(collector.tokens_revoked_total.get(), 1);
    }

    #[test]
    fn test_security_metrics() {
        let collector = MetricsCollector::new().unwrap();

        collector.record_suspicious_activity();
        collector.record_rate_limit_exceeded();
        collector.record_brute_force_attempt();

        assert_eq!(collector.suspicious_activity_total.get(), 1);
        assert_eq!(collector.rate_limit_exceeded_total.get(), 1);
        assert_eq!(collector.brute_force_attempts_total.get(), 1);
    }

    #[tokio::test]
    async fn test_metrics_gathering() {
        let collector = MetricsCollector::new().unwrap();

        // Record some metrics
        collector.record_auth_attempt(true, Duration::from_millis(100));

        // Gather metrics
        let metrics_output = collector.gather_metrics().unwrap();

        // Verify output contains expected metrics
        assert!(metrics_output.contains("auth_attempts_total"));
        assert!(metrics_output.contains("auth_success_total"));
    }
}
