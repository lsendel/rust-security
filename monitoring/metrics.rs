//! Production monitoring and metrics collection
//!
//! This module provides comprehensive metrics collection for production monitoring,
//! including SLO tracking, error budgets, and performance regression detection.

use prometheus::{Encoder, Gauge, Histogram, IntCounter, IntGauge, Registry, TextEncoder};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Production metrics registry
#[derive(Clone)]
pub struct ProductionMetrics {
    registry: Arc<Registry>,
    start_time: Instant,

    // Authentication metrics
    pub auth_requests_total: IntCounter,
    pub auth_success_total: IntCounter,
    pub auth_failures_total: IntCounter,
    pub auth_duration_seconds: Histogram,

    // Authorization metrics
    pub authz_requests_total: IntCounter,
    pub authz_allow_total: IntCounter,
    pub authz_deny_total: IntCounter,
    pub authz_duration_seconds: Histogram,

    // Rate limiting metrics
    pub rate_limit_hits: IntCounter,
    pub rate_limit_exceeded: IntCounter,

    // Connection pool metrics
    pub pool_connections_active: IntGauge,
    pub pool_connections_total: IntGauge,
    pub pool_acquisition_duration: Histogram,

    // Error metrics
    pub errors_total: IntCounter,
    pub errors_by_type: prometheus::IntCounterVec,

    // Performance metrics
    pub request_duration_seconds: prometheus::HistogramVec,
    pub active_connections: IntGauge,
    pub memory_usage_bytes: IntGauge,

    // SLO tracking
    pub slo_auth_latency_budget_remaining: Gauge,
    pub slo_authz_latency_budget_remaining: Gauge,
    pub slo_error_budget_remaining: Gauge,
}

impl ProductionMetrics {
    /// Create a new production metrics registry
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Arc::new(Registry::new());

        // Authentication metrics
        let auth_requests_total = IntCounter::new(
            "auth_requests_total",
            "Total number of authentication requests",
        )?;
        registry.register(Box::new(auth_requests_total.clone()))?;

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

        let auth_duration_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "auth_duration_seconds",
                "Authentication request duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        )?;
        registry.register(Box::new(auth_duration_seconds.clone()))?;

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

        let authz_duration_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "authz_duration_seconds",
                "Authorization request duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5]),
        )?;
        registry.register(Box::new(authz_duration_seconds.clone()))?;

        // Rate limiting metrics
        let rate_limit_hits = IntCounter::new(
            "rate_limit_hits",
            "Total number of rate limit checks that passed",
        )?;
        registry.register(Box::new(rate_limit_hits.clone()))?;

        let rate_limit_exceeded = IntCounter::new(
            "rate_limit_exceeded",
            "Total number of rate limit violations",
        )?;
        registry.register(Box::new(rate_limit_exceeded.clone()))?;

        // Connection pool metrics
        let pool_connections_active = IntGauge::new(
            "pool_connections_active",
            "Number of active connections in the pool",
        )?;
        registry.register(Box::new(pool_connections_active.clone()))?;

        let pool_connections_total = IntGauge::new(
            "pool_connections_total",
            "Total number of connections created",
        )?;
        registry.register(Box::new(pool_connections_total.clone()))?;

        let pool_acquisition_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "pool_acquisition_duration_seconds",
                "Connection acquisition duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25]),
        )?;
        registry.register(Box::new(pool_acquisition_duration.clone()))?;

        // Error metrics
        let errors_total = IntCounter::new("errors_total", "Total number of errors")?;
        registry.register(Box::new(errors_total.clone()))?;

        let errors_by_type = prometheus::IntCounterVec::new(
            prometheus::Opts::new("errors_by_type", "Errors categorized by type"),
            &["error_type"],
        )?;
        registry.register(Box::new(errors_by_type.clone()))?;

        // Performance metrics
        let request_duration_seconds = prometheus::HistogramVec::new(
            prometheus::HistogramOpts::new(
                "request_duration_seconds",
                "Request duration by endpoint and method",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
            &["endpoint", "method", "status"],
        )?;
        registry.register(Box::new(request_duration_seconds.clone()))?;

        let active_connections =
            IntGauge::new("active_connections", "Number of active client connections")?;
        registry.register(Box::new(active_connections.clone()))?;

        let memory_usage_bytes = IntGauge::new("memory_usage_bytes", "Memory usage in bytes")?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;

        // SLO tracking metrics
        let slo_auth_latency_budget_remaining = Gauge::new(
            "slo_auth_latency_budget_remaining",
            "Remaining error budget for auth latency SLO (percentage)",
        )?;
        registry.register(Box::new(slo_auth_latency_budget_remaining.clone()))?;

        let slo_authz_latency_budget_remaining = Gauge::new(
            "slo_authz_latency_budget_remaining",
            "Remaining error budget for authz latency SLO (percentage)",
        )?;
        registry.register(Box::new(slo_authz_latency_budget_remaining.clone()))?;

        let slo_error_budget_remaining = Gauge::new(
            "slo_error_budget_remaining",
            "Remaining error budget for overall error rate SLO (percentage)",
        )?;
        registry.register(Box::new(slo_error_budget_remaining.clone()))?;

        Ok(Self {
            registry,
            start_time: Instant::now(),
            auth_requests_total,
            auth_success_total,
            auth_failures_total,
            auth_duration_seconds,
            authz_requests_total,
            authz_allow_total,
            authz_deny_total,
            authz_duration_seconds,
            rate_limit_hits,
            rate_limit_exceeded,
            pool_connections_active,
            pool_connections_total,
            pool_acquisition_duration,
            errors_total,
            errors_by_type,
            request_duration_seconds,
            active_connections,
            memory_usage_bytes,
            slo_auth_latency_budget_remaining,
            slo_authz_latency_budget_remaining,
            slo_error_budget_remaining,
        })
    }

    /// Record an authentication request
    pub fn record_auth_request(&self, duration: Duration, success: bool) {
        self.auth_requests_total.inc();
        self.auth_duration_seconds.observe(duration.as_secs_f64());

        if success {
            self.auth_success_total.inc();
        } else {
            self.auth_failures_total.inc();
        }
    }

    /// Record an authorization request
    pub fn record_authz_request(&self, duration: Duration, allowed: bool) {
        self.authz_requests_total.inc();
        self.authz_duration_seconds.observe(duration.as_secs_f64());

        if allowed {
            self.authz_allow_total.inc();
        } else {
            self.authz_deny_total.inc();
        }
    }

    /// Record rate limit check
    pub fn record_rate_limit(&self, allowed: bool) {
        if allowed {
            self.rate_limit_hits.inc();
        } else {
            self.rate_limit_exceeded.inc();
        }
    }

    /// Record connection pool metrics
    pub fn record_connection_acquisition(&self, duration: Duration) {
        self.pool_acquisition_duration
            .observe(duration.as_secs_f64());
    }

    /// Record an error
    pub fn record_error(&self, error_type: &str) {
        self.errors_total.inc();
        self.errors_by_type.with_label_values(&[error_type]).inc();
    }

    /// Record HTTP request metrics
    pub fn record_request(&self, endpoint: &str, method: &str, status: &str, duration: Duration) {
        self.request_duration_seconds
            .with_label_values(&[endpoint, method, status])
            .observe(duration.as_secs_f64());
    }

    /// Update SLO budgets based on current performance
    pub fn update_slo_budgets(&self) {
        // Calculate SLO budgets based on error rates and latency percentiles
        // This is a simplified implementation - in production, you'd want more sophisticated tracking

        // For demonstration, assume we have 99.9% SLO with 0.1% error budget
        let total_auth_requests = self.auth_requests_total.get();
        let auth_errors = self.auth_failures_total.get();

        if total_auth_requests > 0 {
            let error_rate = auth_errors as f64 / total_auth_requests as f64;
            let error_budget_used = error_rate / 0.001; // 0.1% error budget
            let error_budget_remaining = (1.0 - error_budget_used).max(0.0);
            self.slo_error_budget_remaining.set(error_budget_remaining);
        }

        // Similar calculations for latency budgets would go here
        // In practice, you'd track percentile latencies and compare against SLO targets
    }

    /// Get metrics in Prometheus format
    pub fn gather(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buffer)?;

        Ok(String::from_utf8(buffer)?)
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }
}

/// SLO configuration and tracking
pub struct SLOConfig {
    pub auth_latency_target_ms: f64,  // e.g., 100ms for P95
    pub authz_latency_target_ms: f64, // e.g., 50ms for P95
    pub error_budget_percentage: f64, // e.g., 0.1% (99.9% uptime)
    pub slo_window_days: u32,         // e.g., 30 days
}

impl Default for SLOConfig {
    fn default() -> Self {
        Self {
            auth_latency_target_ms: 100.0,
            authz_latency_target_ms: 50.0,
            error_budget_percentage: 0.1,
            slo_window_days: 30,
        }
    }
}

/// Performance regression detector
pub struct PerformanceRegressionDetector {
    baseline_latencies: Vec<f64>,
    recent_latencies: Vec<f64>,
    threshold_percentage: f64,
}

impl PerformanceRegressionDetector {
    pub fn new(threshold_percentage: f64) -> Self {
        Self {
            baseline_latencies: Vec::new(),
            recent_latencies: Vec::new(),
            threshold_percentage,
        }
    }

    /// Add a latency measurement
    pub fn record_latency(&mut self, latency_ms: f64) {
        self.recent_latencies.push(latency_ms);

        // Keep only recent measurements
        if self.recent_latencies.len() > 1000 {
            self.recent_latencies.remove(0);
        }
    }

    /// Set baseline performance
    pub fn set_baseline(&mut self, latencies: Vec<f64>) {
        self.baseline_latencies = latencies;
    }

    /// Check for performance regression
    pub fn check_regression(&self) -> Option<f64> {
        if self.baseline_latencies.is_empty() || self.recent_latencies.is_empty() {
            return None;
        }

        let baseline_avg: f64 =
            self.baseline_latencies.iter().sum::<f64>() / self.baseline_latencies.len() as f64;
        let recent_avg: f64 =
            self.recent_latencies.iter().sum::<f64>() / self.recent_latencies.len() as f64;

        let degradation_percentage = ((recent_avg - baseline_avg) / baseline_avg) * 100.0;

        if degradation_percentage > self.threshold_percentage {
            Some(degradation_percentage)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_recording() {
        let metrics = ProductionMetrics::new().unwrap();

        // Test auth metrics
        metrics.record_auth_request(Duration::from_millis(50), true);
        metrics.record_auth_request(Duration::from_millis(200), false);

        assert_eq!(metrics.auth_requests_total.get(), 2);
        assert_eq!(metrics.auth_success_total.get(), 1);
        assert_eq!(metrics.auth_failures_total.get(), 1);

        // Test authz metrics
        metrics.record_authz_request(Duration::from_millis(10), true);
        metrics.record_authz_request(Duration::from_millis(30), false);

        assert_eq!(metrics.authz_requests_total.get(), 2);
        assert_eq!(metrics.authz_allow_total.get(), 1);
        assert_eq!(metrics.authz_deny_total.get(), 1);
    }

    #[test]
    fn test_performance_regression_detector() {
        let mut detector = PerformanceRegressionDetector::new(10.0); // 10% threshold

        // Set baseline
        detector.set_baseline(vec![100.0, 105.0, 95.0]);

        // Add recent measurements with significant degradation
        for _ in 0..10 {
            detector.record_latency(120.0); // 20% degradation
        }

        let regression = detector.check_regression();
        assert!(regression.is_some());
        assert!(regression.unwrap() > 10.0);
    }
}
