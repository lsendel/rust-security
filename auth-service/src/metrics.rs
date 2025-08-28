//! Comprehensive observability metrics for the Auth Service.
//!
//! This module provides a complete metrics collection system that builds upon
//! the existing security metrics to provide comprehensive observability for:
//! - Token operations (issuance, validation, revocation, introspection)
//! - Policy evaluation and cache operations  
//! - Request rates, latency, and error rates
//! - Security events and authentication flows
//! - System health and performance metrics
//!
//! The metrics are designed to be compatible with Prometheus and follow
//! best practices for naming and labeling.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::{
    extract::{MatchedPath, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use once_cell::sync::Lazy;
#[cfg(feature = "monitoring")]
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};
use tracing::{debug, error};

/// Core metrics registry and collectors for comprehensive observability
pub struct MetricsRegistry {
    /// Prometheus registry for all metrics
    pub registry: Registry,

    // === Token Operation Metrics ===
    /// Token issuance operations (success/failure by type and grant)
    pub token_issuance_total: IntCounterVec,
    /// Token validation operations with detailed result tracking
    pub token_validation_total: IntCounterVec,
    /// Token revocation operations by reason and type
    pub token_revocation_total: IntCounterVec,
    /// Token introspection operations with latency tracking
    pub token_introspection_total: IntCounterVec,
    /// Token operation latency histogram by operation type
    pub token_operation_duration: HistogramVec,
    /// Currently active tokens by type
    pub active_tokens_gauge: IntCounterVec,

    // === Policy Evaluation Metrics ===
    /// Policy evaluation attempts with success/failure tracking
    pub policy_evaluation_total: IntCounterVec,
    /// Policy evaluation latency by policy type and result
    pub policy_evaluation_duration: HistogramVec,
    /// Policy cache operations (hit/miss/eviction)
    pub policy_cache_operations: IntCounterVec,
    /// Policy compilation and validation results
    pub policy_compilation_total: IntCounterVec,

    // === Cache Metrics ===
    /// Cache operations across all cache types (hit/miss/eviction)
    pub cache_operations_total: IntCounterVec,
    /// Cache hit ratio by cache type
    pub cache_hit_ratio: HistogramVec,
    /// Cache size by cache type
    pub cache_size_gauge: IntCounterVec,
    /// Cache operation latency
    pub cache_operation_duration: HistogramVec,

    // === HTTP Request Metrics ===
    /// HTTP requests by method, endpoint, and status
    pub http_requests_total: IntCounterVec,
    /// HTTP request duration by endpoint and method
    pub http_request_duration: HistogramVec,
    /// HTTP request size in bytes
    pub http_request_size_bytes: HistogramVec,
    /// HTTP response size in bytes
    pub http_response_size_bytes: HistogramVec,
    /// Concurrent HTTP requests gauge
    pub http_requests_in_flight: IntGauge,

    // === Rate Limiting Metrics ===
    /// Rate limit enforcement by endpoint and result
    pub rate_limit_enforcement_total: IntCounterVec,
    /// Rate limit quotas by client and endpoint
    pub rate_limit_quota_gauge: IntCounterVec,
    /// Rate limit reset time tracking
    pub rate_limit_reset_duration: HistogramVec,

    // === Security Event Metrics ===
    /// Authentication attempts with detailed context
    pub auth_attempts_detailed: IntCounterVec,
    /// MFA challenge and validation metrics
    pub mfa_operations_total: IntCounterVec,
    /// Security policy violations
    pub security_violations_total: IntCounterVec,
    /// Anomaly detection events
    pub anomaly_detection_total: IntCounterVec,

    // === System Health Metrics ===
    /// System resource usage (memory, CPU, connections)
    pub system_resources_gauge: IntCounterVec,
    /// Background task execution metrics
    pub background_task_total: IntCounterVec,
    /// Database/Redis connection health
    pub connection_health_gauge: IntCounterVec,
    /// Circuit breaker state changes
    pub circuit_breaker_state_changes: IntCounterVec,
}

impl MetricsRegistry {
    /// Create a new metrics registry with all collectors initialized
    pub fn new() -> Self {
        let registry = Registry::new();

        // === Token Operation Metrics ===
        let token_issuance_total = IntCounterVec::new(
            Opts::new(
                "auth_token_issuance_total",
                "Total token issuance operations",
            ),
            &["token_type", "grant_type", "client_id", "result"],
        )
        .expect("Failed to create token_issuance_total metric");

        let token_validation_total = IntCounterVec::new(
            Opts::new(
                "auth_token_validation_total",
                "Total token validation operations",
            ),
            &["token_type", "validation_type", "result", "client_id"],
        )
        .expect("Failed to create token_validation_total metric");

        let token_revocation_total = IntCounterVec::new(
            Opts::new(
                "auth_token_revocation_total",
                "Total token revocation operations",
            ),
            &["token_type", "reason", "client_id", "result"],
        )
        .expect("Failed to create token_revocation_total metric");

        let token_introspection_total = IntCounterVec::new(
            Opts::new(
                "auth_token_introspection_total",
                "Total token introspection operations",
            ),
            &["client_id", "result", "token_active"],
        )
        .expect("Failed to create token_introspection_total metric");

        let token_operation_duration = HistogramVec::new(
            HistogramOpts::new(
                "auth_token_operation_duration_seconds",
                "Duration of token operations in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
            &["operation_type", "result"],
        )
        .expect("Failed to create token_operation_duration metric");

        let active_tokens_gauge = IntCounterVec::new(
            Opts::new("auth_active_tokens", "Number of currently active tokens"),
            &["token_type", "client_id"],
        )
        .expect("Failed to create active_tokens_gauge metric");

        // === Policy Evaluation Metrics ===
        let policy_evaluation_total = IntCounterVec::new(
            Opts::new(
                "auth_policy_evaluation_total",
                "Total policy evaluation operations",
            ),
            &["policy_type", "resource", "action", "result"],
        )
        .expect("Failed to create policy_evaluation_total metric");

        let policy_evaluation_duration = HistogramVec::new(
            HistogramOpts::new(
                "auth_policy_evaluation_duration_seconds",
                "Duration of policy evaluation in seconds",
            )
            .buckets(vec![
                0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
            ]),
            &["policy_type", "result"],
        )
        .expect("Failed to create policy_evaluation_duration metric");

        let policy_cache_operations = IntCounterVec::new(
            Opts::new(
                "auth_policy_cache_operations_total",
                "Total policy cache operations",
            ),
            &["operation", "result", "policy_type"],
        )
        .expect("Failed to create policy_cache_operations metric");

        let policy_compilation_total = IntCounterVec::new(
            Opts::new(
                "auth_policy_compilation_total",
                "Total policy compilation operations",
            ),
            &["policy_type", "result", "source"],
        )
        .expect("Failed to create policy_compilation_total metric");

        // === Cache Metrics ===
        let cache_operations_total = IntCounterVec::new(
            Opts::new("auth_cache_operations_total", "Total cache operations"),
            &["cache_type", "operation", "result"],
        )
        .expect("Failed to create cache_operations_total metric");

        let cache_hit_ratio = HistogramVec::new(
            HistogramOpts::new("auth_cache_hit_ratio", "Cache hit ratio by cache type").buckets(
                vec![
                    0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 1.0,
                ],
            ),
            &["cache_type"],
        )
        .expect("Failed to create cache_hit_ratio metric");

        let cache_size_gauge = IntCounterVec::new(
            Opts::new("auth_cache_size", "Current cache size by type"),
            &["cache_type", "measurement"],
        )
        .expect("Failed to create cache_size_gauge metric");

        let cache_operation_duration = HistogramVec::new(
            HistogramOpts::new(
                "auth_cache_operation_duration_seconds",
                "Duration of cache operations in seconds",
            )
            .buckets(vec![
                0.00001, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1,
            ]),
            &["cache_type", "operation"],
        )
        .expect("Failed to create cache_operation_duration metric");

        // === HTTP Request Metrics ===
        let http_requests_total = IntCounterVec::new(
            Opts::new("auth_http_requests_total", "Total HTTP requests"),
            &["method", "endpoint", "status_code", "client_id"],
        )
        .expect("Failed to create http_requests_total metric");

        let http_request_duration = HistogramVec::new(
            HistogramOpts::new(
                "auth_http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["method", "endpoint"],
        )
        .expect("Failed to create http_request_duration metric");

        let http_request_size_bytes = HistogramVec::new(
            HistogramOpts::new("auth_http_request_size_bytes", "HTTP request size in bytes")
                .buckets(vec![
                    64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0,
                ]),
            &["method", "endpoint"],
        )
        .expect("Failed to create http_request_size_bytes metric");

        let http_response_size_bytes = HistogramVec::new(
            HistogramOpts::new(
                "auth_http_response_size_bytes",
                "HTTP response size in bytes",
            )
            .buckets(vec![
                64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0,
            ]),
            &["method", "endpoint", "status_code"],
        )
        .expect("Failed to create http_response_size_bytes metric");

        let http_requests_in_flight = IntGauge::new(
            "auth_http_requests_in_flight",
            "Number of HTTP requests currently being processed",
        )
        .expect("Failed to create http_requests_in_flight metric");

        // === Rate Limiting Metrics ===
        let rate_limit_enforcement_total = IntCounterVec::new(
            Opts::new(
                "auth_rate_limit_enforcement_total",
                "Total rate limit enforcement events",
            ),
            &["endpoint", "client_id", "result", "limit_type"],
        )
        .expect("Failed to create rate_limit_enforcement_total metric");

        let rate_limit_quota_gauge = IntCounterVec::new(
            Opts::new(
                "auth_rate_limit_quota",
                "Current rate limit quota by client and endpoint",
            ),
            &["client_id", "endpoint", "quota_type"],
        )
        .expect("Failed to create rate_limit_quota_gauge metric");

        let rate_limit_reset_duration = HistogramVec::new(
            HistogramOpts::new(
                "auth_rate_limit_reset_duration_seconds",
                "Duration until rate limit reset in seconds",
            )
            .buckets(vec![1.0, 5.0, 15.0, 30.0, 60.0, 300.0, 900.0, 3600.0]),
            &["client_id", "endpoint"],
        )
        .expect("Failed to create rate_limit_reset_duration metric");

        // === Security Event Metrics ===
        let auth_attempts_detailed = IntCounterVec::new(
            Opts::new(
                "auth_authentication_attempts_detailed_total",
                "Detailed authentication attempts",
            ),
            &[
                "method",
                "client_id",
                "ip_address",
                "user_agent_class",
                "result",
            ],
        )
        .expect("Failed to create auth_attempts_detailed metric");

        let mfa_operations_total = IntCounterVec::new(
            Opts::new("auth_mfa_operations_total", "Total MFA operations"),
            &["operation", "method", "client_id", "result"],
        )
        .expect("Failed to create mfa_operations_total metric");

        let security_violations_total = IntCounterVec::new(
            Opts::new(
                "auth_security_violations_total",
                "Total security policy violations",
            ),
            &["violation_type", "severity", "client_id", "resource"],
        )
        .expect("Failed to create security_violations_total metric");

        let anomaly_detection_total = IntCounterVec::new(
            Opts::new(
                "auth_anomaly_detection_total",
                "Total anomaly detection events",
            ),
            &["anomaly_type", "confidence", "client_id", "action_taken"],
        )
        .expect("Failed to create anomaly_detection_total metric");

        // === System Health Metrics ===
        let system_resources_gauge = IntCounterVec::new(
            Opts::new("auth_system_resources", "System resource usage"),
            &["resource_type", "unit"],
        )
        .expect("Failed to create system_resources_gauge metric");

        let background_task_total = IntCounterVec::new(
            Opts::new(
                "auth_background_task_total",
                "Total background task executions",
            ),
            &["task_type", "result", "duration_bucket"],
        )
        .expect("Failed to create background_task_total metric");

        let connection_health_gauge = IntCounterVec::new(
            Opts::new("auth_connection_health", "Connection health status"),
            &["connection_type", "endpoint", "status"],
        )
        .expect("Failed to create connection_health_gauge metric");

        let circuit_breaker_state_changes = IntCounterVec::new(
            Opts::new(
                "auth_circuit_breaker_state_changes_total",
                "Circuit breaker state changes",
            ),
            &["service", "from_state", "to_state", "reason"],
        )
        .expect("Failed to create circuit_breaker_state_changes metric");

        // Register all metrics with the registry
        Self::register_metrics(
            &registry,
            vec![
                Box::new(token_issuance_total.clone()),
                Box::new(token_validation_total.clone()),
                Box::new(token_revocation_total.clone()),
                Box::new(token_introspection_total.clone()),
                Box::new(token_operation_duration.clone()),
                Box::new(active_tokens_gauge.clone()),
                Box::new(policy_evaluation_total.clone()),
                Box::new(policy_evaluation_duration.clone()),
                Box::new(policy_cache_operations.clone()),
                Box::new(policy_compilation_total.clone()),
                Box::new(cache_operations_total.clone()),
                Box::new(cache_hit_ratio.clone()),
                Box::new(cache_size_gauge.clone()),
                Box::new(cache_operation_duration.clone()),
                Box::new(http_requests_total.clone()),
                Box::new(http_request_duration.clone()),
                Box::new(http_request_size_bytes.clone()),
                Box::new(http_response_size_bytes.clone()),
                Box::new(http_requests_in_flight.clone()),
                Box::new(rate_limit_enforcement_total.clone()),
                Box::new(rate_limit_quota_gauge.clone()),
                Box::new(rate_limit_reset_duration.clone()),
                Box::new(auth_attempts_detailed.clone()),
                Box::new(mfa_operations_total.clone()),
                Box::new(security_violations_total.clone()),
                Box::new(anomaly_detection_total.clone()),
                Box::new(system_resources_gauge.clone()),
                Box::new(background_task_total.clone()),
                Box::new(connection_health_gauge.clone()),
                Box::new(circuit_breaker_state_changes.clone()),
            ],
        );

        Self {
            registry,
            token_issuance_total,
            token_validation_total,
            token_revocation_total,
            token_introspection_total,
            token_operation_duration,
            active_tokens_gauge,
            policy_evaluation_total,
            policy_evaluation_duration,
            policy_cache_operations,
            policy_compilation_total,
            cache_operations_total,
            cache_hit_ratio,
            cache_size_gauge,
            cache_operation_duration,
            http_requests_total,
            http_request_duration,
            http_request_size_bytes,
            http_response_size_bytes,
            http_requests_in_flight,
            rate_limit_enforcement_total,
            rate_limit_quota_gauge,
            rate_limit_reset_duration,
            auth_attempts_detailed,
            mfa_operations_total,
            security_violations_total,
            anomaly_detection_total,
            system_resources_gauge,
            background_task_total,
            connection_health_gauge,
            circuit_breaker_state_changes,
        }
    }

    /// Register metrics with the registry, handling registration errors gracefully
    fn register_metrics(registry: &Registry, metrics: Vec<Box<dyn prometheus::core::Collector>>) {
        for metric in metrics {
            if let Err(e) = registry.register(metric) {
                error!("Failed to register metric: {}", e);
            }
        }
    }

    /// Generate Prometheus metrics output
    pub fn gather_metrics(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global metrics registry instance
pub static METRICS: Lazy<MetricsRegistry> = Lazy::new(MetricsRegistry::new);

/// Advanced metrics middleware with high-cardinality protection
pub async fn metrics_middleware(req: Request, next: Next) -> Response {
    let start_time = Instant::now();
    let method = req.method().clone();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| normalize_path_for_cardinality(p.as_str()))
        .unwrap_or("unknown".to_string());

    // Extract client ID with cardinality protection
    let client_id = extract_client_id_with_protection(&req);

    // Track request size
    let request_size = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    // Increment in-flight requests
    METRICS.http_requests_in_flight.inc();

    // Process request
    let response = next.run(req).await;

    // Decrement in-flight requests
    METRICS.http_requests_in_flight.dec();

    // Calculate response time
    let duration = start_time.elapsed();
    let status_code = response.status();

    // Extract response size from headers
    let response_size = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    // Record metrics
    METRICS
        .http_requests_total
        .with_label_values(&[
            method.as_str(),
            &path,
            &status_code.as_u16().to_string(),
            &client_id,
        ])
        .inc();

    METRICS
        .http_request_duration
        .with_label_values(&[method.as_str(), &path])
        .observe(duration.as_secs_f64());

    if request_size > 0.0 {
        METRICS
            .http_request_size_bytes
            .with_label_values(&[method.as_str(), &path])
            .observe(request_size);
    }

    if response_size > 0.0 {
        METRICS
            .http_response_size_bytes
            .with_label_values(&[method.as_str(), &path, &status_code.as_u16().to_string()])
            .observe(response_size);
    }

    // Log detailed request info for debugging
    // Record SLO metrics
    let latency_slo_violation = duration.as_millis() > 100; // 100ms SLO
    if latency_slo_violation {
        METRICS
            .security_violations_total
            .with_label_values(&["slo_violation", "warning", &client_id, &path])
            .inc();
    }

    // Log detailed request info for debugging
    debug!(
        method = %method,
        path = %path,
        status = %status_code,
        duration_ms = %duration.as_millis(),
        client_id = %client_id,
        request_size = %request_size,
        response_size = %response_size,
        slo_violation = %latency_slo_violation,
        "HTTP request processed"
    );

    response
}

/// Extract client ID with cardinality protection
fn extract_client_id_with_protection(req: &Request) -> String {
    match req.headers().get("client-id").and_then(|v| v.to_str().ok()) {
        Some(id) if is_valid_client_id(id) => id.to_string(),
        _ => "unknown".to_string(),
    }
}

/// Validate client ID to prevent cardinality explosion
fn is_valid_client_id(id: &str) -> bool {
    id.len() <= 50
        && id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

/// Normalize path for metrics to prevent cardinality explosion
fn normalize_path_for_cardinality(path: &str) -> String {
    // Replace UUIDs and other variable parts with placeholders
    let uuid_pattern = regex::Regex::new(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    )
    .unwrap();
    let numeric_pattern = regex::Regex::new(r"/\d+").unwrap();

    let normalized = uuid_pattern.replace_all(path, "{uuid}");
    let normalized = numeric_pattern.replace_all(&normalized, "/{id}");

    normalized.to_string()
}

/// Prometheus metrics endpoint handler
pub async fn metrics_handler() -> impl IntoResponse {
    match METRICS.gather_metrics() {
        Ok(metrics) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            metrics,
        ),
        Err(e) => {
            error!("Failed to gather metrics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "text/plain")],
                format!("Error gathering metrics: {}", e),
            )
        }
    }
}

/// Helper functions for common metric patterns
pub struct MetricsHelper;

impl MetricsHelper {
    /// Record a token operation with timing
    pub fn record_token_operation<F, R>(operation_type: &str, operation: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed();

        METRICS
            .token_operation_duration
            .with_label_values(&[operation_type, "success"])
            .observe(duration.as_secs_f64());

        result
    }

    /// Record a token operation with error handling
    pub fn record_token_operation_result<F, R, E>(
        operation_type: &str,
        operation: F,
    ) -> Result<R, E>
    where
        F: FnOnce() -> Result<R, E>,
    {
        let start = Instant::now();
        let result = operation();
        let duration = start.elapsed();

        let result_label = if operation_result.is_ok() { "success" } else { "error" };

        METRICS
            .token_operation_duration
            .with_label_values(&[operation_type, result_label])
            .observe(duration.as_secs_f64());

        result
    }

    /// Record a cache operation
    pub fn record_cache_operation(
        cache_type: &str,
        operation: &str,
        result: &str,
        duration: Duration,
    ) {
        METRICS
            .cache_operations_total
            .with_label_values(&[cache_type, operation, result])
            .inc();

        METRICS
            .cache_operation_duration
            .with_label_values(&[cache_type, operation])
            .observe(duration.as_secs_f64());
    }

    /// Record a policy evaluation
    pub fn record_policy_evaluation(
        policy_type: &str,
        resource: &str,
        action: &str,
        result: &str,
        duration: Duration,
    ) {
        METRICS
            .policy_evaluation_total
            .with_label_values(&[policy_type, resource, action, result])
            .inc();

        METRICS
            .policy_evaluation_duration
            .with_label_values(&[policy_type, result])
            .observe(duration.as_secs_f64());
    }

    /// Record a security violation
    pub fn record_security_violation(
        violation_type: &str,
        severity: &str,
        client_id: &str,
        resource: &str,
    ) {
        METRICS
            .security_violations_total
            .with_label_values(&[violation_type, severity, client_id, resource])
            .inc();
    }

    /// Record an anomaly detection event
    pub fn record_anomaly_detection(
        anomaly_type: &str,
        confidence: &str,
        client_id: &str,
        action_taken: &str,
    ) {
        METRICS
            .anomaly_detection_total
            .with_label_values(&[anomaly_type, confidence, client_id, action_taken])
            .inc();
    }

    /// Update cache hit ratio
    pub fn update_cache_hit_ratio(cache_type: &str, hits: u64, total: u64) {
        if total > 0 {
            let ratio = hits as f64 / total as f64;
            METRICS
                .cache_hit_ratio
                .with_label_values(&[cache_type])
                .observe(ratio);
        }
    }

    /// Record rate limit enforcement
    pub fn record_rate_limit_enforcement(
        endpoint: &str,
        client_id: &str,
        result: &str,
        limit_type: &str,
    ) {
        METRICS
            .rate_limit_enforcement_total
            .with_label_values(&[endpoint, client_id, result, limit_type])
            .inc();
    }

    /// Update system resource usage
    pub fn update_system_resources(resource_type: &str, unit: &str, value: i64) {
        METRICS
            .system_resources_gauge
            .with_label_values(&[resource_type, unit])
            .reset();

        for _ in 0..value {
            METRICS
                .system_resources_gauge
                .with_label_values(&[resource_type, unit])
                .inc();
        }
    }

    /// Record background task execution
    pub fn record_background_task(task_type: &str, result: &str, duration: Duration) {
        let duration_bucket = match duration.as_secs() {
            0..=1 => "fast",
            2..=10 => "medium",
            11..=60 => "slow",
            _ => "very_slow",
        };

        METRICS
            .background_task_total
            .with_label_values(&[task_type, result, duration_bucket])
            .inc();
    }
}

/// Comprehensive metrics collection configuration
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Whether to enable detailed metrics collection
    pub enabled: bool,
    /// Metrics endpoint path
    pub endpoint_path: String,
    /// Whether to include sensitive information in metrics labels
    pub include_sensitive_labels: bool,
    /// Histogram bucket configuration
    pub custom_buckets: HashMap<String, Vec<f64>>,
    /// Metrics retention period in seconds
    pub retention_seconds: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint_path: "/metrics".to_string(),
            include_sensitive_labels: false,
            custom_buckets: HashMap::new(),
            retention_seconds: 3600, // 1 hour
        }
    }
}

/// Metrics macros for convenient usage
#[macro_export]
macro_rules! record_token_operation {
    ($op_type:expr, $operation:expr) => {
        $crate::metrics::MetricsHelper::record_token_operation($op_type, $operation)
    };
}

#[macro_export]
macro_rules! record_cache_hit {
    ($cache_type:expr) => {
        $crate::metrics::METRICS
            .cache_operations_total
            .with_label_values(&[$cache_type, "get", "hit"])
            .inc();
    };
}

#[macro_export]
macro_rules! record_cache_miss {
    ($cache_type:expr) => {
        $crate::metrics::METRICS
            .cache_operations_total
            .with_label_values(&[$cache_type, "get", "miss"])
            .inc();
    };
}

#[macro_export]
macro_rules! record_policy_evaluation {
    ($policy_type:expr, $resource:expr, $action:expr, $result:expr, $duration:expr) => {
        $crate::metrics::MetricsHelper::record_policy_evaluation(
            $policy_type,
            $resource,
            $action,
            $result,
            $duration,
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_registry_creation() {
        let metrics = MetricsRegistry::new();
        assert!(!metrics.registry.gather().is_empty());
    }

    #[test]
    fn test_metrics_helper_token_operation() {
        let result = MetricsHelper::record_token_operation("test", || {
            std::thread::sleep(Duration::from_millis(1));
            42
        });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_cache_operation_recording() {
        MetricsHelper::record_cache_operation("test_cache", "get", "hit", Duration::from_millis(5));
    }

    #[test]
    fn test_metrics_macros() {
        let result = record_token_operation!("test_macro", || 100);
        assert_eq!(result, 100);

        record_cache_hit!("test_cache");
        record_cache_miss!("test_cache");
    }
}
