//! Comprehensive observability metrics for the Policy Service.
//!
//! This module provides metrics collection for Cedar policy evaluation,
//! authorization decisions, cache operations, and service health.

use std::time::{Duration, Instant};

use axum::{
    extract::{MatchedPath, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};
use tracing::{debug, error};

/// Core metrics registry for policy service observability
#[allow(dead_code)]
pub struct PolicyMetricsRegistry {
    /// Prometheus registry for all metrics
    pub registry: Registry,

    // === Authorization Metrics ===
    /// Authorization requests by decision, principal type, action, and resource
    pub authorization_requests_total: IntCounterVec,
    /// Authorization decision latency by policy complexity
    pub authorization_duration: HistogramVec,
    /// Policy evaluation errors by type and cause
    pub policy_evaluation_errors_total: IntCounterVec,
    /// Number of policies evaluated per request
    pub policies_evaluated_per_request: HistogramVec,

    // === Policy Management Metrics ===
    /// Policy compilation and validation results
    pub policy_compilation_total: IntCounterVec,
    /// Policy reload operations (success/failure)
    pub policy_reload_total: IntCounterVec,
    /// Number of active policies by type
    pub active_policies_gauge: IntCounterVec,
    /// Policy file size and complexity metrics
    pub policy_complexity_gauge: IntCounterVec,

    // === Entity Management Metrics ===
    /// Entity operations (lookup, validation)
    pub entity_operations_total: IntCounterVec,
    /// Entity cache operations (hit/miss/eviction)
    pub entity_cache_operations: IntCounterVec,
    /// Number of active entities by type
    pub active_entities_gauge: IntCounterVec,

    // === HTTP Request Metrics ===
    /// HTTP requests by method, endpoint, and status
    pub http_requests_total: IntCounterVec,
    /// HTTP request duration by endpoint
    pub http_request_duration: HistogramVec,
    /// HTTP request size in bytes
    pub http_request_size_bytes: HistogramVec,
    /// HTTP response size in bytes
    pub http_response_size_bytes: HistogramVec,
    /// Concurrent HTTP requests
    pub http_requests_in_flight: IntGauge,

    // === Security Metrics ===
    /// Security policy violations by type and severity
    pub security_violations_total: IntCounterVec,
    /// Anomalous authorization patterns
    pub authorization_anomalies_total: IntCounterVec,
    /// Rate limiting enforcement
    pub rate_limit_enforcement_total: IntCounterVec,

    // === Performance Metrics ===
    /// Memory usage by component
    pub memory_usage_bytes: IntCounterVec,
    /// CPU usage by component
    pub cpu_usage_percent: IntCounterVec,
    /// Background task execution
    pub background_tasks_total: IntCounterVec,

    // === SLO Metrics ===
    /// SLO violations by type and severity
    pub slo_violations_total: IntCounterVec,
    /// Error budget consumption
    pub error_budget_consumption: IntCounterVec,
}

impl PolicyMetricsRegistry {
    /// Create a new metrics registry with all collectors initialized
    pub fn new() -> Self {
        let registry = Registry::new();

        // === Authorization Metrics ===
        let authorization_requests_total = IntCounterVec::new(
            Opts::new(
                "policy_authorization_requests_total",
                "Total authorization requests",
            ),
            &[
                "decision",
                "principal_type",
                "action_type",
                "resource_type",
                "client_id",
            ],
        )
        .expect("Failed to create authorization_requests_total metric");

        let authorization_duration = HistogramVec::new(
            HistogramOpts::new(
                "policy_authorization_duration_seconds",
                "Duration of authorization decisions in seconds",
            )
            .buckets(vec![
                0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
            ]),
            &["decision", "policy_complexity"],
        )
        .expect("Failed to create authorization_duration metric");

        let policy_evaluation_errors_total = IntCounterVec::new(
            Opts::new(
                "policy_evaluation_errors_total",
                "Total policy evaluation errors",
            ),
            &["error_type", "error_cause", "policy_id"],
        )
        .expect("Failed to create policy_evaluation_errors_total metric");

        let policies_evaluated_per_request = HistogramVec::new(
            HistogramOpts::new(
                "policy_policies_evaluated_per_request",
                "Number of policies evaluated per authorization request",
            )
            .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0]),
            &["request_type"],
        )
        .expect("Failed to create policies_evaluated_per_request metric");

        // === Policy Management Metrics ===
        let policy_compilation_total = IntCounterVec::new(
            Opts::new(
                "policy_compilation_total",
                "Total policy compilation operations",
            ),
            &["result", "policy_source", "validation_type"],
        )
        .expect("Failed to create policy_compilation_total metric");

        let policy_reload_total = IntCounterVec::new(
            Opts::new("policy_reload_total", "Total policy reload operations"),
            &["result", "trigger_type", "policies_changed"],
        )
        .expect("Failed to create policy_reload_total metric");

        let active_policies_gauge = IntCounterVec::new(
            Opts::new(
                "policy_active_policies",
                "Number of active policies by type",
            ),
            &["policy_type", "scope"],
        )
        .expect("Failed to create active_policies_gauge metric");

        let policy_complexity_gauge = IntCounterVec::new(
            Opts::new("policy_complexity", "Policy complexity metrics"),
            &["metric_type", "policy_id"],
        )
        .expect("Failed to create policy_complexity_gauge metric");

        // === Entity Management Metrics ===
        let entity_operations_total = IntCounterVec::new(
            Opts::new("policy_entity_operations_total", "Total entity operations"),
            &["operation", "entity_type", "result"],
        )
        .expect("Failed to create entity_operations_total metric");

        let entity_cache_operations = IntCounterVec::new(
            Opts::new(
                "policy_entity_cache_operations_total",
                "Total entity cache operations",
            ),
            &["operation", "result", "entity_type"],
        )
        .expect("Failed to create entity_cache_operations metric");

        let active_entities_gauge = IntCounterVec::new(
            Opts::new(
                "policy_active_entities",
                "Number of active entities by type",
            ),
            &["entity_type", "namespace"],
        )
        .expect("Failed to create active_entities_gauge metric");

        // === HTTP Request Metrics ===
        let http_requests_total = IntCounterVec::new(
            Opts::new("policy_http_requests_total", "Total HTTP requests"),
            &["method", "endpoint", "status_code", "client_id"],
        )
        .expect("Failed to create http_requests_total metric");

        let http_request_duration = HistogramVec::new(
            HistogramOpts::new(
                "policy_http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
            ]),
            &["method", "endpoint"],
        )
        .expect("Failed to create http_request_duration metric");

        let http_request_size_bytes = HistogramVec::new(
            HistogramOpts::new(
                "policy_http_request_size_bytes",
                "HTTP request size in bytes",
            )
            .buckets(vec![64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0]),
            &["method", "endpoint"],
        )
        .expect("Failed to create http_request_size_bytes metric");

        let http_response_size_bytes = HistogramVec::new(
            HistogramOpts::new(
                "policy_http_response_size_bytes",
                "HTTP response size in bytes",
            )
            .buckets(vec![64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0]),
            &["method", "endpoint", "status_code"],
        )
        .expect("Failed to create http_response_size_bytes metric");

        let http_requests_in_flight = IntGauge::new(
            "policy_http_requests_in_flight",
            "Number of HTTP requests currently being processed",
        )
        .expect("Failed to create http_requests_in_flight metric");

        // === Security Metrics ===
        let security_violations_total = IntCounterVec::new(
            Opts::new(
                "policy_security_violations_total",
                "Total security violations",
            ),
            &["violation_type", "severity", "client_id", "resource"],
        )
        .expect("Failed to create security_violations_total metric");

        let authorization_anomalies_total = IntCounterVec::new(
            Opts::new(
                "policy_authorization_anomalies_total",
                "Total authorization anomalies",
            ),
            &["anomaly_type", "confidence", "principal", "action_taken"],
        )
        .expect("Failed to create authorization_anomalies_total metric");

        let rate_limit_enforcement_total = IntCounterVec::new(
            Opts::new(
                "policy_rate_limit_enforcement_total",
                "Total rate limit enforcement",
            ),
            &["endpoint", "client_id", "result", "limit_type"],
        )
        .expect("Failed to create rate_limit_enforcement_total metric");

        // === Performance Metrics ===
        let memory_usage_bytes = IntCounterVec::new(
            Opts::new(
                "policy_memory_usage_bytes",
                "Memory usage in bytes by component",
            ),
            &["component", "type"],
        )
        .expect("Failed to create memory_usage_bytes metric");

        let cpu_usage_percent = IntCounterVec::new(
            Opts::new(
                "policy_cpu_usage_percent",
                "CPU usage percentage by component",
            ),
            &["component", "type"],
        )
        .expect("Failed to create cpu_usage_percent metric");

        let background_tasks_total = IntCounterVec::new(
            Opts::new(
                "policy_background_tasks_total",
                "Total background task executions",
            ),
            &["task_type", "result", "duration_bucket"],
        )
        .expect("Failed to create background_tasks_total metric");

        // === SLO Metrics ===
        let slo_violations_total = IntCounterVec::new(
            Opts::new("policy_slo_violations_total", "Total SLO violations"),
            &["slo_type", "severity", "service_component"],
        )
        .expect("Failed to create slo_violations_total metric");

        let error_budget_consumption = IntCounterVec::new(
            Opts::new(
                "policy_error_budget_consumption",
                "Error budget consumption",
            ),
            &["slo_type", "time_window", "service_component"],
        )
        .expect("Failed to create error_budget_consumption metric");

        // Register all metrics
        let metrics: Vec<Box<dyn prometheus::core::Collector>> = vec![
            Box::new(authorization_requests_total.clone()),
            Box::new(authorization_duration.clone()),
            Box::new(policy_evaluation_errors_total.clone()),
            Box::new(policies_evaluated_per_request.clone()),
            Box::new(policy_compilation_total.clone()),
            Box::new(policy_reload_total.clone()),
            Box::new(active_policies_gauge.clone()),
            Box::new(policy_complexity_gauge.clone()),
            Box::new(entity_operations_total.clone()),
            Box::new(entity_cache_operations.clone()),
            Box::new(active_entities_gauge.clone()),
            Box::new(http_requests_total.clone()),
            Box::new(http_request_duration.clone()),
            Box::new(http_request_size_bytes.clone()),
            Box::new(http_response_size_bytes.clone()),
            Box::new(http_requests_in_flight.clone()),
            Box::new(security_violations_total.clone()),
            Box::new(authorization_anomalies_total.clone()),
            Box::new(rate_limit_enforcement_total.clone()),
            Box::new(memory_usage_bytes.clone()),
            Box::new(cpu_usage_percent.clone()),
            Box::new(background_tasks_total.clone()),
            Box::new(slo_violations_total.clone()),
            Box::new(error_budget_consumption.clone()),
        ];

        for metric in metrics {
            if let Err(e) = registry.register(metric) {
                error!("Failed to register metric: {}", e);
            }
        }

        Self {
            registry,
            authorization_requests_total,
            authorization_duration,
            policy_evaluation_errors_total,
            policies_evaluated_per_request,
            policy_compilation_total,
            policy_reload_total,
            active_policies_gauge,
            policy_complexity_gauge,
            entity_operations_total,
            entity_cache_operations,
            active_entities_gauge,
            http_requests_total,
            http_request_duration,
            http_request_size_bytes,
            http_response_size_bytes,
            http_requests_in_flight,
            security_violations_total,
            authorization_anomalies_total,
            rate_limit_enforcement_total,
            memory_usage_bytes,
            cpu_usage_percent,
            background_tasks_total,
            slo_violations_total,
            error_budget_consumption,
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

impl Default for PolicyMetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global policy metrics registry instance
pub static POLICY_METRICS: Lazy<PolicyMetricsRegistry> = Lazy::new(PolicyMetricsRegistry::new);

/// Advanced metrics middleware for policy service
pub async fn policy_metrics_middleware(req: Request, next: Next) -> Response {
    let start_time = Instant::now();
    let method = req.method().clone();
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map_or("unknown".to_string(), |p| {
            normalize_path_for_cardinality(p.as_str())
        });

    // Extract client ID with cardinality protection
    let client_id = extract_client_id_with_protection(&req);

    // Extract request size
    let request_size = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    // Increment in-flight requests
    POLICY_METRICS.http_requests_in_flight.inc();

    // Process request
    let response = next.run(req).await;

    // Decrement in-flight requests
    POLICY_METRICS.http_requests_in_flight.dec();

    // Calculate response time
    let duration = start_time.elapsed();
    let status_code = response.status();

    // Extract response size
    let response_size = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0);

    // Record metrics
    POLICY_METRICS
        .http_requests_total
        .with_label_values(&[
            method.as_str(),
            &path,
            &status_code.as_u16().to_string(),
            &client_id,
        ])
        .inc();

    POLICY_METRICS
        .http_request_duration
        .with_label_values(&[method.as_str(), &path])
        .observe(duration.as_secs_f64());

    if request_size > 0.0 {
        POLICY_METRICS
            .http_request_size_bytes
            .with_label_values(&[method.as_str(), &path])
            .observe(request_size);
    }

    if response_size > 0.0 {
        POLICY_METRICS
            .http_response_size_bytes
            .with_label_values(&[method.as_str(), &path, &status_code.as_u16().to_string()])
            .observe(response_size);
    }

    // Record SLO metrics (50ms SLO for authorization decisions)
    let latency_slo_violation = duration.as_millis() > 50;
    if latency_slo_violation && path.contains("/authorize") {
        POLICY_METRICS
            .slo_violations_total
            .with_label_values(&["latency", "warning", "authorization"])
            .inc();
    }

    debug!(
        method = %method,
        path = %path,
        status = %status_code,
        duration_ms = %duration.as_millis(),
        client_id = %client_id,
        request_size = %request_size,
        response_size = %response_size,
        slo_violation = %latency_slo_violation,
        "Policy service HTTP request processed"
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
    let mut normalized = match path {
        p if p.starts_with("/v1/authorize") => "/v1/authorize".to_string(),
        p if p.starts_with("/health") => "/health".to_string(),
        p if p.starts_with("/metrics") => "/metrics".to_string(),
        p if p.starts_with("/v1/policies/") => "/v1/policies/:id".to_string(),
        p if p.starts_with("/v1/entities/") => "/v1/entities/:id".to_string(),
        p => p.to_string(),
    };
    // Coarse normalization: collapse UUID-like and long hex segments to :id tokens to further bound cardinality
    // This is a conservative best-effort without regex to avoid extra deps.
    if normalized == path {
        let parts: Vec<&str> = path.split('/').collect();
        let mapped: Vec<String> = parts
            .into_iter()
            .map(|seg| {
                if seg.len() >= 16
                    && seg
                        .chars()
                        .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_')
                {
                    ":id".to_string()
                } else if seg.chars().all(|c| c.is_ascii_digit()) && seg.len() > 6 {
                    ":id".to_string()
                } else {
                    seg.to_string()
                }
            })
            .collect();
        normalized = mapped.join("/");
        if !normalized.starts_with('/') {
            normalized = format!("/{}", normalized);
        }
    }
    normalized
}

/// Prometheus metrics endpoint handler for policy service
pub async fn policy_metrics_handler() -> impl IntoResponse {
    match POLICY_METRICS.gather_metrics() {
        Ok(metrics) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            metrics,
        ),
        Err(e) => {
            error!("Failed to gather policy metrics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("content-type", "text/plain")],
                format!("Error gathering metrics: {e}"),
            )
        }
    }
}

/// Helper functions for policy-specific metrics
pub struct PolicyMetricsHelper;

impl PolicyMetricsHelper {
    /// Record an authorization request with detailed context
    pub fn record_authorization_request(
        decision: &str,
        principal_type: &str,
        action_type: &str,
        resource_type: &str,
        client_id: &str,
        duration: Duration,
        policy_complexity: &str,
    ) {
        POLICY_METRICS
            .authorization_requests_total
            .with_label_values(&[
                decision,
                principal_type,
                action_type,
                resource_type,
                client_id,
            ])
            .inc();

        POLICY_METRICS
            .authorization_duration
            .with_label_values(&[decision, policy_complexity])
            .observe(duration.as_secs_f64());
    }

    /// Record a policy evaluation error
    #[allow(dead_code)]
    pub fn record_policy_evaluation_error(error_type: &str, error_cause: &str, policy_id: &str) {
        POLICY_METRICS
            .policy_evaluation_errors_total
            .with_label_values(&[error_type, error_cause, policy_id])
            .inc();
    }

    /// Record the number of policies evaluated for a request
    pub fn record_policies_evaluated(request_type: &str, count: f64) {
        POLICY_METRICS
            .policies_evaluated_per_request
            .with_label_values(&[request_type])
            .observe(count);
    }

    /// Record an authorization anomaly
    #[allow(dead_code)]
    pub fn record_authorization_anomaly(
        anomaly_type: &str,
        confidence: &str,
        principal: &str,
        action_taken: &str,
    ) {
        POLICY_METRICS
            .authorization_anomalies_total
            .with_label_values(&[anomaly_type, confidence, principal, action_taken])
            .inc();
    }

    /// Record SLO violation
    #[allow(dead_code)]
    pub fn record_slo_violation(slo_type: &str, severity: &str, component: &str) {
        POLICY_METRICS
            .slo_violations_total
            .with_label_values(&[slo_type, severity, component])
            .inc();
    }

    /// Update error budget consumption
    #[allow(dead_code)]
    pub fn update_error_budget_consumption(
        slo_type: &str,
        time_window: &str,
        component: &str,
        consumption: i64,
    ) {
        // Reset and set new value
        let metric = POLICY_METRICS.error_budget_consumption.with_label_values(&[
            slo_type,
            time_window,
            component,
        ]);

        metric.reset();
        for _ in 0..consumption {
            metric.inc();
        }
    }
}

/// Macros for convenient policy metrics usage
#[macro_export]
macro_rules! record_authorization {
    ($decision:expr, $principal_type:expr, $action_type:expr, $resource_type:expr, $client_id:expr, $duration:expr) => {
        $crate::metrics::PolicyMetricsHelper::record_authorization_request(
            $decision,
            $principal_type,
            $action_type,
            $resource_type,
            $client_id,
            $duration,
            "standard",
        );
    };
}

#[macro_export]
macro_rules! record_policy_error {
    ($error_type:expr, $error_cause:expr, $policy_id:expr) => {
        $crate::metrics::PolicyMetricsHelper::record_policy_evaluation_error(
            $error_type,
            $error_cause,
            $policy_id,
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_policy_metrics_registry_creation() {
        let metrics = PolicyMetricsRegistry::new();
        assert!(!metrics.registry.gather().is_empty());
    }

    #[test]
    fn test_authorization_recording() {
        PolicyMetricsHelper::record_authorization_request(
            "Allow",
            "User",
            "Read",
            "Document",
            "test-client",
            Duration::from_millis(5),
            "simple",
        );
    }

    #[test]
    fn test_policy_error_recording() {
        PolicyMetricsHelper::record_policy_evaluation_error(
            "ValidationError",
            "InvalidSyntax",
            "policy-123",
        );
    }

    #[test]
    fn test_cardinality_protection() {
        assert!(is_valid_client_id("valid-client-123"));
        assert!(!is_valid_client_id("invalid/client/with/slashes"));
        assert!(!is_valid_client_id(&"x".repeat(100)));
    }
}
