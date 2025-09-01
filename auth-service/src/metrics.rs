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

#![cfg(feature = "monitoring")]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::{
    extract::{MatchedPath, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
#[cfg(feature = "monitoring")]
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, Opts, Registry, TextEncoder,
};
use std::sync::LazyLock;
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
    ///
    /// Initializes all metric collectors and registers them with the Prometheus registry.
    /// The initialization is broken down into logical groups for better maintainability.
    ///
    /// # Returns
    /// A new `MetricsRegistry` instance with all metrics initialized and registered.
    #[must_use]
    pub fn new() -> Self {
        let registry = Registry::new();
        let metrics_groups = Self::create_all_metric_groups();
        Self::register_all_metrics(&registry, &metrics_groups);
        Self::build_registry(registry, metrics_groups)
    }

    /// Create all metric groups
    ///
    /// Creates and returns all metric groups in a structured format.
    ///
    /// # Returns
    /// A tuple containing all metric groups.
    fn create_all_metric_groups() -> (
        (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec, HistogramVec, IntCounterVec),
        (IntCounterVec, HistogramVec, IntCounterVec, IntCounterVec),
        (IntCounterVec, HistogramVec, IntCounterVec, HistogramVec),
        (IntCounterVec, HistogramVec, HistogramVec, HistogramVec, IntGauge),
        (IntCounterVec, IntCounterVec, HistogramVec),
        (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec),
        (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec),
    ) {
        (
            Self::create_token_metrics(),
            Self::create_policy_metrics(),
            Self::create_cache_metrics(),
            Self::create_http_metrics(),
            Self::create_rate_limit_metrics(),
            Self::create_security_metrics(),
            Self::create_system_metrics(),
        )
    }

    /// Register all metrics with the registry
    ///
    /// Takes all metric groups and registers them with the Prometheus registry.
    ///
    /// # Arguments
    /// * `registry` - The Prometheus registry to register metrics with
    /// * `metrics_groups` - Tuple containing all metric groups
    fn register_all_metrics(
        registry: &Registry,
        metrics_groups: &(
            (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec, HistogramVec, IntCounterVec),
            (IntCounterVec, HistogramVec, IntCounterVec, IntCounterVec),
            (IntCounterVec, HistogramVec, IntCounterVec, HistogramVec),
            (IntCounterVec, HistogramVec, HistogramVec, HistogramVec, IntGauge),
            (IntCounterVec, IntCounterVec, HistogramVec),
            (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec),
            (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec),
        ),
    ) {
        let all_metrics = Self::collect_all_metrics(
            &metrics_groups.0,
            &metrics_groups.1,
            &metrics_groups.2,
            &metrics_groups.3,
            &metrics_groups.4,
            &metrics_groups.5,
            &metrics_groups.6,
        );
        Self::register_metrics(registry, all_metrics);
    }

    /// Build the final MetricsRegistry struct
    ///
    /// Constructs the MetricsRegistry with all metrics from the groups.
    ///
    /// # Arguments
    /// * `registry` - The Prometheus registry
    /// * `metrics_groups` - Tuple containing all metric groups
    ///
    /// # Returns
    /// A new MetricsRegistry instance
    fn build_registry(
        registry: Registry,
        metrics_groups: (
            (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec, HistogramVec, IntCounterVec),
            (IntCounterVec, HistogramVec, IntCounterVec, IntCounterVec),
            (IntCounterVec, HistogramVec, IntCounterVec, HistogramVec),
            (IntCounterVec, HistogramVec, HistogramVec, HistogramVec, IntGauge),
            (IntCounterVec, IntCounterVec, HistogramVec),
            (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec),
            (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec),
        ),
    ) -> Self {
        let (token_metrics, policy_metrics, cache_metrics, http_metrics, rate_limit_metrics, security_metrics, system_metrics) = metrics_groups;

        Self {
            registry,
            token_issuance_total: token_metrics.0,
            token_validation_total: token_metrics.1,
            token_revocation_total: token_metrics.2,
            token_introspection_total: token_metrics.3,
            token_operation_duration: token_metrics.4,
            active_tokens_gauge: token_metrics.5,
            policy_evaluation_total: policy_metrics.0,
            policy_evaluation_duration: policy_metrics.1,
            policy_cache_operations: policy_metrics.2,
            policy_compilation_total: policy_metrics.3,
            cache_operations_total: cache_metrics.0,
            cache_hit_ratio: cache_metrics.1,
            cache_size_gauge: cache_metrics.2,
            cache_operation_duration: cache_metrics.3,
            http_requests_total: http_metrics.0,
            http_request_duration: http_metrics.1,
            http_request_size_bytes: http_metrics.2,
            http_response_size_bytes: http_metrics.3,
            http_requests_in_flight: http_metrics.4,
            rate_limit_enforcement_total: rate_limit_metrics.0,
            rate_limit_quota_gauge: rate_limit_metrics.1,
            rate_limit_reset_duration: rate_limit_metrics.2,
            auth_attempts_detailed: security_metrics.0,
            mfa_operations_total: security_metrics.1,
            security_violations_total: security_metrics.2,
            anomaly_detection_total: security_metrics.3,
            system_resources_gauge: system_metrics.0,
            background_task_total: system_metrics.1,
            connection_health_gauge: system_metrics.2,
            circuit_breaker_state_changes: system_metrics.3,
        }
    }

    /// Create token operation metrics
    ///
    /// Initializes all metrics related to token operations including issuance,
    /// validation, revocation, and introspection.
    ///
    /// # Returns
    /// A tuple containing all token-related metrics.
    fn create_token_metrics() -> (
        IntCounterVec,
        IntCounterVec,
        IntCounterVec,
        IntCounterVec,
        HistogramVec,
        IntCounterVec,
    ) {
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

        (
            token_issuance_total,
            token_validation_total,
            token_revocation_total,
            token_introspection_total,
            token_operation_duration,
            active_tokens_gauge,
        )
    }

    /// Create policy evaluation metrics
    ///
    /// Initializes all metrics related to policy evaluation, caching, and compilation.
    ///
    /// # Returns
    /// A tuple containing all policy-related metrics.
    fn create_policy_metrics() -> (IntCounterVec, HistogramVec, IntCounterVec, IntCounterVec) {
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

        (
            policy_evaluation_total,
            policy_evaluation_duration,
            policy_cache_operations,
            policy_compilation_total,
        )
    }

    /// Create cache operation metrics
    ///
    /// Initializes all metrics related to cache operations, hit ratios, and performance.
    ///
    /// # Returns
    /// A tuple containing all cache-related metrics.
    fn create_cache_metrics() -> (IntCounterVec, HistogramVec, IntCounterVec, HistogramVec) {
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

        (
            cache_operations_total,
            cache_hit_ratio,
            cache_size_gauge,
            cache_operation_duration,
        )
    }

    /// Create HTTP request metrics
    ///
    /// Initializes all metrics related to HTTP requests, responses, and processing.
    ///
    /// # Returns
    /// A tuple containing all HTTP-related metrics.
    fn create_http_metrics() -> (IntCounterVec, HistogramVec, HistogramVec, HistogramVec, IntGauge) {
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
                .buckets(Self::get_size_buckets()),
            &["method", "endpoint"],
        )
        .expect("Failed to create http_request_size_bytes metric");

        let http_response_size_bytes = HistogramVec::new(
            HistogramOpts::new(
                "auth_http_response_size_bytes",
                "HTTP response size in bytes",
            )
            .buckets(Self::get_size_buckets()),
            &["method", "endpoint", "status_code"],
        )
        .expect("Failed to create http_response_size_bytes metric");

        let http_requests_in_flight = IntGauge::new(
            "auth_http_requests_in_flight",
            "Number of HTTP requests currently being processed",
        )
        .expect("Failed to create http_requests_in_flight metric");

        (
            http_requests_total,
            http_request_duration,
            http_request_size_bytes,
            http_response_size_bytes,
            http_requests_in_flight,
        )
    }

    /// Create rate limiting metrics
    ///
    /// Initializes all metrics related to rate limiting enforcement and quotas.
    ///
    /// # Returns
    /// A tuple containing all rate limiting-related metrics.
    fn create_rate_limit_metrics() -> (IntCounterVec, IntCounterVec, HistogramVec) {
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

        (
            rate_limit_enforcement_total,
            rate_limit_quota_gauge,
            rate_limit_reset_duration,
        )
    }

    /// Create security event metrics
    ///
    /// Initializes all metrics related to security events, authentication, and MFA.
    ///
    /// # Returns
    /// A tuple containing all security-related metrics.
    fn create_security_metrics() -> (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec) {
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

        (
            auth_attempts_detailed,
            mfa_operations_total,
            security_violations_total,
            anomaly_detection_total,
        )
    }

    /// Create system health metrics
    ///
    /// Initializes all metrics related to system resources, background tasks, and connections.
    ///
    /// # Returns
    /// A tuple containing all system-related metrics.
    fn create_system_metrics() -> (IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec) {
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

        (
            system_resources_gauge,
            background_task_total,
            connection_health_gauge,
            circuit_breaker_state_changes,
        )
    }

    /// Get common size buckets for byte measurements
    ///
    /// Provides a consistent set of histogram buckets for measuring sizes in bytes.
    ///
    /// # Returns
    /// A vector of bucket boundaries for byte measurements.
    fn get_size_buckets() -> Vec<f64> {
        vec![
            64.0,
            256.0,
            1024.0,
            4096.0,
            16384.0,
            65_536.0,
            262_144.0,
            1_048_576.0,
        ]
    }

    /// Collect all metrics into a single vector for registration
    ///
    /// Aggregates all metrics from different categories into a single collection
    /// for batch registration with the Prometheus registry.
    ///
    /// # Arguments
    /// * `token_metrics` - Token operation metrics
    /// * `policy_metrics` - Policy evaluation metrics
    /// * `cache_metrics` - Cache operation metrics
    /// * `http_metrics` - HTTP request metrics
    /// * `rate_limit_metrics` - Rate limiting metrics
    /// * `security_metrics` - Security event metrics
    /// * `system_metrics` - System health metrics
    ///
    /// # Returns
    /// A vector containing all metrics as boxed collectors.
    #[allow(clippy::too_many_arguments)]
    fn collect_all_metrics(
        token_metrics: &(
            IntCounterVec,
            IntCounterVec,
            IntCounterVec,
            IntCounterVec,
            HistogramVec,
            IntCounterVec,
        ),
        policy_metrics: &(IntCounterVec, HistogramVec, IntCounterVec, IntCounterVec),
        cache_metrics: &(IntCounterVec, HistogramVec, IntCounterVec, HistogramVec),
        http_metrics: &(IntCounterVec, HistogramVec, HistogramVec, HistogramVec, IntGauge),
        rate_limit_metrics: &(IntCounterVec, IntCounterVec, HistogramVec),
        security_metrics: &(IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec),
        system_metrics: &(IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec),
    ) -> Vec<Box<dyn prometheus::core::Collector>> {
        let mut all_metrics = Vec::new();
        
        // Collect each metric group separately
        all_metrics.extend(Self::collect_token_metrics(token_metrics));
        all_metrics.extend(Self::collect_policy_metrics(policy_metrics));
        all_metrics.extend(Self::collect_cache_metrics(cache_metrics));
        all_metrics.extend(Self::collect_http_metrics(http_metrics));
        all_metrics.extend(Self::collect_rate_limit_metrics(rate_limit_metrics));
        all_metrics.extend(Self::collect_security_metrics(security_metrics));
        all_metrics.extend(Self::collect_system_metrics(system_metrics));
        
        all_metrics
    }

    /// Collect token metrics into boxed collectors
    fn collect_token_metrics(
        token_metrics: &(
            IntCounterVec,
            IntCounterVec,
            IntCounterVec,
            IntCounterVec,
            HistogramVec,
            IntCounterVec,
        ),
    ) -> Vec<Box<dyn prometheus::core::Collector>> {
        vec![
            Box::new(token_metrics.0.clone()),
            Box::new(token_metrics.1.clone()),
            Box::new(token_metrics.2.clone()),
            Box::new(token_metrics.3.clone()),
            Box::new(token_metrics.4.clone()),
            Box::new(token_metrics.5.clone()),
        ]
    }

    /// Collect policy metrics into boxed collectors
    fn collect_policy_metrics(
        policy_metrics: &(IntCounterVec, HistogramVec, IntCounterVec, IntCounterVec),
    ) -> Vec<Box<dyn prometheus::core::Collector>> {
        vec![
            Box::new(policy_metrics.0.clone()),
            Box::new(policy_metrics.1.clone()),
            Box::new(policy_metrics.2.clone()),
            Box::new(policy_metrics.3.clone()),
        ]
    }

    /// Collect cache metrics into boxed collectors
    fn collect_cache_metrics(
        cache_metrics: &(IntCounterVec, HistogramVec, IntCounterVec, HistogramVec),
    ) -> Vec<Box<dyn prometheus::core::Collector>> {
        vec![
            Box::new(cache_metrics.0.clone()),
            Box::new(cache_metrics.1.clone()),
            Box::new(cache_metrics.2.clone()),
            Box::new(cache_metrics.3.clone()),
        ]
    }

    /// Collect HTTP metrics into boxed collectors
    fn collect_http_metrics(
        http_metrics: &(IntCounterVec, HistogramVec, HistogramVec, HistogramVec, IntGauge),
    ) -> Vec<Box<dyn prometheus::core::Collector>> {
        vec![
            Box::new(http_metrics.0.clone()),
            Box::new(http_metrics.1.clone()),
            Box::new(http_metrics.2.clone()),
            Box::new(http_metrics.3.clone()),
            Box::new(http_metrics.4.clone()),
        ]
    }

    /// Collect rate limit metrics into boxed collectors
    fn collect_rate_limit_metrics(
        rate_limit_metrics: &(IntCounterVec, IntCounterVec, HistogramVec),
    ) -> Vec<Box<dyn prometheus::core::Collector>> {
        vec![
            Box::new(rate_limit_metrics.0.clone()),
            Box::new(rate_limit_metrics.1.clone()),
            Box::new(rate_limit_metrics.2.clone()),
        ]
    }

    /// Collect security metrics into boxed collectors
    fn collect_security_metrics(
        security_metrics: &(IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec),
    ) -> Vec<Box<dyn prometheus::core::Collector>> {
        vec![
            Box::new(security_metrics.0.clone()),
            Box::new(security_metrics.1.clone()),
            Box::new(security_metrics.2.clone()),
            Box::new(security_metrics.3.clone()),
        ]
    }

    /// Collect system metrics into boxed collectors
    fn collect_system_metrics(
        system_metrics: &(IntCounterVec, IntCounterVec, IntCounterVec, IntCounterVec),
    ) -> Vec<Box<dyn prometheus::core::Collector>> {
        vec![
            Box::new(system_metrics.0.clone()),
            Box::new(system_metrics.1.clone()),
            Box::new(system_metrics.2.clone()),
            Box::new(system_metrics.3.clone()),
        ]
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
    ///
    /// # Errors
    /// Returns an error if:
    /// - Metric encoding fails
    /// - UTF-8 conversion of metrics buffer fails
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
pub static METRICS: LazyLock<MetricsRegistry> = LazyLock::new(MetricsRegistry::new);

/// Advanced metrics middleware with high-cardinality protection
pub async fn metrics_middleware(req: Request, next: Next) -> Response {
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
pub fn metrics_handler() -> impl IntoResponse {
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
                format!("Error gathering metrics: {e}"),
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

        let result_label = if result.is_ok() { "success" } else { "error" };

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
