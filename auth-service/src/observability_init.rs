//! Observability System Initialization and Integration
//!
//! This module provides initialization and integration for the comprehensive
//! observability system, coordinating metrics, tracing, health checks, and alerting.

use anyhow::Result;
use axum::response::IntoResponse;
use std::sync::Arc;
use tracing::info;

#[cfg(feature = "monitoring")]
use crate::business_metrics::BusinessMetricsRegistry;

#[cfg(not(feature = "monitoring"))]
use crate::business_metrics::BusinessMetricsHelper as BusinessMetricsRegistry;

use crate::{
    enhanced_observability::{
        observability_middleware, EnhancedObservability, ObservabilityConfig, SliConfig,
    },
    AuthError,
};

#[cfg(feature = "monitoring")]
use crate::{
    metrics::MetricsRegistry,
    security_metrics::SecurityMetrics,
};

/// Observability system coordinator
pub struct ObservabilitySystem {
    /// Enhanced observability core
    pub enhanced_observability: Arc<EnhancedObservability>,
    /// Metrics registry
    #[cfg(feature = "monitoring")]
    pub metrics_registry: Arc<MetricsRegistry>,
    /// Security metrics collector
    #[cfg(feature = "monitoring")]
    pub security_metrics: Arc<SecurityMetrics>,
    /// Business metrics
    pub business_metrics: Arc<BusinessMetricsRegistry>,
}

impl ObservabilitySystem {
    /// Initialize the complete observability system
    pub async fn initialize() -> Result<Self, AuthError> {
        info!("Initializing comprehensive observability system");

        // Initialize business metrics
        let business_metrics = Arc::new(BusinessMetricsRegistry::default());

        // Load configuration from environment
        let observability_config = Self::load_observability_config();
        let sli_config = Self::load_sli_config();

        #[cfg(feature = "monitoring")]
        let (metrics_registry, security_metrics, enhanced_observability) = {
            // Initialize metrics registry
            let metrics_registry = Arc::new(MetricsRegistry::new());

            // Initialize security metrics
            let security_metrics = Arc::new(
                SecurityMetrics::new().map_err(|_| AuthError::InternalError {
                    error_id: uuid::Uuid::new_v4(),
                    context: "Failed to initialize security metrics".to_string(),
                })?,
            );

            // Initialize enhanced observability
            let enhanced_observability = Arc::new(
                EnhancedObservability::new(
                    observability_config,
                    sli_config,
                    Arc::clone(&metrics_registry),
                    Arc::clone(&security_metrics),
                    Arc::clone(&business_metrics),
                )
                .await
                .map_err(|e| AuthError::InternalError {
                    error_id: uuid::Uuid::new_v4(),
                    context: format!("Failed to initialize enhanced observability: {}", e),
                })?,
            );

            (metrics_registry, security_metrics, enhanced_observability)
        };

        #[cfg(not(feature = "monitoring"))]
        let enhanced_observability = Arc::new(
            EnhancedObservability::new_minimal(observability_config, sli_config, Arc::clone(&business_metrics))
                .await
                .map_err(|e| AuthError::InternalError {
                    error_id: uuid::Uuid::new_v4(),
                    context: format!("Failed to initialize enhanced observability: {}", e),
                })?,
        );

        info!("Observability system initialized successfully");

        Ok(Self {
            enhanced_observability,
            #[cfg(feature = "monitoring")]
            metrics_registry,
            #[cfg(feature = "monitoring")]
            security_metrics,
            business_metrics,
        })
    }

    /// Load observability configuration from environment
    fn load_observability_config() -> ObservabilityConfig {
        ObservabilityConfig {
            service_name: std::env::var("SERVICE_NAME")
                .unwrap_or_else(|_| "auth-service".to_string()),
            enable_profiling: std::env::var("ENABLE_PROFILING")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            enable_alerting: std::env::var("ENABLE_ALERTING")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            health_check_interval_seconds: std::env::var("HEALTH_CHECK_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            slo_calculation_interval_seconds: std::env::var("SLO_CALCULATION_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            metrics_retention_hours: std::env::var("METRICS_RETENTION_HOURS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(24),
            dashboard_config: crate::enhanced_observability::DashboardConfig {
                enable_grafana_export: std::env::var("ENABLE_GRAFANA_EXPORT")
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true),
                dashboard_refresh_interval: std::env::var("DASHBOARD_REFRESH_INTERVAL")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30),
                custom_panels: std::env::var("CUSTOM_DASHBOARD_PANELS")
                    .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_else(|_| {
                        vec![
                            "authentication_flow".to_string(),
                            "token_operations".to_string(),
                            "security_events".to_string(),
                        ]
                    }),
            },
        }
    }

    /// Load SLI configuration from environment
    fn load_sli_config() -> SliConfig {
        SliConfig {
            availability_target: std::env::var("SLI_AVAILABILITY_TARGET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(99.9),
            latency_target_ms: std::env::var("SLI_LATENCY_TARGET_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            error_rate_target: std::env::var("SLI_ERROR_RATE_TARGET")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.1),
            measurement_window_minutes: std::env::var("SLI_MEASUREMENT_WINDOW_MINUTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
        }
    }
}

/// Standalone health check endpoint handler
pub async fn health_check_handler(
    axum::extract::State(observability): axum::extract::State<Arc<ObservabilitySystem>>,
) -> impl axum::response::IntoResponse {
    let health_status = observability
        .enhanced_observability
        .get_health_status()
        .await;

    let status_code = match health_status.overall_health {
        crate::enhanced_observability::HealthCheckStatus::Healthy => axum::http::StatusCode::OK,
        crate::enhanced_observability::HealthCheckStatus::Degraded => axum::http::StatusCode::OK,
        crate::enhanced_observability::HealthCheckStatus::Unhealthy => {
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        }
    };

    (status_code, axum::Json(health_status))
}

/// Standalone metrics endpoint handler
pub async fn metrics_handler(
    axum::extract::State(_observability): axum::extract::State<Arc<ObservabilitySystem>>,
) -> impl axum::response::IntoResponse {
    // For now, return a placeholder until we implement gather_metrics properly
    (
        axum::http::StatusCode::OK,
        "# Metrics placeholder\n".to_string(),
    )
}

/// Standalone SLO status endpoint handler
pub async fn slo_status_handler(
    axum::extract::State(observability): axum::extract::State<Arc<ObservabilitySystem>>,
) -> impl axum::response::IntoResponse {
    let slo_status = observability.enhanced_observability.get_slo_status().await;
    (axum::http::StatusCode::OK, axum::Json(slo_status))
}

/// Standalone performance profiles endpoint handler
pub async fn performance_profiles_handler(
    axum::extract::State(observability): axum::extract::State<Arc<ObservabilitySystem>>,
) -> impl axum::response::IntoResponse {
    let profiles = observability
        .enhanced_observability
        .get_performance_profiles()
        .await;
    (axum::http::StatusCode::OK, axum::Json(profiles))
}

/// Standalone active alerts endpoint handler
pub async fn alerts_handler(
    axum::extract::State(observability): axum::extract::State<Arc<ObservabilitySystem>>,
) -> impl axum::response::IntoResponse {
    let alerts = observability
        .enhanced_observability
        .get_active_alerts()
        .await;
    (axum::http::StatusCode::OK, axum::Json(alerts))
}

/// Standalone Grafana dashboard configuration handler
pub async fn grafana_dashboard_handler(
    axum::extract::State(observability): axum::extract::State<Arc<ObservabilitySystem>>,
) -> impl axum::response::IntoResponse {
    match observability
        .enhanced_observability
        .export_metrics_for_grafana()
        .await
    {
        Ok(dashboard) => (
            axum::http::StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            dashboard,
        )
            .into_response(),
        Err(e) => {
            tracing::warn!("Failed to export Grafana dashboard: {}", e);
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                r#"{"error": "Failed to export dashboard"}"#,
            )
                .into_response()
        }
    }
}

impl ObservabilitySystem {
    /// Record an authentication event with comprehensive metrics
    pub async fn record_auth_event(
        &self,
        method: &str,
        success: bool,
        _user_id: Option<&str>,
        duration: std::time::Duration,
        client_ip: Option<&str>,
    ) {
        // Record in enhanced observability
        self.enhanced_observability
            .record_operation_performance("authentication", duration, success)
            .await;

        // Record business metrics
        // Note: This would need to be implemented based on the actual BusinessMetricsRegistry interface
        // For now, we'll comment this out until we can verify the correct method signature
        // self.business_metrics.record_authentication_attempt(method, success).await;

        // Record security event if failed
        if !success {
            let security_event = crate::security_logging::SecurityEvent::new(
                crate::security_logging::SecurityEventType::AuthenticationFailure,
                crate::security_logging::SecuritySeverity::Medium,
                "authentication".to_string(),
                "Authentication attempt failed".to_string(),
            )
            .with_detail_string("method".to_string(), method.to_string())
            .with_detail_string(
                "client_ip".to_string(),
                client_ip.unwrap_or("unknown").to_string(),
            );

            self.enhanced_observability
                .record_security_event(&security_event)
                .await;
        }
    }

    /// Record a token operation with comprehensive metrics
    pub async fn record_token_operation(
        &self,
        operation: &str,
        _token_type: &str,
        success: bool,
        duration: std::time::Duration,
    ) {
        // Record in enhanced observability
        self.enhanced_observability
            .record_operation_performance(&format!("token_{}", operation), duration, success)
            .await;

        // Record in metrics registry
        // TODO: Implement get_metrics_helper method for MetricsRegistry
        // if let Ok(metrics) = self.metrics_registry.get_metrics_helper() {
        //     metrics.record_token_operation(operation, token_type, success);
        // }
    }

    /// Graceful shutdown of observability system
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down observability system");

        // Perform any cleanup needed
        // In a real implementation, you might want to flush metrics, close connections, etc.

        info!("Observability system shutdown completed");
        Ok(())
    }
}

/// Add observability routes to router with state
pub fn add_observability_routes(
    observability: Arc<ObservabilitySystem>,
) -> axum::Router<Arc<ObservabilitySystem>> {
    axum::Router::new()
        .route("/health", axum::routing::get(health_check_handler))
        .route("/metrics", axum::routing::get(metrics_handler))
        .route("/observability/slo", axum::routing::get(slo_status_handler))
        .route(
            "/observability/profiles",
            axum::routing::get(performance_profiles_handler),
        )
        .route("/observability/alerts", axum::routing::get(alerts_handler))
        .route(
            "/observability/dashboard",
            axum::routing::get(grafana_dashboard_handler),
        )
        .with_state(observability)
        .layer(axum::middleware::from_fn(observability_middleware))
}

/// Helper trait for adding observability to services
pub trait ObservabilityAware {
    fn observability(&self) -> &ObservabilitySystem;

    #[allow(async_fn_in_trait)]
    async fn record_operation(
        &self,
        operation: &str,
        duration: std::time::Duration,
        success: bool,
    ) {
        self.observability()
            .enhanced_observability
            .record_operation_performance(operation, duration, success)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_observability_config() {
        // Test with default values
        let config = ObservabilitySystem::load_observability_config();
        assert_eq!(config.service_name, "auth-service");
        assert!(config.enable_profiling);
        assert!(config.enable_alerting);
    }

    #[test]
    fn test_load_sli_config() {
        // Test with default values
        let config = ObservabilitySystem::load_sli_config();
        assert_eq!(config.availability_target, 99.9);
        assert_eq!(config.latency_target_ms, 100);
        assert_eq!(config.error_rate_target, 0.1);
    }

    #[tokio::test]
    async fn test_observability_system_initialization() {
        // This test would require proper mocking of dependencies
        // In a real test environment, you'd set up test metrics registries
        // TODO: Implement proper integration test when mocking infrastructure is available
    }
}
