//! Service integration for metrics collection
//!
//! This module provides integration points for services to collect and expose metrics.

use crate::ProductionMetrics;
use axum::{extract::MatchedPath, http::Request, middleware::Next, response::Response};
use std::time::Instant;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

/// Middleware to collect HTTP request metrics
pub async fn metrics_middleware<B>(
    metrics: &ProductionMetrics,
    matched_path: Option<MatchedPath>,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let path = matched_path
        .map(|mp| mp.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    // Track active connections
    metrics.active_connections.inc();

    let response = next.run(req).await;

    let duration = start.elapsed();
    let status = response.status().as_u16().to_string();

    // Record request metrics
    metrics.record_request(&path, method.as_str(), &status, duration);

    // Track active connections
    metrics.active_connections.dec();

    response
}

/// Authentication service metrics integration
pub mod auth_integration {
    use super::*;
    use std::time::Duration;

    /// Record authentication attempt
    pub fn record_auth_attempt(metrics: &ProductionMetrics, duration: Duration, success: bool) {
        metrics.record_auth_request(duration, success);

        if !success {
            metrics.record_error("authentication_failure");
        }
    }

    /// Record rate limit check
    pub fn record_rate_limit_check(metrics: &ProductionMetrics, allowed: bool) {
        metrics.record_rate_limit(allowed);

        if !allowed {
            metrics.record_error("rate_limit_exceeded");
        }
    }
}

/// Authorization service metrics integration
pub mod authz_integration {
    use super::*;
    use std::time::Duration;

    /// Record authorization decision
    pub fn record_authz_decision(metrics: &ProductionMetrics, duration: Duration, allowed: bool) {
        metrics.record_authz_request(duration, allowed);

        if !allowed {
            metrics.record_error("authorization_denied");
        }
    }
}

/// Connection pool metrics integration
pub mod pool_integration {
    use super::*;
    use std::time::Duration;

    /// Record connection acquisition
    pub fn record_connection_acquisition(metrics: &ProductionMetrics, duration: Duration) {
        metrics.record_connection_acquisition(duration);
    }

    /// Update connection pool statistics
    pub fn update_pool_stats(metrics: &ProductionMetrics, active: u64, total: u64) {
        metrics.pool_connections_active.set(active as i64);
        metrics.pool_connections_total.set(total as i64);
    }
}

/// System metrics integration
pub mod system_integration {
    use super::*;

    /// Update system resource metrics
    pub fn update_system_metrics(metrics: &ProductionMetrics) {
        // In a real implementation, you would collect actual system metrics
        // For now, we'll use placeholder values

        // Memory usage (simplified - in practice, use system APIs)
        metrics.memory_usage_bytes.set(256 * 1024 * 1024); // 256MB placeholder
    }

    /// Update SLO budgets
    pub fn update_slo_budgets(metrics: &ProductionMetrics) {
        metrics.update_slo_budgets();
    }
}

/// Health check endpoint for monitoring
pub async fn health_check(metrics: &ProductionMetrics) -> axum::Json<serde_json::Value> {
    let uptime = metrics.uptime_seconds();

    // Update system metrics on health check
    system_integration::update_system_metrics(metrics);
    system_integration::update_slo_budgets(metrics);

    axum::Json(serde_json::json!({
        "status": "healthy",
        "uptime_seconds": uptime,
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Metrics endpoint for Prometheus scraping
pub async fn metrics_endpoint(metrics: &ProductionMetrics) -> String {
    metrics
        .gather()
        .unwrap_or_else(|_| "# Error gathering metrics\n".to_string())
}

/// Create metrics router
pub fn create_metrics_router(metrics: ProductionMetrics) -> axum::Router {
    use axum::{routing::get, Router};

    Router::new()
        .route("/health", get(move || health_check(&metrics)))
        .route("/metrics", get(move || metrics_endpoint(&metrics)))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

/// Example of how to integrate metrics into an existing service
pub mod example_integration {
    use super::*;

    /// Example authentication handler with metrics
    pub async fn example_auth_handler(
        metrics: &ProductionMetrics,
        // Other parameters...
    ) -> Result<impl axum::response::IntoResponse, axum::http::StatusCode> {
        let start = Instant::now();

        // Your authentication logic here...
        let success = true; // Replace with actual logic

        let duration = start.elapsed();
        auth_integration::record_auth_attempt(metrics, duration, success);

        if success {
            Ok(axum::Json(serde_json::json!({"token": "example_token"})))
        } else {
            Err(axum::http::StatusCode::UNAUTHORIZED)
        }
    }

    /// Example authorization handler with metrics
    pub async fn example_authz_handler(
        metrics: &ProductionMetrics,
        // Other parameters...
    ) -> Result<impl axum::response::IntoResponse, axum::http::StatusCode> {
        let start = Instant::now();

        // Your authorization logic here...
        let allowed = true; // Replace with actual logic

        let duration = start.elapsed();
        authz_integration::record_authz_decision(metrics, duration, allowed);

        if allowed {
            Ok(axum::Json(serde_json::json!({"decision": "allow"})))
        } else {
            Err(axum::http::StatusCode::FORBIDDEN)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_metrics_integration() {
        let metrics = ProductionMetrics::new().unwrap();

        // Test auth integration
        auth_integration::record_auth_attempt(&metrics, Duration::from_millis(50), true);
        auth_integration::record_auth_attempt(&metrics, Duration::from_millis(100), false);

        assert_eq!(metrics.auth_requests_total.get(), 2);
        assert_eq!(metrics.auth_success_total.get(), 1);
        assert_eq!(metrics.auth_failures_total.get(), 1);

        // Test authz integration
        authz_integration::record_authz_decision(&metrics, Duration::from_millis(10), true);
        authz_integration::record_authz_decision(&metrics, Duration::from_millis(20), false);

        assert_eq!(metrics.authz_requests_total.get(), 2);
        assert_eq!(metrics.authz_allow_total.get(), 1);
        assert_eq!(metrics.authz_deny_total.get(), 1);

        // Test error recording
        metrics.record_error("test_error");
        assert_eq!(metrics.errors_total.get(), 1);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let metrics = ProductionMetrics::new().unwrap();

        // Add some test data
        auth_integration::record_auth_attempt(&metrics, Duration::from_millis(50), true);

        let metrics_output = metrics_endpoint(&metrics).await;

        // Verify the metrics output contains expected data
        assert!(metrics_output.contains("auth_requests_total"));
        assert!(metrics_output.contains("auth_success_total"));
    }
}
