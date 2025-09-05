//! Simple metrics implementation for MVP policy service

use std::time::Duration;
use axum::response::{IntoResponse, Response};

/// Record authorization request metrics
pub fn record_authorization_request(
    _decision: &str,
    _principal_type: &str, 
    _action_type: &str,
    _resource_type: &str,
    _client_id: &str,
    _duration: Duration,
    _policy_type: &str,
) {
    // For MVP, just log metrics
    tracing::info!(
        decision = _decision,
        principal_type = _principal_type,
        action_type = _action_type,
        resource_type = _resource_type,
        client_id = _client_id,
        duration_ms = _duration.as_millis(),
        policy_type = _policy_type,
        "Authorization request recorded"
    );
}

/// Record policy evaluation metrics  
pub fn record_policies_evaluated(_operation: &str, _count: f64) {
    tracing::debug!(
        operation = _operation,
        count = _count,
        "Policy evaluation recorded"
    );
}

/// Policy metrics helper for MVP
pub struct PolicyMetricsHelper;

impl PolicyMetricsHelper {
    pub fn record_authorization_request(
        decision: &str,
        principal_type: &str,
        action_type: &str,
        resource_type: &str,
        client_id: &str,
        duration: Duration,
        policy_type: &str,
    ) {
        record_authorization_request(decision, principal_type, action_type, resource_type, client_id, duration, policy_type);
    }
    
    pub fn record_policies_evaluated(operation: &str, count: f64) {
        record_policies_evaluated(operation, count);
    }
}

/// MVP metrics handler
pub async fn policy_metrics_handler() -> impl IntoResponse {
    let metrics = format!(
        "# HELP policy_service_requests_total Total authorization requests\n\
         # TYPE policy_service_requests_total counter\n\
         policy_service_requests_total 0\n\
         \n\
         # HELP policy_service_up Service health status\n\
         # TYPE policy_service_up gauge\n\
         policy_service_up 1\n"
    );
    
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "text/plain; charset=utf-8")
        .body(axum::body::Body::from(metrics))
        .unwrap()
}

/// MVP metrics middleware
pub async fn policy_metrics_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let start = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    let response = next.run(req).await;
    let duration = start.elapsed();
    
    tracing::debug!(
        method = %method,
        uri = %uri, 
        status = %response.status(),
        duration_ms = duration.as_millis(),
        "Request metrics recorded"
    );
    
    response
}