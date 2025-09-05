//! HTTP request handlers for MVP policy service

#![allow(clippy::multiple_crate_versions)]

use axum::{extract::State, http::HeaderMap, Json};
use std::sync::Arc;
use std::time::Instant;

use crate::errors::{AppError, AuthorizationError};
use crate::models::{AppState, AuthorizeRequest, AuthorizeResponse, PolicyConflict};
use crate::utils::{
    extract_action_type, extract_client_id_from_context, extract_entity_type, parse_entity,
};
use crate::validation::validate_authorization_input_with_context;

/// Simple metrics helper for MVP
pub struct PolicyMetricsHelper;

impl PolicyMetricsHelper {
    pub fn record_authorization_request(
        _decision: &str,
        _principal_type: &str,
        _action_type: &str,
        _resource_type: &str,
        _client_id: &str,
        _duration: std::time::Duration,
        _policy_type: &str,
    ) {
        // For MVP, just log metrics to console
        tracing::info!(
            decision = _decision,
            principal_type = _principal_type,
            action_type = _action_type,
            resource_type = _resource_type,
            client_id = _client_id,
            duration_ms = _duration.as_millis(),
            policy_type = _policy_type,
            "Authorization metrics recorded"
        );
    }
    
    pub fn record_policies_evaluated(_operation: &str, _count: f64) {
        tracing::debug!(
            operation = _operation,
            count = _count,
            "Policies evaluated"
        );
    }
}

#[utoipa::path(
    post,
    path = "/v1/authorize",
    tag = "authorization",
    request_body = crate::models::AuthorizeRequest,
    responses(
        (status = 200, description = "Authorization decision made successfully", body = crate::models::AuthorizeResponse),
        (status = 400, description = "Invalid request parameters"),
        (status = 500, description = "Internal server error")
    )
)]
/// Authorize a request using Cedar policies - MVP version
///
/// This function evaluates an authorization request against loaded Cedar policies
/// with enhanced security validation.
///
/// # Security Features
/// 
/// - Enhanced input validation with threat detection
/// - Client IP and User-Agent tracking
/// - Comprehensive request sanitization
/// - Structured security logging
///
/// # Request Format
///
/// ```json
/// {
///     "request_id": "unique-request-identifier",
///     "principal": {
///         "type": "User",
///         "id": "alice"
///     },
///     "action": "read",
///     "resource": {
///         "type": "Document",
///         "id": "doc-123"
///     },
///     "context": {
///         "time": "2024-01-15T10:30:00Z",
///         "ip_address": "192.168.1.100"
///     }
/// }
/// ```
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, AppError> {
    // Extract client information for security context
    let client_ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());
        
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Validate input for security and correctness with enhanced security context
    let validation_start = Instant::now();
    validate_authorization_input_with_context(&body, client_ip.clone(), user_agent.clone())?;
    let validation_duration = validation_start.elapsed();
    
    // Record validation metrics with security context
    PolicyMetricsHelper::record_policies_evaluated("validation", validation_duration.as_secs_f64());

    let action = cedar_policy::EntityUid::from_json(serde_json::json!({
        "type": "Action",
        "id": body.action.trim()
    }))
    .map_err(|e| AuthorizationError::InvalidAction {
        action: format!("{}: {}", body.action.trim(), e),
    })?;

    // Extract client_id from context before moving it
    let client_id =
        extract_client_id_from_context(&body.context).unwrap_or_else(|| "unknown".to_string());

    let principal =
        parse_entity(&body.principal).map_err(|e| AuthorizationError::InvalidPrincipal {
            details: e.to_string(),
        })?;

    let resource =
        parse_entity(&body.resource).map_err(|e| AuthorizationError::InvalidResource {
            details: e.to_string(),
        })?;

    let context = cedar_policy::Context::from_json_value(body.context, None).map_err(|e| {
        AuthorizationError::InvalidContext {
            reason: e.to_string(),
        }
    })?;

    let request =
        cedar_policy::Request::new(principal, action, resource, context, None).map_err(|e| {
            AuthorizationError::RequestFailed {
                reason: e.to_string(),
            }
        })?;

    let auth_start = Instant::now();
    let decision = state
        .authorizer
        .is_authorized(&request, &state.policies, &state.entities)
        .decision();
    let auth_duration = auth_start.elapsed();

    let decision_str = if decision == cedar_policy::Decision::Allow {
        "Allow"
    } else {
        "Deny"
    };

    // Record authorization metrics
    let principal_type =
        extract_entity_type(&body.principal).unwrap_or_else(|| "unknown".to_string());
    let resource_type =
        extract_entity_type(&body.resource).unwrap_or_else(|| "unknown".to_string());
    let action_type = extract_action_type(&body.action);

    PolicyMetricsHelper::record_authorization_request(
        decision_str,
        &principal_type,
        &action_type,
        &resource_type,
        &client_id,
        auth_duration,
        "mvp",
    );

    // Record policies evaluated (simplified for MVP)
    PolicyMetricsHelper::record_policies_evaluated("authorization", 1.0);

    // Log authorization decision for audit
    tracing::info!(
        request_id = %body.request_id,
        decision = %decision_str,
        action = %body.action,
        client_ip = ?client_ip,
        user_agent = ?user_agent,
        "Authorization decision made"
    );

    Ok(Json(AuthorizeResponse {
        decision: decision_str.to_string(),
    }))
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy")
    )
)]
/// Health check endpoint for MVP
pub async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "policy-service-mvp",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

#[utoipa::path(
    get,
    path = "/metrics",
    tag = "metrics", 
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain"),
        (status = 500, description = "Failed to gather metrics")
    )
)]
/// Metrics endpoint for MVP
pub async fn get_metrics() -> impl axum::response::IntoResponse {
    // For MVP, return simple text metrics
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

/// Metrics middleware for MVP (no-op)
pub async fn metrics_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let start = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    let response = next.run(req).await;
    let duration = start.elapsed();
    
    tracing::debug!(
        method = %method,
        uri = %uri,
        status = %response.status(),
        duration_ms = duration.as_millis(),
        "Request completed"
    );
    
    response
}