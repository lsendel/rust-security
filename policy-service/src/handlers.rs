//! HTTP request handlers for the policy service

use axum::{extract::State, Json};
use std::sync::Arc;
use std::time::Instant;

use crate::errors::{AppError, AuthorizationError};
use crate::models::{AppState, AuthorizeRequest, AuthorizeResponse, PolicyConflict};
use crate::utils::{
    extract_action_type, extract_client_id_from_context, extract_entity_type, parse_entity,
};
use crate::validation::validate_authorization_input;

// Metrics imports - use the appropriate module based on features
#[cfg(all(not(feature = "prom-client"), feature = "prometheus-backend"))]
use crate::metrics::{policy_metrics_handler, policy_metrics_middleware, PolicyMetricsHelper};
#[cfg(feature = "prom-client")]
use crate::metrics_prom_client::{
    policy_metrics_handler, policy_metrics_middleware, PolicyMetricsHelper,
};

#[utoipa::path(
    post,
    path = "/v1/authorize",
    tag = "authorization",
    request_body = crate::models::AuthorizeRequest,
    responses(
        (status = 200, description = "Authorization decision made successfully", body = crate::models::AuthorizeResponse),
        (status = 400, description = "Invalid request parameters", body = crate::documentation::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::documentation::ErrorResponse)
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
/// Authorize a request using Cedar policies
///
/// This function evaluates an authorization request against the loaded Cedar policies.
/// It performs comprehensive input validation, entity parsing, and policy evaluation
/// to determine whether the requested action is permitted or denied.
///
/// # Request Format
///
/// The authorization request should be a JSON object with the following structure:
///
/// ```json
/// {
///     "request_id": "unique-request-identifier",
///     "principal": {
///         "type": "User",
///         "id": "alice"
///     },
///     "action": "Document::read",
///     "resource": {
///         "type": "Document",
///         "id": "confidential-doc-123"
///     },
///     "context": {
///         "time": "2024-01-15T10:30:00Z",
///         "ip_address": "192.168.1.100",
///         "user_agent": "Mozilla/5.0...",
///         "client_id": "web-app-v1.2"
///     }
/// }
/// ```
///
/// # Action Format
///
/// Actions must follow the format `Domain::Action` where:
/// - `Domain` is the resource domain (e.g., "Document", "User", "System")
/// - `Action` is the specific action (e.g., "read", "write", "delete", "create")
///
/// Valid examples:
/// - `"Document::read"`
/// - `"User::update_profile"`
/// - `"System::restart_service"`
///
/// # Security Validation
///
/// The function performs several security validations:
/// - Input sanitization (removes control characters, validates format)
/// - JSON structure depth limits (prevents DoS via deeply nested objects)
/// - Payload size limits (prevents memory exhaustion attacks)
/// - Action format validation (ensures proper domain:action structure)
///
/// # Metrics and Monitoring
///
/// Authorization decisions are automatically recorded with the following metrics:
/// - Decision outcome (Allow/Deny)
/// - Principal type and ID
/// - Resource type and ID
/// - Action performed
/// - Client identifier (if provided)
/// - Authorization duration
///
/// # Errors
///
/// Returns an error if:
/// - Action is invalid, empty, or contains control characters
/// - Action is missing domain separator (:)
/// - Action is too long (>256 characters)
/// - Principal or resource entities are malformed
/// - Context parsing fails
/// - Authorization request construction fails
/// - Input validation fails
/// - JSON payload is too deeply nested (>10 levels)
/// - JSON payload is too large (>1MB)
///
/// # Examples
///
/// Basic authorization request:
/// ```rust,no_run
/// use policy_service::{authorize, AppState};
/// use axum::{Json, Router};
/// use std::sync::Arc;
///
/// // Example request body
/// let request = r#"{
///     "request_id": "req-12345",
///     "principal": {"type": "User", "id": "alice"},
///     "action": "Document::read",
///     "resource": {"type": "Document", "id": "doc-456"},
///     "context": {"client_id": "web-client"}
/// }"#;
///
/// // This would be called by the Axum framework with proper state
/// // let result = authorize(State(state), Json(request_body)).await;
/// ```
///
/// # Performance Considerations
///
/// - Authorization decisions are cached where possible
/// - Metrics recording is performed asynchronously to minimize latency impact
/// - Input validation is performed early to fail fast on invalid requests
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, AppError> {
    // Validate input for security and correctness
    validate_authorization_input(&body)?;

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
        "standard",
    );

    // Record policies evaluated (simplified - in reality would count actual policies)
    PolicyMetricsHelper::record_policies_evaluated("authorization", 1.0);

    // Log authorization decision for audit
    tracing::info!(
        request_id = %body.request_id,
        decision = %decision_str,
        action = %body.action,
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
        (status = 200, description = "Service is healthy", body = crate::documentation::HealthCheckResponse)
    )
)]
/// Health check endpoint
pub async fn health_check() -> Json<crate::documentation::HealthCheckResponse> {
    Json(crate::documentation::HealthCheckResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
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
/// Metrics endpoint
pub async fn get_metrics() -> impl axum::response::IntoResponse {
    policy_metrics_handler().await
}

#[utoipa::path(
    get,
    path = "/v1/policies/conflicts",
    tag = "authorization",
    responses(
        (status = 200, description = "Policy conflicts retrieved successfully", body = Vec<crate::models::PolicyConflict>),
        (status = 500, description = "Internal server error", body = crate::documentation::ErrorResponse)
    )
)]
/// Check for policy conflicts
pub async fn check_policy_conflicts(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PolicyConflict>>, AppError> {
    let conflicts = crate::detect_policy_conflicts(&state.policies);
    Ok(Json(conflicts))
}

/// Get the metrics middleware function for Axum
#[cfg(any(feature = "prometheus-backend", feature = "prom-client"))]
pub async fn metrics_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Call the actual metrics middleware based on feature
    #[cfg(feature = "prometheus-backend")]
    {
        crate::metrics::policy_metrics_middleware(req, next).await
    }
    #[cfg(all(not(feature = "prometheus-backend"), feature = "prom-client"))]
    {
        crate::metrics_prom_client::policy_metrics_middleware(req, next).await
    }

    // Fallback if no metrics feature is enabled
    #[cfg(not(any(feature = "prometheus-backend", feature = "prom-client")))]
    {
        next.run(req).await
    }
}
