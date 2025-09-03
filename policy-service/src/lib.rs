#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, future_incompatible)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    clippy::unused_async,
    clippy::needless_pass_by_value,
    clippy::future_not_send,
    clippy::items_after_statements,
    clippy::unnecessary_wraps,
    clippy::struct_excessive_bools,
    clippy::branches_sharing_code,
    clippy::trivially_copy_pass_by_ref,
    dead_code
)]
use std::sync::Arc;
use std::time::Instant;

// Explicitly acknowledge unused dependencies that are part of future functionality
use anyhow as _;
use cedar_policy as _;
use cedar_policy_core as _;
use chrono as _;
use dotenvy as _;
use once_cell as _;
#[cfg(not(feature = "prom-client"))]
use prometheus as _;
use serde as _;
use serde_json as _;
use thiserror as _;
use tokio as _;
use tower_http as _;
use tracing_subscriber as _;
use utoipa_swagger_ui as _;

// Dev dependencies used in tests (acknowledged to prevent clippy warnings)
#[cfg(test)]
use futures as _;
#[cfg(test)]
use reqwest as _;
#[cfg(test)]
use tempfile as _;

use axum::{
    extract::State,
    http::{self},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use cedar_policy::{Authorizer, Context, Entities, PolicySet, Request};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct PolicyConflict {
    pub policy_id: String,
    pub conflicting_policy: String,
    pub conflict_type: String,
}

#[must_use]
pub fn detect_policy_conflicts(policies: &PolicySet) -> Vec<PolicyConflict> {
    let mut conflicts = Vec::new();
    let policy_list: Vec<_> = policies.policies().collect();

    for (i, policy1) in policy_list.iter().enumerate() {
        for policy2 in policy_list.iter().skip(i + 1) {
            if policies_conflict(policy1, policy2) {
                conflicts.push(PolicyConflict {
                    policy_id: policy1.id().to_string(),
                    conflicting_policy: policy2.id().to_string(),
                    conflict_type: "overlapping_conditions".to_string(),
                });
            }
        }
    }
    conflicts
}

fn policies_conflict(policy1: &cedar_policy::Policy, policy2: &cedar_policy::Policy) -> bool {
    // Basic conflict detection - same principal/action/resource with different effects
    policy1.principal_constraint() == policy2.principal_constraint()
        && policy1.action_constraint() == policy2.action_constraint()
        && policy1.resource_constraint() == policy2.resource_constraint()
        && policy1.effect() != policy2.effect()
}
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use utoipa::ToSchema;

mod documentation;
pub mod errors;
#[cfg(feature = "prometheus-backend")]
mod metrics;
#[cfg(feature = "prom-client")]
mod metrics_prom_client;

use documentation::{ErrorResponse, HealthCheckResponse};
use errors::{AppError, AuthorizationError, PolicyError};
#[cfg(feature = "prom-client")]
use crate::metrics_prom_client::{policy_metrics_handler, policy_metrics_middleware, PolicyMetricsHelper};
#[cfg(all(not(feature = "prom-client"), feature = "prometheus-backend"))]
use crate::metrics::{policy_metrics_handler, policy_metrics_middleware, PolicyMetricsHelper};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    pub request_id: String,
    pub principal: serde_json::Value,
    pub action: String,
    pub resource: serde_json::Value,
    pub context: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeResponse {
    pub decision: String,
}

pub struct AppState {
    pub authorizer: Authorizer,
    pub policies: PolicySet,
    pub entities: Entities,
}

/// Load policies and entities from files
///
/// # Errors
/// Returns an error if:
/// - Policy file cannot be read or parsed
/// - Entity file cannot be read or parsed
/// - Policy compilation fails
pub fn load_policies_and_entities() -> Result<Arc<AppState>, AppError> {
    let policies_path = concat!(env!("CARGO_MANIFEST_DIR"), "/policies.cedar");
    let policies_str = std::fs::read_to_string(policies_path)
        .map_err(|e| AppError::io("Failed to read policies file", e))?;
    let policies = policies_str
        .parse::<PolicySet>()
        .map_err(|e| AppError::Policy(Box::new(PolicyError::CompilationFailed { source: e })))?;

    let entities_path = concat!(env!("CARGO_MANIFEST_DIR"), "/entities.json");
    let entities_str = std::fs::read_to_string(entities_path)
        .map_err(|e| AppError::io("Failed to read entities file", e))?;
    let entities = Entities::from_json_str(&entities_str, None).map_err(|e| {
        AppError::Policy(Box::new(PolicyError::ValidationFailed {
            reason: format!("Failed to parse entities: {e}"),
        }))
    })?;

    Ok(Arc::new(AppState {
        authorizer: Authorizer::new(),
        policies,
        entities,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/authorize",
    tag = "authorization",
    request_body = AuthorizeRequest,
    responses(
        (status = 200, description = "Authorization decision made successfully", body = AuthorizeResponse),
        (status = 400, description = "Invalid request parameters", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
/// Authorize a request using Cedar policies
///
/// # Errors
/// Returns an error if:
/// - Action is invalid or empty
/// - Principal or resource entities are malformed
/// - Context parsing fails
/// - Authorization request construction fails
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthorizeRequest>,
) -> Result<Json<AuthorizeResponse>, AppError> {
    // Validate action is non-empty and basic format (e.g., contains a colon like "domain:verb")
    if body.action.trim().is_empty() {
        return Err(AuthorizationError::InvalidAction {
            action: "(empty)".to_string(),
        }
        .into());
    }
    let action = cedar_policy::EntityUid::from_json(serde_json::json!({
        "type": "Action",
        "id": body.action
    }))
    .map_err(|e| AuthorizationError::InvalidAction {
        action: format!("{}: {}", body.action, e),
    })?;

    let principal =
        parse_entity(&body.principal).map_err(|e| AuthorizationError::InvalidPrincipal {
            details: e.to_string(),
        })?;

    let resource =
        parse_entity(&body.resource).map_err(|e| AuthorizationError::InvalidResource {
            details: e.to_string(),
        })?;

    let context = Context::from_json_value(body.context, None).map_err(|e| {
        AuthorizationError::InvalidContext {
            reason: e.to_string(),
        }
    })?;

    let request = Request::new(principal, action, resource, context, None).map_err(|e| {
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
        "unknown", // TODO: Extract client ID from context or headers
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

fn parse_entity(v: &serde_json::Value) -> Result<cedar_policy::EntityUid, AuthorizationError> {
    cedar_policy::EntityUid::from_json(v.clone()).map_err(|e| AuthorizationError::RequestFailed {
        reason: format!("Invalid entity format: {e}"),
    })
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthCheckResponse)
    )
)]
pub async fn health_check() -> Json<HealthCheckResponse> {
    Json(HealthCheckResponse {
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
pub async fn get_metrics() -> impl IntoResponse {
    policy_metrics_handler().await
}

/// Extract entity type from JSON value for metrics
fn extract_entity_type(v: &serde_json::Value) -> Option<String> {
    v.get("type")
        .and_then(|t| t.as_str())
        .map(std::string::ToString::to_string)
}

/// Extract action type from action string
fn extract_action_type(action: &str) -> String {
    // Extract the action type from action format like "Document::read" or "read"
    action
        .find("::")
        .map_or_else(|| action.to_string(), |pos| action[pos + 2..].to_string())
}

pub fn app(state: Arc<AppState>) -> Router {
    let cors = match std::env::var("ALLOWED_ORIGINS") {
        Ok(origins) if !origins.trim().is_empty() => {
            let mut layer = CorsLayer::new();
            for o in origins.split(',') {
                if let Ok(origin) = o.trim().parse::<http::HeaderValue>() {
                    layer = layer.allow_origin(origin);
                }
            }
            layer
        }
        _ => {
            // Default to no origins unless explicitly configured
            CorsLayer::new()
        }
    };

    Router::new()
        .route("/health", get(health_check))
        .route("/v1/authorize", post(authorize))
        .route("/v1/policies/conflicts", get(check_policy_conflicts))
        .route("/metrics", get(get_metrics))
        .layer(axum::middleware::from_fn(policy_metrics_middleware))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn check_policy_conflicts(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PolicyConflict>>, AppError> {
    let conflicts = detect_policy_conflicts(&state.policies);
    Ok(Json(conflicts))
}

pub use documentation::ApiDoc;
