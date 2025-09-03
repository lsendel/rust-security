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

// Module declarations
mod documentation;
pub mod errors;
pub mod handlers;
#[cfg(feature = "prometheus-backend")]
mod metrics;
#[cfg(feature = "prom-client")]
mod metrics_prom_client;
pub mod models;
pub mod utils;
pub mod validation;

// Re-export public types
pub use handlers::{authorize, check_policy_conflicts, get_metrics, health_check};
pub use models::{AppState, AuthorizeRequest, AuthorizeResponse, PolicyConflict};
pub use utils::{extract_action_type, extract_client_id_from_context, extract_entity_type};

// Re-export for backward compatibility
pub use documentation::ApiDoc;

/// Load policies and entities from files
///
/// This function initializes the policy service by loading Cedar policies from a policy file
/// and entity definitions from an entities JSON file. These files should be located in the
/// Cargo manifest directory.
///
/// # File Format Requirements
///
/// ## Policy File (policies.cedar)
/// Contains Cedar policy definitions in the standard Cedar policy language format.
/// Example:
/// ```cedar
/// permit (
///     principal,
///     action == Document::"read",
///     resource
/// ) when {
///     principal.role == "admin"
/// };
/// ```
///
/// ## Entity File (entities.json)
/// Contains entity definitions in JSON format that define the entities referenced in policies.
/// Example:
/// ```json
/// {
///     "User::\"alice\"": {
///         "type": "User",
///         "id": "alice",
///         "attributes": {
///             "role": "admin",
///             "department": "engineering"
///         }
///     },
///     "Document::\"doc1\"": {
///         "type": "Document",
///         "id": "doc1",
///         "attributes": {
///             "classification": "confidential",
///             "owner": "alice"
///         }
///     }
/// }
/// ```
///
/// # Security Considerations
///
/// - Policy files should be validated for syntax correctness
/// - Entity data should be sanitized to prevent injection attacks
/// - Files should have appropriate filesystem permissions
///
/// # Errors
///
/// Returns an error if:
/// - Policy file cannot be read or parsed
/// - Entity file cannot be read or parsed
/// - Policy compilation fails
/// - File paths are invalid
///
/// # Examples
///
/// ```rust,no_run
/// use policy_service::load_policies_and_entities;
///
/// let app_state = load_policies_and_entities()
///     .expect("Failed to load policies and entities");
/// ```
pub fn load_policies_and_entities() -> Result<std::sync::Arc<AppState>, errors::AppError> {
    let policies_path = concat!(env!("CARGO_MANIFEST_DIR"), "/policies.cedar");
    let policies_str = std::fs::read_to_string(policies_path)
        .map_err(|e| errors::AppError::io("Failed to read policies file", e))?;
    let policies = policies_str
        .parse::<cedar_policy::PolicySet>()
        .map_err(|e| {
            errors::AppError::Policy(Box::new(errors::PolicyError::CompilationFailed {
                source: e,
            }))
        })?;

    let entities_path = concat!(env!("CARGO_MANIFEST_DIR"), "/entities.json");
    let entities_str = std::fs::read_to_string(entities_path)
        .map_err(|e| errors::AppError::io("Failed to read entities file", e))?;
    let entities = cedar_policy::Entities::from_json_str(&entities_str, None).map_err(|e| {
        errors::AppError::Policy(Box::new(errors::PolicyError::ValidationFailed {
            reason: format!("Failed to parse entities: {e}"),
        }))
    })?;

    Ok(std::sync::Arc::new(AppState {
        authorizer: cedar_policy::Authorizer::new(),
        policies,
        entities,
    }))
}

/// Create the Axum application router with all routes configured
///
/// This function sets up the complete HTTP application with:
/// - Authorization endpoint (`/v1/authorize`)
/// - Health check endpoint (`/health`)
/// - Metrics endpoint (`/metrics`)
/// - Policy conflict detection (`/v1/policies/conflicts`)
///
/// # Security Features
///
/// - CORS configuration (configurable via ALLOWED_ORIGINS env var)
/// - Request ID propagation for tracing
/// - Metrics middleware for monitoring
/// - Structured logging with tracing
///
/// # Middleware Stack
///
/// 1. **Metrics Middleware**: Records request metrics and performance data
/// 2. **Request ID Propagation**: Adds unique request IDs for tracing
/// 3. **CORS Layer**: Handles cross-origin requests based on configuration
/// 4. **Tracing Layer**: Logs HTTP requests and responses
///
/// # Environment Variables
///
/// - `ALLOWED_ORIGINS`: Comma-separated list of allowed CORS origins
///   (defaults to no origins if not set)
///
/// # Examples
///
/// ```rust,no_run
/// use policy_service::{load_policies_and_entities, app};
/// use std::sync::Arc;
///
/// let app_state = load_policies_and_entities().expect("Failed to load policies");
/// let router = app(Arc::new(app_state));
/// ```
pub fn app(state: std::sync::Arc<AppState>) -> axum::Router {
    use axum::{
        routing::{get, post},
        Router,
    };
    use tower_http::{
        cors::CorsLayer,
        request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
        trace::TraceLayer,
    };

    let cors = match std::env::var("ALLOWED_ORIGINS") {
        Ok(origins) if !origins.trim().is_empty() => {
            let mut layer = CorsLayer::new();
            for o in origins.split(',') {
                if let Ok(origin) = o.trim().parse::<axum::http::HeaderValue>() {
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

    let mut router = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/v1/authorize", post(handlers::authorize))
        .route(
            "/v1/policies/conflicts",
            get(handlers::check_policy_conflicts),
        )
        .route("/metrics", get(handlers::get_metrics))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    // Conditionally add metrics middleware based on available features
    #[cfg(any(feature = "prometheus-backend", feature = "prom-client"))]
    {
        router = router.layer(axum::middleware::from_fn(
            crate::handlers::metrics_middleware,
        ));
    }

    router.with_state(state)
}

/// Detect policy conflicts in a policy set
///
/// This function analyzes a set of Cedar policies to identify potential conflicts
/// where multiple policies might apply to the same principal/action/resource combination
/// but have different effects (allow vs deny).
///
/// # Conflict Types Detected
///
/// Currently detects:
/// - **Overlapping Conditions**: Policies with identical principal, action, and resource
///   constraints but different effects (permit vs forbid)
///
/// # Algorithm
///
/// The function performs an O(n²) comparison of all policies in the set:
/// 1. Collect all policies into a vector
/// 2. Compare each policy against all subsequent policies
/// 3. Check for constraint overlap and effect differences
/// 4. Record conflicts with policy IDs and conflict type
///
/// # Performance Considerations
///
/// - O(n²) complexity may be slow for large policy sets
/// - Consider caching conflict analysis results
/// - Use this function during policy development/testing, not in production hot path
///
/// # Examples
///
/// ```rust,no_run
/// use policy_service::{load_policies_and_entities, detect_policy_conflicts};
///
/// let app_state = load_policies_and_entities().unwrap();
/// let conflicts = detect_policy_conflicts(&app_state.policies);
///
/// for conflict in conflicts {
///     println!("Conflict between {} and {}: {}",
///         conflict.policy_id,
///         conflict.conflicting_policy,
///         conflict.conflict_type
///     );
/// }
/// ```
#[must_use]
pub fn detect_policy_conflicts(policies: &cedar_policy::PolicySet) -> Vec<PolicyConflict> {
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

/// Check if two policies conflict
fn policies_conflict(policy1: &cedar_policy::Policy, policy2: &cedar_policy::Policy) -> bool {
    // Basic conflict detection - same principal/action/resource with different effects
    policy1.principal_constraint() == policy2.principal_constraint()
        && policy1.action_constraint() == policy2.action_constraint()
        && policy1.resource_constraint() == policy2.resource_constraint()
        && policy1.effect() != policy2.effect()
}
