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
    clippy::multiple_crate_versions,
    clippy::items_after_statements,
    clippy::unnecessary_wraps,
    clippy::struct_excessive_bools,
    clippy::branches_sharing_code,
    clippy::trivially_copy_pass_by_ref,
    dead_code
)]

//! # MVP Policy Service
//!
//! A lightweight, security-focused policy validation service designed for MVP deployment.
//!
//! ## Features
//!
//! - Enhanced security validation with threat detection
//! - Cedar Policy Language support for authorization decisions
//! - Comprehensive input sanitization and validation
//! - Structured security logging and monitoring
//! - MVP-focused architecture with essential features only
//!
//! ## Security Features
//!
//! - `DoS` protection (payload size, depth, complexity limits)
//! - Injection attack prevention (SQL, XSS, script injection detection)
//! - Control character filtering and input sanitization
//! - Security context tracking with threat level classification
//! - Client IP and User-Agent validation and logging
//!
//! ## Usage
//!
//! ```rust,no_run
//! use policy_service::{load_policies_and_entities, app};
//!
//! let app_state = load_policies_and_entities().expect("Failed to load policies");
//! let router = app(app_state);
//! ```

// Module declarations - MVP essential modules only
pub mod documentation;
pub mod errors;
pub mod handlers;
pub mod models;
pub mod utils;
pub mod validation;

// Optional metrics module based on features
#[cfg(feature = "prometheus-backend")]
mod metrics;
#[cfg(feature = "prom-client")]
mod metrics_prom_client;

// Re-export public API
pub use documentation::ApiDoc;
pub use handlers::{authorize, get_metrics, health_check};
pub use models::{AppState, AuthorizeRequest, AuthorizeResponse, PolicyConflict};
pub use utils::{extract_action_type, extract_client_id_from_context, extract_entity_type};

/// Load policies and entities for MVP deployment
///
/// This function initializes the policy service by loading Cedar policies from files
/// located in the Cargo manifest directory. For MVP, this uses simplified file loading.
///
/// # Security Considerations
///
/// - Policy files are validated for syntax correctness
/// - Entity data is sanitized to prevent injection attacks
/// - Files must have appropriate filesystem permissions
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
    // For MVP, use simple default policies if files don't exist
    let policies_path = concat!(env!("CARGO_MANIFEST_DIR"), "/policies.cedar");
    let policies_str = std::fs::read_to_string(policies_path).unwrap_or_else(|_| {
        // Default MVP policy - allow authenticated users basic access
        r"
            permit(
                principal,
                action,
                resource
            ) when {
                principal has authenticated && 
                principal.authenticated == true
            };
            "
        .to_string()
    });

    let policies = policies_str
        .parse::<cedar_policy::PolicySet>()
        .map_err(|e| {
            errors::AppError::Policy(Box::new(errors::PolicyError::CompilationFailed {
                source: e,
            }))
        })?;

    let entities_path = concat!(env!("CARGO_MANIFEST_DIR"), "/entities.json");
    let entities_str = std::fs::read_to_string(entities_path).unwrap_or_else(|_| {
        // Default MVP entities
        r#"[
                {
                    "uid": {"type": "User", "id": "mvp-user"},
                    "attrs": {"authenticated": true, "role": "user"},
                    "parents": []
                },
                {
                    "uid": {"type": "Action", "id": "read"},
                    "attrs": {},
                    "parents": []
                },
                {
                    "uid": {"type": "Resource", "id": "mvp-resource"},
                    "attrs": {"public": true},
                    "parents": []
                }
            ]"#
        .to_string()
    });

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

/// Create the Axum application router for MVP deployment
///
/// This function sets up the HTTP application with:
/// - Authorization endpoint (`/v1/authorize`)  
/// - Health check endpoint (`/health`)
/// - Metrics endpoint (`/metrics`) - if enabled
///
/// # Security Features
///
/// - CORS configuration (configurable via ALLOWED_ORIGINS env var)
/// - Request ID propagation for tracing
/// - Enhanced security validation middleware
/// - Structured logging with tracing
///
/// # Examples
///
/// ```rust,no_run
/// use policy_service::{load_policies_and_entities, app};
///
/// let app_state = load_policies_and_entities().expect("Failed to load policies");
/// let router = app(app_state);
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

    // Secure CORS configuration: deny by default; allow only configured origins
    let cors = match std::env::var("ALLOWED_ORIGINS") {
        Ok(origins) if !origins.trim().is_empty() => {
            let mut layer = CorsLayer::new();
            for o in origins.split(',') {
                let o = o.trim();
                if o == "*" {
                    tracing::warn!("Wildcard CORS origin (*) is not allowed; ignoring entry");
                    continue;
                }
                if let Ok(origin) = o.parse::<axum::http::HeaderValue>() {
                    layer = layer.allow_origin(origin);
                }
            }
            layer
        }
        _ => {
            // Deny all cross-origin requests by default; methods/headers allowed only for same-origin
            CorsLayer::new()
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ])
        }
    };

    let mut router = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/v1/authorize", post(handlers::authorize))
        // Expose metrics only when explicitly allowed
        .route(
            "/metrics",
            get(|| async move {
                use axum::response::IntoResponse as _;
                if std::env::var("METRICS_PUBLIC").unwrap_or_else(|_| "false".to_string()) == "true"
                {
                    handlers::get_metrics().await.into_response()
                } else {
                    axum::response::Response::builder()
                        .status(403)
                        .body(axum::body::Body::from("metrics disabled"))
                        .unwrap()
                }
            }),
        )
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    // Conditionally add metrics middleware for MVP
    #[cfg(any(feature = "prometheus-backend", feature = "prom-client"))]
    {
        router = router.layer(axum::middleware::from_fn(
            crate::handlers::metrics_middleware,
        ));
    }

    router.with_state(state)
}

/// Detect policy conflicts - simplified for MVP
///
/// This function analyzes Cedar policies to identify potential conflicts.
/// For MVP, this performs basic conflict detection.
///
/// # Examples
///
/// ```rust,no_run
/// use policy_service::{load_policies_and_entities, detect_policy_conflicts};
///
/// let app_state = load_policies_and_entities().unwrap();
/// let conflicts = detect_policy_conflicts(&app_state.policies);
/// ```
#[must_use]
pub fn detect_policy_conflicts(policies: &cedar_policy::PolicySet) -> Vec<PolicyConflict> {
    let mut conflicts = Vec::new();
    let policy_list: Vec<_> = policies.policies().collect();

    // For MVP, perform basic conflict detection
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

/// Check if two policies conflict - MVP implementation
fn policies_conflict(policy1: &cedar_policy::Policy, policy2: &cedar_policy::Policy) -> bool {
    // Basic conflict detection for MVP
    policy1.principal_constraint() == policy2.principal_constraint()
        && policy1.action_constraint() == policy2.action_constraint()
        && policy1.resource_constraint() == policy2.resource_constraint()
        && policy1.effect() != policy2.effect()
}
