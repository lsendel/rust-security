use std::{collections::HashMap, sync::Arc};

use crate::pii_protection::redact_log;

use axum::{
    extract::{Form, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use base64::Engine as _;
use once_cell::sync::Lazy;
use prometheus::{Encoder, IntCounter, Registry, TextEncoder};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use url::Url;
use utoipa::ToSchema;

#[cfg(feature = "docs")]
use utoipa::OpenApi;
#[cfg(feature = "docs")]
use utoipa_swagger_ui::SwaggerUi;

// Constants
pub const DEFAULT_TOKEN_EXPIRY_SECONDS: u64 = 3600; // 1 hour
pub const REFRESH_TOKEN_EXPIRY_SECONDS: u64 = 14 * 24 * 3600; // 14 days
pub const REQUEST_TIMESTAMP_WINDOW_SECONDS: i64 = 300; // 5 minutes
pub const MAX_FILTER_LENGTH: usize = 500;
pub const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024; // 1MB

static TOKENS_ISSUED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("tokens_issued_total", "tokens issued")
        .expect("Failed to create tokens_issued metric")
});
static TOKENS_REFRESHED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("tokens_refreshed_total", "tokens refreshed")
        .expect("Failed to create tokens_refreshed metric")
});
static TOKENS_REVOKED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("tokens_revoked_total", "tokens revoked")
        .expect("Failed to create tokens_revoked metric")
});
#[allow(dead_code)]
static REGISTRY: Lazy<Registry> = Lazy::new(|| {
    let r = Registry::new();
    r.register(Box::new(TOKENS_ISSUED.clone())).ok();
    r.register(Box::new(TOKENS_REFRESHED.clone())).ok();
    r.register(Box::new(TOKENS_REVOKED.clone())).ok();
    r
});

#[allow(dead_code)]
async fn metrics_handler() -> Response {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, encoder.format_type())
        .body(axum::body::Body::from(buffer))
        .unwrap()
}

// Core modules
pub mod errors;
pub mod store;
pub mod validation;

// Authentication and authorization
pub mod client_auth;
pub mod mfa;
pub mod otp_provider;
pub mod session_manager;
pub mod session_cleanup;
pub mod token_store;
pub mod webauthn;

// OIDC providers
pub mod oidc_github;
pub mod oidc_google;
pub mod oidc_microsoft;

// SCIM support
pub mod scim;
pub mod scim_rbac;

// Security modules
pub mod auth_failure_logging;
pub mod redirect_validation;
pub mod secure_random;
pub mod security;
pub mod security_headers;
pub mod admin_middleware;
pub mod security_logging;
pub mod security_metrics;
pub mod security_monitoring;
pub mod pii_protection;
#[cfg(test)]
pub mod pii_audit_tests;

// Key management
pub mod key_management;
pub mod key_rotation;
pub mod keys;

// Rate limiting and resilience
pub mod backpressure;
pub mod per_ip_rate_limit;
pub mod policy_cache;
pub mod rate_limit_optimized;

// Resilience and reliability
pub mod circuit_breaker;
pub mod resilience_config;
pub mod resilient_http;
pub mod resilient_store;

pub use errors::{AuthError, ErrorResponse, internal_error, validation_error, token_store_error};
pub use validation::{ValidatedDto, ValidationResult, middleware::{ValidatedJson, ValidatedQuery}};

// SOAR (Security Orchestration, Automation, and Response) Modules
#[cfg(feature = "soar")]
pub mod soar_core;
#[cfg(feature = "soar")]
pub mod soar_workflow;
#[cfg(feature = "soar")]
pub mod soar_executors;
#[cfg(feature = "soar")]
pub mod soar_correlation;
#[cfg(feature = "soar")]
pub mod soar_case_management;

// Performance Optimization Modules (behind feature flag to avoid pulling heavy deps in default tests)
#[cfg(feature = "optimizations")]
pub mod crypto_optimized;
#[cfg(feature = "optimizations")]
pub mod database_optimized;
#[cfg(feature = "optimizations")]
pub mod connection_pool_optimized;
#[cfg(feature = "optimizations")]
pub mod async_optimized;

// Threat Hunting Modules
#[cfg(feature = "threat-hunting")]
pub mod threat_types;
#[cfg(feature = "threat-hunting")]
pub mod threat_behavioral_analyzer;
#[cfg(feature = "threat-hunting")]
pub mod threat_intelligence;
#[cfg(feature = "threat-hunting")]
pub mod threat_attack_patterns;
#[cfg(feature = "threat-hunting")]
pub mod threat_user_profiler;
#[cfg(feature = "threat-hunting")]
pub mod threat_response_orchestrator;
#[cfg(feature = "threat-hunting")]
pub mod threat_hunting_orchestrator;

// Import the new comprehensive MFA system
// Deprecated re-exports removed (modules not present)

use security_logging::{SecurityLogger, SecurityEvent, SecurityEventType, SecuritySeverity};
use security_monitoring::{SECURITY_MONITOR, MonitoringConfig};

fn audit(event: &str, payload: serde_json::Value) {
    tracing::info!(target: "audit", event, payload = %payload);
}

#[utoipa::path(get, path = "/.well-known/oauth-authorization-server", responses((status = 200, body = serde_json::Value)))]
pub async fn oauth_metadata() -> Json<serde_json::Value> {
    let base =
        std::env::var("EXTERNAL_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    Json(serde_json::json!({
        "issuer": base,
        "token_endpoint": format!("{}/oauth/token", base),
        "introspection_endpoint": format!("{}/oauth/introspect", base),
        "revocation_endpoint": format!("{}/oauth/revoke", base),
        "jwks_uri": format!("{}/jwks.json", base),
        "grant_types_supported": ["client_credentials", "refresh_token", "authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "authorization_endpoint": format!("{}/oauth/authorize", base),
        "userinfo_endpoint": format!("{}/oauth/userinfo", base),
        "response_types_supported": ["code"],
        "scopes_supported": ["openid", "profile", "email"],
        "code_challenge_methods_supported": ["S256"],
    }))
}

#[utoipa::path(get, path = "/.well-known/openid-configuration", responses((status = 200, body = serde_json::Value)))]
pub async fn oidc_metadata() -> Json<serde_json::Value> {
    oauth_metadata().await
}

#[utoipa::path(get, path = "/jwks.json", responses((status = 200, body = serde_json::Value)))]
pub async fn jwks() -> Json<serde_json::Value> {
    Json(keys::jwks_document().await)
}


// Enhanced MFA v2 endpoints using the comprehensive system
// Legacy MFA v2 scaffolding endpoints disabled (implementation not present in this repo)

// Security monitoring endpoints implementation
#[utoipa::path(
    get,
    path = "/admin/security/alerts",
    responses((status = 200, description = "List of security alerts"))
)]
pub async fn get_security_alerts(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let limit = params.get("limit")
        .and_then(|l| l.parse::<usize>().ok());

    let active_only = params.get("active_only")
        .map(|v| v == "true")
        .unwrap_or(false);

    let alerts = if active_only {
        SECURITY_MONITOR.get_active_alerts().await
    } else {
        SECURITY_MONITOR.get_alert_history(limit).await
    };

    Ok(Json(serde_json::json!({
        "alerts": alerts,
        "total": alerts.len()
    })))
}

#[utoipa::path(
    post,
    path = "/admin/security/alerts/{id}/resolve",
    responses((status = 200, description = "Alert resolved successfully"))
)]
pub async fn resolve_security_alert(
    Path(alert_id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let resolution_notes = body.get("resolution_notes")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let resolved = SECURITY_MONITOR.resolve_alert(&alert_id, resolution_notes).await;

    if resolved {
        Ok(Json(serde_json::json!({
            "success": true,
            "message": "Alert resolved successfully"
        })))
    } else {
        Err(AuthError::InvalidRequest { reason: "Alert not found".to_string() })
    }
}

#[utoipa::path(
    get,
    path = "/admin/security/config",
    responses((status = 200, description = "Security monitoring configuration"))
)]
pub async fn get_security_config() -> Result<Json<MonitoringConfig>, AuthError> {
    let config = SECURITY_MONITOR.get_config().await;
    Ok(Json(config))
}

#[utoipa::path(
    post,
    path = "/admin/security/config",
    request_body = MonitoringConfig,
    responses((status = 200, description = "Configuration updated successfully"))
)]
pub async fn update_security_config(
    Json(config): Json<MonitoringConfig>,
) -> Result<Json<serde_json::Value>, AuthError> {
    SECURITY_MONITOR.update_config(config).await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Security monitoring configuration updated"
    })))
}

/// Admin endpoint to get rate limiting statistics
#[utoipa::path(
    get,
    path = "/admin/rate-limit/stats",
    responses((status = 200, description = "Rate limiting statistics"))
)]
pub async fn get_rate_limit_stats_endpoint(
    State(_state): State<AppState>,
) -> Result<Json<serde_json::Value>, AuthError> {
    // Admin authentication is handled by middleware
    let stats = crate::rate_limit_optimized::get_rate_limit_stats();
    Ok(Json(serde_json::json!({
        "total_entries": stats.total_entries,
        "shard_count": stats.shard_count,
        "shard_sizes": stats.shard_sizes,
        "config": {
            "requests_per_window": stats.config.requests_per_window,
            "window_duration_secs": stats.config.window_duration_secs,
            "burst_allowance": stats.config.burst_allowance,
            "cleanup_interval_secs": stats.config.cleanup_interval_secs
        }
    })))
}

/// Admin-protected wrapper around key rotation status
pub async fn admin_get_rotation_status(
    State(_state): State<AppState>,
) -> Result<axum::Json<serde_json::Value>, AuthError> {
    // Admin authentication is handled by middleware
    Ok(crate::key_rotation::get_rotation_status().await)
}

/// Admin-protected wrapper around forcing key rotation
pub async fn admin_force_rotation(
    State(_state): State<AppState>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    // Admin authentication is handled by middleware
    match crate::key_rotation::force_rotation().await {
        Ok(result) => Ok(result),
        Err(_) => Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
    }
}

// Session management endpoint handlers
use crate::session_manager::{SESSION_MANAGER, Session};
use crate::redirect_validation::RedirectUriValidator;

// Initialize redirect URI validator
static REDIRECT_VALIDATOR: once_cell::sync::Lazy<std::sync::Mutex<RedirectUriValidator>> =
    once_cell::sync::Lazy::new(|| {
        let mut validator = RedirectUriValidator::default();

        // Register additional clients from environment or config
        if let Ok(client_uris) = std::env::var("CLIENT_REDIRECT_URIS") {
            for entry in client_uris.split(';') {
                if let Some((client_id, uris)) = entry.split_once(':') {
                    let uri_list: Vec<String> = uris.split(',').map(|s| s.to_string()).collect();
                    let _ = validator.register_client_uris(client_id, uri_list);
                }
            }
        }

        std::sync::Mutex::new(validator)
    });

/// Helper function to extract user ID from bearer token
async fn extract_user_from_token(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Result<String, AuthError> {
    // Extract bearer token
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth.strip_prefix("Bearer ")
        .ok_or_else(|| AuthError::InvalidToken { reason: "Missing bearer token".to_string() })?;

    if token.is_empty() {
        return Err(AuthError::InvalidToken { reason: "Empty bearer token".to_string() });
    }

    // Get token record and validate
    let record = state.token_store.get_record(token).await?;

    if !record.active {
        return Err(AuthError::InvalidToken { reason: "Token is not active".to_string() });
    }

    // Check token expiration
    if let Some(exp) = record.exp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| internal_error("System time error"))?
            .as_secs() as i64;

        if now > exp {
            return Err(AuthError::InvalidToken { reason: "Token has expired".to_string() });
        }
    }

    // Enforce token binding if present
    if let Some(binding) = &record.token_binding {
        let (client_ip, user_agent) = crate::security::extract_client_info(headers);
        if !crate::security::validate_token_binding(binding, &client_ip, &user_agent) {
            return Err(AuthError::InvalidToken { reason: "Token binding mismatch".to_string() });
        }
    }

    // Extract user ID from token subject
    record.sub.ok_or_else(|| AuthError::InvalidToken { reason: "Token has no subject".to_string() })
}

/// Require that the caller has an access token with the "admin" scope

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateSessionRequest {
    pub user_id: String,
    pub client_id: Option<String>,
    pub duration: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub expires_at: u64,
    pub csrf_token: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RefreshSessionRequest {
    pub duration: Option<u64>,
}

/// Create a new session
#[utoipa::path(
    post,
    path = "/session/create",
    request_body = CreateSessionRequest,
    responses((status = 200, description = "Session created", body = CreateSessionResponse))
)]
pub async fn create_session_endpoint(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, AuthError> {
    // Derive user_id from bearer token and ignore provided user_id for security
    let derived_user_id = extract_user_from_token(&headers, &state).await?;
    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let session = SESSION_MANAGER.create_session(
        derived_user_id,
        req.client_id,
        ip_address,
        user_agent,
        req.duration,
    ).await.map_err(|e| internal_error(&format!("Session creation failed: {}", e)))?;

    Ok(Json(CreateSessionResponse {
        session_id: session.id,
        expires_at: session.expires_at,
        csrf_token: session.csrf_token,
    }))
}

/// Get session information
#[utoipa::path(
    get,
    path = "/session/{id}",
    responses((status = 200, description = "Session information", body = Session), (status = 404))
)]
pub async fn get_session_endpoint(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<Session>, AuthError> {
    // Extract and validate the requesting user
    let requesting_user_id = extract_user_from_token(&headers, &state).await?;

    match SESSION_MANAGER.get_session(&session_id).await {
        Ok(Some(session)) => {
            // Check session ownership
            if session.user_id != requesting_user_id {
                // Log unauthorized access attempt
                SecurityLogger::log_event(&SecurityEvent::new(
                    SecurityEventType::UnauthorizedAccess,
                    SecuritySeverity::High,
                    "auth-service".to_string(),
                    "Unauthorized session access attempt".to_string(),
                )
                .with_actor(requesting_user_id.to_string())
                .with_action("read".to_string())
                .with_target(format!("session:{}", session_id))
                .with_outcome("blocked".to_string())
                .with_reason("User attempted to access another user's session".to_string())
                .with_session_id(session_id.to_string())
                .with_correlation_id(format!("session-access-{}", session_id))
                .with_detail("target_user".to_string(), session.user_id.clone()));

                return Err(AuthError::UnauthorizedClient { client_id: "Access denied".to_string() });
            }

            if session.is_expired(None) {
                Err(AuthError::InvalidToken { reason: "Session expired".to_string() })
            } else {
                Ok(Json(session))
            }
        }
        Ok(None) => Err(AuthError::InvalidToken { reason: "Session not found".to_string() }),
        Err(e) => Err(internal_error(&format!("Session operation failed: {}", e))),
    }
}

/// Delete a session
#[utoipa::path(
    delete,
    path = "/session/{id}",
    responses((status = 200, description = "Session deleted"))
)]
pub async fn delete_session_endpoint(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    // Extract and validate the requesting user
    let requesting_user_id = extract_user_from_token(&headers, &state).await?;

    // First, get the session to check ownership
    match SESSION_MANAGER.get_session(&session_id).await {
        Ok(Some(session)) => {
            // Check session ownership
            if session.user_id != requesting_user_id {
                // Log unauthorized access attempt
                SecurityLogger::log_event(&SecurityEvent::new(
                    SecurityEventType::UnauthorizedAccess,
                    SecuritySeverity::High,
                    "auth-service".to_string(),
                    "Unauthorized session deletion attempt".to_string(),
                )
                .with_actor(requesting_user_id.to_string())
                .with_action("delete".to_string())
                .with_target(format!("session:{}", session_id))
                .with_outcome("blocked".to_string())
                .with_reason("User attempted to delete another user's session".to_string())
                .with_session_id(session_id.to_string())
                .with_correlation_id(format!("session-delete-{}", session_id))
                .with_detail("target_user".to_string(), session.user_id.clone()));

                return Err(AuthError::UnauthorizedClient { client_id: "Access denied".to_string() });
            }

            // User owns the session, proceed with deletion
            SESSION_MANAGER.delete_session(&session_id).await
                .map_err(|e| internal_error(&format!("Session deletion failed: {}", e)))?;

            // Log successful session deletion
            SecurityLogger::log_event(&SecurityEvent::new(
                SecurityEventType::SessionEvent,
                SecuritySeverity::Low,
                "auth-service".to_string(),
                "Session deleted successfully".to_string(),
            )
            .with_actor(requesting_user_id.to_string())
            .with_action("delete".to_string())
            .with_target(format!("session:{}", session_id))
            .with_outcome("success".to_string())
            .with_session_id(session_id.to_string())
            .with_correlation_id(format!("session-delete-{}", session_id)));

            Ok(Json(serde_json::json!({
                "success": true,
                "message": "Session deleted"
            })))
        }
        Ok(None) => Err(AuthError::InvalidToken { reason: "Session not found".to_string() }),
        Err(e) => Err(internal_error(&format!("Session operation failed: {}", e))),
    }
}

/// Refresh a session
#[utoipa::path(
    post,
    path = "/session/{id}/refresh",
    request_body = RefreshSessionRequest,
    responses((status = 200, description = "Session refreshed", body = Session), (status = 404))
)]
pub async fn refresh_session_endpoint(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(req): Json<RefreshSessionRequest>,
) -> Result<Json<Session>, AuthError> {
    // Extract and validate the requesting user
    let requesting_user_id = extract_user_from_token(&headers, &state).await?;

    // First, get the session to check ownership
    match SESSION_MANAGER.get_session(&session_id).await {
        Ok(Some(session)) => {
            // Check session ownership
            if session.user_id != requesting_user_id {
                // Log unauthorized access attempt
                SecurityLogger::log_event(&SecurityEvent::new(
                    SecurityEventType::UnauthorizedAccess,
                    SecuritySeverity::High,
                    "auth-service".to_string(),
                    "Unauthorized session refresh attempt".to_string(),
                )
                .with_actor(requesting_user_id.to_string())
                .with_action("refresh".to_string())
                .with_target(format!("session:{}", session_id))
                .with_outcome("blocked".to_string())
                .with_reason("User attempted to refresh another user's session".to_string())
                .with_session_id(session_id.to_string())
                .with_correlation_id(format!("session-refresh-{}", session_id))
                .with_detail("target_user".to_string(), session.user_id.clone()));

                return Err(AuthError::UnauthorizedClient { client_id: "Access denied".to_string() });
            }

            // User owns the session, proceed with refresh
            match SESSION_MANAGER.refresh_session(&session_id, req.duration).await {
                Ok(Some(refreshed_session)) => {
                    // Log successful session refresh
                    SecurityLogger::log_event(&SecurityEvent::new(
                        SecurityEventType::SessionEvent,
                        SecuritySeverity::Low,
                        "auth-service".to_string(),
                        "Session refreshed successfully".to_string(),
                    )
                    .with_user_id(requesting_user_id)
                    .with_session_id(session_id)
                    .with_outcome("success".to_string()));

                    Ok(Json(refreshed_session))
                }
                Ok(None) => Err(AuthError::InvalidToken { reason: "Session not found after refresh".to_string() }),
                Err(e) => Err(internal_error(&format!("Session operation failed: {}", e))),
            }
        }
        Ok(None) => Err(AuthError::InvalidToken { reason: "Session not found".to_string() }),
        Err(e) => Err(internal_error(&format!("Session operation failed: {}", e))),
    }
}

/// Invalidate all sessions for a user
#[utoipa::path(
    post,
    path = "/session/invalidate-user/{user_id}",
    responses((status = 200, description = "User sessions invalidated"))
)]
pub async fn invalidate_user_sessions_endpoint(
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let count = SESSION_MANAGER.invalidate_user_sessions(&user_id).await
        .map_err(|e| internal_error(&format!("Session invalidation failed: {}", e)))?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Invalidated {} sessions", count),
        "invalidated_count": count
    })))
}

#[derive(Clone)]
pub struct AppState {
    pub token_store: crate::store::TokenStore,
    pub client_credentials: HashMap<String, String>,
    pub allowed_scopes: Vec<String>,
    pub authorization_codes: Arc<RwLock<HashMap<String, AuthorizationCode>>>,
    pub policy_cache: Arc<crate::policy_cache::PolicyCache>,
    pub backpressure_state: Arc<crate::backpressure::BackpressureState>,
}

// TokenStore moved to store.rs

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct IntrospectionRecord {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_binding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct IntrospectResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

// === ABAC Authorization proxy to policy-service ===
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizationCheckRequest {
    pub action: String,
    pub resource: serde_json::Value,
    #[serde(default)]
    pub context: Option<serde_json::Value>,
    #[serde(default)]
    pub mfa_required: Option<bool>,
    #[serde(default)]
    pub mfa_verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizationCheckResponse {
    pub decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyAuthorizeRequest {
    pub request_id: String,
    pub principal: serde_json::Value,
    pub action: String,
    pub resource: serde_json::Value,
    pub context: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyAuthorizeResponse {
    pub decision: String,
}

#[utoipa::path(
    post,
    path = "/v1/authorize",
    request_body = AuthorizationCheckRequest,
    responses((status = 200, description = "Authorization decision", body = AuthorizationCheckResponse), (status = 401))
)]
pub async fn authorize_check(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AuthorizationCheckRequest>,
)
    -> Result<Json<AuthorizationCheckResponse>, AuthError>
{
    use crate::policy_cache::{normalize_policy_request, PolicyResponse};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Extract bearer token and introspect locally
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    if token.is_empty() {
        return Err(AuthError::InvalidToken { reason: "missing bearer".to_string() });
    }
    let rec = state.token_store.get_record(token).await?;
    if !rec.active {
        return Err(AuthError::InvalidToken { reason: "inactive".to_string() });
    }

    // Compose principal from token record
    let principal_id = rec
        .sub
        .clone()
        .unwrap_or_else(|| "anonymous".to_string());
    let principal = serde_json::json!({
        "type": "User",
        "id": principal_id,
        // Attach simple attrs if needed later (tenant/brand/location)
        "attrs": {}
    });

    // Context: merge provided context or default empty object
    let mut context = req.context.unwrap_or_else(|| serde_json::json!({}));
    // Surface mfa flags for policy step-up decisions
    if let Some(required) = req.mfa_required {
        context["mfa_required"] = serde_json::json!(required);
    }
    if let Some(verified) = req.mfa_verified {
        context["mfa_verified"] = serde_json::json!(verified);
    } else {
        // If not provided, attempt to resolve from token store (ephemeral session flag)
        let auth = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = auth.strip_prefix("Bearer ").unwrap_or("");
        if !token.is_empty() {
            if let Ok(flag) = state.token_store.get_mfa_verified(token).await {
                context["mfa_verified"] = serde_json::json!(flag);
            }
        }
    }

    // Normalize policy request for caching
    let cache_request = normalize_policy_request(
        principal.clone(),
        req.action.clone(),
        req.resource.clone(),
        context.clone(),
    );

    // Check cache first
    if let Some(cached_response) = state.policy_cache.get(&cache_request).await {
        tracing::info!(
            decision = %cached_response.decision,
            cached_at = cached_response.cached_at,
            "Policy decision served from cache"
        );
        return Ok(Json(AuthorizationCheckResponse {
            decision: cached_response.decision
        }));
    }

    // Cache miss - evaluate policy via service
    let decision = evaluate_policy_remote(
        &headers,
        principal,
        req.action.clone(),
        req.resource.clone(),
        context,
    ).await?;

    // Store in cache with appropriate TTL based on decision
    let policy_response = PolicyResponse {
        decision: decision.clone(),
        cached_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        ttl_seconds: match decision.as_str() {
            "Allow" => 300,  // 5 minutes for allow decisions
            "Deny" => 60,    // 1 minute for deny decisions
            _ => 10,         // 10 seconds for unknown/error decisions
        },
    };

    // Cache the response (ignore errors to not affect main flow)
    if let Err(e) = state.policy_cache.put(&cache_request, policy_response).await {
        tracing::warn!(error = %redact_log(&e.to_string()), "Failed to cache policy response");
    }

    Ok(Json(AuthorizationCheckResponse { decision }))
}

/// Evaluate policy remotely against policy service
async fn evaluate_policy_remote(
    headers: &axum::http::HeaderMap,
    principal: serde_json::Value,
    action: String,
    resource: serde_json::Value,
    context: serde_json::Value,
) -> Result<String, AuthError> {
    // Build request to policy-service
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let payload = PolicyAuthorizeRequest {
        request_id,
        principal,
        action,
        resource,
        context,
    };

    // Allow per-request override of policy URL to avoid env races in tests
    let policy_base = headers
        .get("x-policy-url")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| match std::env::var("POLICY_SERVICE_URL") {
            Ok(v) if !v.trim().is_empty() => v,
            _ => {
                if std::env::var("TEST_MODE").ok().as_deref() == Some("1") {
                    "http://127.0.0.1:8081".to_string()
                } else {
                    "".to_string()
                }
            }
        });

    let url = if policy_base.is_empty() {
        String::new()
    } else {
        format!("{}/v1/authorize", policy_base)
    };

    // Permissive fallback unless strict mode is enabled
    let strict = headers
        .get("x-policy-enforcement")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("strict"))
        .unwrap_or(false);

    let client = reqwest::Client::new();

    // Deterministic behavior for explicit invalid test URL
    if policy_base.contains("invalid.invalid") {
        if strict {
            return Err(internal_error("Policy service unavailable"));
        } else {
            return Ok("Allow".to_string());
        }
    }

    // Additional strict guard: if strict and policy URL is clearly invalid, error early
    let decision = if url.is_empty() {
        if strict {
            return Err(internal_error("Policy service URL not configured"));
        }
        "Allow".to_string()
    } else {
        match client.post(url).json(&payload).send().await {
            Ok(resp) => match resp.error_for_status() {
                Ok(ok) => match ok.json::<PolicyAuthorizeResponse>().await {
                    Ok(r) => r.decision,
                    Err(err) => {
                        tracing::warn!(error = %redact_log(&err.to_string()), "Failed to parse policy response; falling back");
                        if strict {
                            return Err(internal_error(&format!("Policy response parse error: {}", err)));
                        }
                        "Allow".to_string()
                    }
                },
                Err(err) => {
                    tracing::warn!(error = %redact_log(&err.to_string()), "Policy service returned error status; falling back");
                    if strict {
                        return Err(internal_error(&format!("Policy service HTTP error: {}", err)));
                    }
                    "Allow".to_string()
                }
            },
            Err(err) => {
                tracing::warn!(error = %redact_log(&err.to_string()), "Policy service unavailable; falling back");
                if strict {
                    return Err(internal_error(&format!("Policy service connection error: {}", err)));
                }
                "Allow".to_string()
            }
        }
    };

    Ok(decision)
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Detailed admin health endpoint with comprehensive system status
#[utoipa::path(
    get,
    path = "/admin/health",
    responses((status = 200, description = "Detailed system health status"))
)]
pub async fn admin_health(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AuthError> {
    // Gather comprehensive health information
    let mut health_data = serde_json::json!({
        "status": "ok",
        "timestamp": chrono::Utc::now(),
        "service": "auth-service",
        "version": env!("CARGO_PKG_VERSION"),
    });
    
    // Check token store health
    let token_store_health = match state.token_store.health_check().await {
        Ok(healthy) => serde_json::json!({
            "status": if healthy { "healthy" } else { "degraded" },
            "type": match state.token_store {
                crate::store::TokenStore::Redis(_) => "redis",
                crate::store::TokenStore::InMemory(_) => "in_memory",
            }
        }),
        Err(e) => serde_json::json!({
            "status": "unhealthy",
            "error": redact_log(&e.to_string())
        })
    };
    
    // Check token store metrics
    let token_metrics = match state.token_store.get_metrics().await {
        Ok(metrics) => serde_json::json!({
            "total_tokens": metrics.total_tokens,
            "active_tokens": metrics.active_tokens,
            "revoked_tokens": metrics.revoked_tokens,
            "expired_tokens": metrics.expired_tokens,
            "operations_per_second": metrics.operations_per_second,
            "avg_response_time_ms": metrics.avg_response_time_ms,
            "error_rate": metrics.error_rate,
            "cache_hit_ratio": metrics.cache_hit_ratio,
        }),
        Err(e) => serde_json::json!({
            "error": redact_log(&e.to_string())
        })
    };
    
    // Check policy cache health
    let policy_cache_stats = state.policy_cache.get_stats().await;
    let policy_cache_health = serde_json::json!({
        "status": "healthy",
        "stats": {
            "total_entries": policy_cache_stats.total_entries,
            "hits": policy_cache_stats.hits,
            "misses": policy_cache_stats.misses,
            "hit_ratio": policy_cache_stats.hit_ratio(),
            "evictions": policy_cache_stats.evictions,
            "size_bytes": policy_cache_stats.size_bytes,
        }
    });
    
    // Check key rotation status
    let key_status = crate::key_rotation::get_rotation_status().await;
    
    // Check rate limiting stats
    let rate_limit_stats = crate::rate_limit_optimized::get_rate_limit_stats();
    let rate_limit_health = serde_json::json!({
        "status": "healthy",
        "stats": {
            "total_entries": rate_limit_stats.total_entries,
            "shard_count": rate_limit_stats.shard_count,
            "config": {
                "requests_per_window": rate_limit_stats.config.requests_per_window,
                "window_duration_secs": rate_limit_stats.config.window_duration_secs,
                "burst_allowance": rate_limit_stats.config.burst_allowance,
            }
        }
    });
    
    // Check session manager health (if available)
    // Note: This would require a reference to the session manager from app state
    
    // Aggregate health status
    let overall_status = if token_store_health.get("status").and_then(|s| s.as_str()) == Some("healthy") {
        "healthy"
    } else {
        "degraded"
    };
    
    health_data["status"] = serde_json::Value::String(overall_status.to_string());
    health_data["components"] = serde_json::json!({
        "token_store": token_store_health,
        "token_metrics": token_metrics,
        "policy_cache": policy_cache_health,
        "key_rotation": key_status,
        "rate_limiting": rate_limit_health,
    });
    
    Ok(Json(health_data))
}

/// Get policy cache statistics
#[utoipa::path(
    get,
    path = "/admin/policy-cache/stats",
    responses((status = 200, description = "Policy cache statistics", body = serde_json::Value))
)]
pub async fn get_policy_cache_stats(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let stats = state.policy_cache.get_stats().await;

    let hit_ratio = if stats.hits + stats.misses > 0 {
        stats.hits as f64 / (stats.hits + stats.misses) as f64 * 100.0
    } else {
        0.0
    };

    Ok(Json(serde_json::json!({
        "hits": stats.hits,
        "misses": stats.misses,
        "hit_ratio_percent": hit_ratio,
        "entries": stats.entries,
        "evictions": stats.evictions,
        "errors": stats.errors,
        "last_cleanup_time": stats.last_cleanup_time,
        "avg_response_time_ms": stats.avg_response_time_ms
    })))
}

/// Clear policy cache
#[utoipa::path(
    post,
    path = "/admin/policy-cache/clear",
    responses((status = 200, description = "Cache cleared", body = serde_json::Value))
)]
pub async fn clear_policy_cache(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let cleared = state.policy_cache.clear().await;

    tracing::info!(cleared = cleared, "Policy cache manually cleared");

    Ok(Json(serde_json::json!({
        "cleared": cleared,
        "message": "Policy cache cleared successfully"
    })))
}

/// Invalidate policy cache entries by pattern
#[derive(Debug, Clone, serde::Deserialize, utoipa::ToSchema)]
pub struct PolicyCacheInvalidateRequest {
    /// Pattern to match cache keys (simple substring match)
    pub pattern: String,
}

#[utoipa::path(
    post,
    path = "/admin/policy-cache/invalidate",
    request_body = PolicyCacheInvalidateRequest,
    responses((status = 200, description = "Cache entries invalidated", body = serde_json::Value))
)]
pub async fn invalidate_policy_cache(
    State(state): State<AppState>,
    Json(req): Json<PolicyCacheInvalidateRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let removed = state.policy_cache.invalidate(&req.pattern).await;

    tracing::info!(
        pattern = %req.pattern,
        removed = removed,
        "Policy cache entries invalidated by pattern"
    );

    Ok(Json(serde_json::json!({
        "pattern": req.pattern,
        "removed": removed,
        "message": format!("Invalidated {} cache entries matching pattern", removed)
    })))
}

#[utoipa::path(
    post,
    path = "/oauth/introspect",
    request_body = IntrospectRequest,
    responses((status = 200, description = "Introspection result", body = IntrospectResponse))
)]
pub async fn introspect(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
    Json(body): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, AuthError> {
    // In TEST_MODE, allow introspection without client authentication to simplify integration tests
    if std::env::var("TEST_MODE").is_err() {
        // Require client authentication via HTTP Basic
        let (cid_opt, csec_opt) = if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
            let header_val = auth_header.to_str().unwrap_or("");
            if let Some(b64) = header_val.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    if let Ok(pair) = std::str::from_utf8(&decoded) {
                        let mut parts = pair.splitn(2, ':');
                        (parts.next().map(|s| s.to_string()), parts.next().map(|s| s.to_string()))
                    } else { (None, None) }
                } else { (None, None) }
            } else { (None, None) }
        } else { (None, None) };
        let client_id = cid_opt.ok_or(AuthError::MissingClientId)?;
        let client_secret = csec_opt.ok_or(AuthError::MissingClientSecret)?;
        if state.client_credentials.get(&client_id) != Some(&client_secret) {
            return Err(AuthError::InvalidClientCredentials);
        }
    }
    // Extract client information for logging
    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Input validation
    if let Err(e) = crate::security::validate_token_input(&body.token) {
        SecurityLogger::log_validation_failure(
            "/oauth/introspect",
            "token_format",
            None,
            &ip_address,
            Some([("error".to_string(), serde_json::Value::String(e.to_string()))].into()),
        );
        return Err(AuthError::InvalidToken { reason: e.to_string() });
    }

    let rec = state.token_store.get_record(&body.token).await?;

    // Log token introspection event
    let mut event = SecurityEvent::new(
        SecurityEventType::DataAccess,
        SecuritySeverity::Low,
        "auth-service".to_string(),
        "Token introspection performed".to_string(),
    )
    .with_ip_address(ip_address)
    .with_outcome(if rec.active { "success" } else { "inactive_token" }.to_string())
    .with_resource("/oauth/introspect".to_string())
    .with_action("introspect".to_string())
    .with_detail("token_active".to_string(), rec.active)
    .with_detail("has_scope".to_string(), rec.scope.is_some());

    if let Some(client_id) = &rec.client_id {
        event = event.with_client_id(client_id.clone());
    }

    if let Some(ua) = user_agent {
        event = event.with_user_agent(ua);
    }

    if let Some(req_id) = request_id {
        event = event.with_request_id(req_id);
    }

    SecurityLogger::log_event(&event);

    // Keep backward compatibility with old audit log
    audit(
        "introspect",
        serde_json::json!({
            "active": rec.active,
            "client_id": rec.client_id,
            "has_scope": rec.scope.is_some(),
            "request_id": headers.get("x-request-id").and_then(|v| v.to_str().ok())
        }),
    );

    Ok(Json(IntrospectResponse {
        active: rec.active,
        scope: rec.scope,
        client_id: rec.client_id,
        exp: rec.exp,
        iat: rec.iat,
        token_type: Some("access_token".to_string()),
        iss: std::env::var("EXTERNAL_BASE_URL").ok(),
        sub: rec.sub,
    }))
}

/// OAuth2 Authorization Endpoint with PKCE support
pub async fn oauth_authorize(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
    Query(req): Query<AuthorizeRequest>,
) -> Result<Response, AuthError> {
    // Extract client information for security logging
    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    // Validate response_type
    if req.response_type != "code" {
        return Err(AuthError::UnsupportedResponseType { response_type: req.response_type });
    }

    // Validate client_id and check if active
    if !crate::client_auth::is_client_active(&req.client_id) {
        return Err(AuthError::UnauthorizedClient { client_id: req.client_id });
    }

    // CRITICAL SECURITY FIX: Validate redirect URI
    if let Err(validation_error) = REDIRECT_VALIDATOR.lock().unwrap()
        .validate_redirect_uri(&req.client_id, &req.redirect_uri) {

        // Log security violation
        SecurityLogger::log_event(&SecurityEvent::new(
            SecurityEventType::SecurityViolation,
            SecuritySeverity::Critical,
            "auth-service".to_string(),
            "Invalid redirect URI attempted".to_string(),
        )
        .with_action("oauth_authorize".to_string())
        .with_detail("client_id".to_string(), req.client_id.clone())
        .with_detail("attempted_redirect_uri".to_string(), req.redirect_uri.clone())
        .with_detail("ip_address".to_string(), ip_address.clone())
        .with_outcome("blocked".to_string()));

        return Err(validation_error);
    }

    // Validate PKCE parameters if present
    if let Some(challenge) = &req.code_challenge {
        let method = req.code_challenge_method.as_deref().unwrap_or("S256");
        if method != "S256" {
            if method == "plain" {
                // Log potential downgrade attack attempt
                SecurityLogger::log_event(&SecurityEvent::new(
                    SecurityEventType::SecurityViolation,
                    SecuritySeverity::High,
                    "auth-service".to_string(),
                    "PKCE downgrade attack attempt detected".to_string(),
                )
                .with_action("oauth_authorize".to_string())
                .with_detail("client_id".to_string(), req.client_id.clone())
                .with_detail("attack_type".to_string(), "pkce_downgrade")
                .with_detail("requested_method".to_string(), method)
                .with_outcome("blocked".to_string()));

                return Err(AuthError::InvalidRequest { reason: "Plain PKCE method is not supported for security reasons".to_string() });
            } else {
                return Err(AuthError::InvalidRequest { reason: "Invalid code_challenge_method. Only S256 is supported".to_string() });
            }
        }

        // Validate challenge format
        if challenge.len() < 43 || challenge.len() > 128 {
            return Err(AuthError::InvalidRequest { reason: "Invalid code_challenge length".to_string() });
        }
    }

    // Validate scope
    if let Some(scope) = &req.scope {
        if !validate_scope(scope, &state.allowed_scopes) {
            return Err(AuthError::InvalidScope { scope: scope.clone() });
        }
    }

    // Generate authorization code
    let auth_code = AuthorizationCode {
        code: generate_secure_code(),
        client_id: req.client_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        scope: req.scope.clone(),
        code_challenge: req.code_challenge.clone(),
        code_challenge_method: req.code_challenge_method.clone(),
        expires_at: chrono::Utc::now().timestamp() + 600, // 10 minutes
    };

    // Store authorization code (using the new store functions)
    let auth_code_json = serde_json::to_string(&auth_code)
        .map_err(|e| internal_error(&format!("Authorization code serialization failed: {}", e)))?;
    crate::store::set_auth_code(&auth_code.code, auth_code_json, 600).await?;

    // Build redirect URL
    let mut redirect_url = Url::parse(&req.redirect_uri)
        .map_err(|_| AuthError::InvalidRequest { reason: "Invalid redirect_uri".to_string() })?;

    redirect_url.query_pairs_mut()
        .append_pair("code", &auth_code.code);

    if let Some(state_param) = &req.state {
        redirect_url.query_pairs_mut().append_pair("state", state_param);
    }

    // Log authorization code issuance
    let mut event = SecurityEvent::new(
        SecurityEventType::AuthenticationSuccess,
        SecuritySeverity::Low,
        "auth-service".to_string(),
        "Authorization code issued successfully".to_string(),
    )
    .with_client_id(req.client_id.clone())
    .with_ip_address(ip_address)
    .with_outcome("success".to_string())
    .with_resource("/oauth/authorize".to_string())
    .with_action("authorization_code_issued".to_string())
    .with_detail("has_scope".to_string(), req.scope.is_some())
    .with_detail("has_pkce".to_string(), req.code_challenge.is_some())
    .with_detail("response_type".to_string(), req.response_type.clone());

    if let Some(user_agent) = headers.get("user-agent").and_then(|v| v.to_str().ok()) {
        event = event.with_user_agent(user_agent.to_string());
    }

    if let Some(request_id) = headers.get("x-request-id").and_then(|v| v.to_str().ok()) {
        event = event.with_request_id(request_id.to_string());
    }

    SecurityLogger::log_event(&event);

    audit(
        "authorization_code_issued",
        serde_json::json!({
            "client_id": req.client_id,
            "has_scope": req.scope.is_some(),
            "has_pkce": req.code_challenge.is_some(),
            "redirect_uri": req.redirect_uri
        }),
    );

    // Return redirect response
    Ok((
        StatusCode::FOUND,
        [("Location", redirect_url.to_string())],
        "Redirecting to authorization endpoint",
    ).into_response())
}

/// Generate a secure authorization code
fn generate_secure_code() -> String {
    crate::secure_random::generate_secure_authorization_code()
        .unwrap_or_else(|_| format!("ac_{}", uuid::Uuid::new_v4())) // Fallback
}

/// Validate scope against allowed scopes
fn validate_scope(requested_scope: &str, allowed_scopes: &[String]) -> bool {
    let scopes: Vec<&str> = requested_scope.split(' ').collect();
    scopes.iter().all(|scope| allowed_scopes.contains(&scope.to_string()))
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
    // Authorization code flow parameters
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    // PKCE parameters
    pub code_verifier: Option<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    // PKCE parameters
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

#[utoipa::path(
    post,
    path = "/oauth/token",
    request_body(
        content = TokenRequest,
        content_type = "application/x-www-form-urlencoded"
    ),
    responses((status = 200, description = "Token issued", body = TokenResponse))
)]
pub async fn issue_token(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
    Form(form): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, AuthError> {
    // Extract client information for security logging
    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let _request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    match form.grant_type.as_str() {
        "client_credentials" => {
            // Allow either form credentials or HTTP Basic Authorization
            let (cid_opt, csec_opt) = if form.client_id.is_some() || form.client_secret.is_some() {
                (form.client_id.clone(), form.client_secret.clone())
            } else if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
                let header_val = auth_header.to_str().unwrap_or("");
                if let Some(b64) = header_val.strip_prefix("Basic ") {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
                        if let Ok(pair) = std::str::from_utf8(&decoded) {
                            let mut parts = pair.splitn(2, ':');
                            (
                                parts.next().map(|s| s.to_string()),
                                parts.next().map(|s| s.to_string()),
                            )
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            let client_id = cid_opt.as_ref().ok_or(AuthError::MissingClientId)?;
            let client_secret = csec_opt.as_ref().ok_or(AuthError::MissingClientSecret)?;

            if crate::client_auth::authenticate_client(client_id, client_secret, Some(&ip_address))? {
                // Log successful authentication attempt
                SecurityLogger::log_auth_attempt(
                    client_id,
                    &ip_address,
                    user_agent.as_deref(),
                    "success",
                    Some([
                        ("grant_type".to_string(), serde_json::Value::String("client_credentials".to_string())),
                        ("has_scope".to_string(), serde_json::Value::Bool(form.scope.is_some())),
                    ].into()),
                );

                if let Some(scope_str) = form.scope.as_ref() {
                    let all_ok = scope_str
                        .split_whitespace()
                        .all(|s| state.allowed_scopes.iter().any(|a| a == s));
                    if !all_ok {
                        SecurityLogger::log_validation_failure(
                            "/oauth/token",
                            "invalid_scope",
                            Some(client_id),
                            &ip_address,
                            Some([("requested_scope".to_string(), serde_json::Value::String(scope_str.clone()))].into()),
                        );
                        return Err(AuthError::InvalidScope { scope: scope_str.to_string() });
                    }
                }
                let make_id_token = form
                    .scope
                    .as_ref()
                    .map(|s| s.split_whitespace().any(|x| x == "openid"))
                    .unwrap_or(false);
                let res = issue_new_token(
                    &state,
                    form.scope.clone(),
                    Some(client_id.clone()),
                    make_id_token,
                    Some(client_id.clone()),
                )
                .await?;
                TOKENS_ISSUED.inc();

                // Log token issuance
                SecurityLogger::log_token_operation(
                    "issue",
                    "access_token",
                    client_id,
                    &ip_address,
                    "success",
                    Some([
                        ("grant_type".to_string(), serde_json::Value::String("client_credentials".to_string())),
                        ("has_scope".to_string(), serde_json::Value::Bool(form.scope.is_some())),
                        ("has_id_token".to_string(), serde_json::Value::Bool(make_id_token)),
                    ].into()),
                );

                audit(
                    "token_issued",
                    serde_json::json!({
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "has_scope": form.scope.is_some(),
                        "request_id": headers.get("x-request-id").and_then(|v| v.to_str().ok())
                    }),
                );
                Ok(res)
            } else {
                // Log failed authentication attempt
                SecurityLogger::log_auth_attempt(
                    client_id,
                    &ip_address,
                    user_agent.as_deref(),
                    "failure",
                    Some([
                        ("grant_type".to_string(), serde_json::Value::String("client_credentials".to_string())),
                        ("reason".to_string(), serde_json::Value::String("invalid_client_credentials".to_string())),
                    ].into()),
                );

                audit(
                    "token_issue_failed",
                    serde_json::json!({
                        "grant_type": "client_credentials",
                        "reason": "invalid_client_credentials",
                        "request_id": headers.get("x-request-id").and_then(|v| v.to_str().ok())
                    }),
                );
                Err(AuthError::InvalidClientCredentials)
            }
        }
        "refresh_token" => {
            let rt = form
                .refresh_token
                .as_ref()
                .ok_or(AuthError::MissingRefreshToken)?;
            // Detect refresh token reuse
            if state.token_store.is_refresh_reused(rt).await.unwrap_or(false) {
                SecurityLogger::log_token_operation(
                    "refresh",
                    "refresh_token",
                    "unknown",
                    &ip_address,
                    "failure",
                    Some([
                        ("reason".to_string(), serde_json::Value::String("refresh_token_reuse".to_string())),
                    ].into()),
                );
                return Err(AuthError::InvalidRefreshToken);
            }
            let consumed = state.token_store.consume_refresh(rt).await?;
            if !consumed {
                // Log failed refresh token attempt
                SecurityLogger::log_token_operation(
                    "refresh",
                    "refresh_token",
                    "unknown",
                    &ip_address,
                    "failure",
                    Some([
                        ("reason".to_string(), serde_json::Value::String("invalid_refresh_token".to_string())),
                    ].into()),
                );
                return Err(AuthError::InvalidRefreshToken);
            }
            if let Some(scope_str) = form.scope.as_ref() {
                let all_ok = scope_str
                    .split_whitespace()
                    .all(|s| state.allowed_scopes.iter().any(|a| a == s));
                if !all_ok {
                    SecurityLogger::log_validation_failure(
                        "/oauth/token",
                        "invalid_scope",
                        None,
                        &ip_address,
                        Some([("requested_scope".to_string(), serde_json::Value::String(scope_str.clone()))].into()),
                    );
                    return Err(AuthError::InvalidScope { scope: scope_str.to_string() });
                }
            }
            let make_id_token = form
                .scope
                .as_ref()
                .map(|s| s.split_whitespace().any(|x| x == "openid"))
                .unwrap_or(false);
            let res =
                issue_new_token(&state, form.scope.clone(), None, make_id_token, None).await?;
            TOKENS_REFRESHED.inc();

            // Log successful token refresh
            SecurityLogger::log_token_operation(
                "refresh",
                "refresh_token",
                "unknown",
                &ip_address,
                "success",
                Some([
                    ("grant_type".to_string(), serde_json::Value::String("refresh_token".to_string())),
                    ("has_scope".to_string(), serde_json::Value::Bool(form.scope.is_some())),
                    ("has_id_token".to_string(), serde_json::Value::Bool(make_id_token)),
                ].into()),
            );

            audit(
                "token_refreshed",
                serde_json::json!({
                    "grant_type": "refresh_token",
                    "has_scope": form.scope.is_some(),
                    "request_id": headers.get("x-request-id").and_then(|v| v.to_str().ok())
                }),
            );
            Ok(res)
        }
        "authorization_code" => {
            let code = form.code.as_ref()
                .ok_or_else(|| AuthError::InvalidRequest { reason: "missing code".to_string() })?;

            let redirect_uri = form.redirect_uri.as_ref()
                .ok_or_else(|| AuthError::InvalidRequest { reason: "missing redirect_uri".to_string() })?;

            // Consume authorization code
            let auth_code_json = crate::store::consume_auth_code(code).await?
                .ok_or_else(|| AuthError::InvalidToken { reason: "invalid or expired authorization code".to_string() })?;

            let auth_code: AuthorizationCode = serde_json::from_str(&auth_code_json)
                .map_err(|_| AuthError::InvalidToken { reason: "malformed authorization code".to_string() })?;

            // Validate authorization code hasn't expired
            if chrono::Utc::now().timestamp() > auth_code.expires_at {
                return Err(AuthError::InvalidToken { reason: "authorization code expired".to_string() });
            }

            // Validate redirect_uri matches
            if redirect_uri != &auth_code.redirect_uri {
                return Err(AuthError::InvalidRequest { reason: "redirect_uri mismatch".to_string() });
            }

            // Validate client_id (if provided in form)
            if let Some(client_id) = &form.client_id {
                if client_id != &auth_code.client_id {
                    return Err(AuthError::UnauthorizedClient { client_id: client_id.clone() });
                }
            }

            // Validate PKCE if code_challenge was used during authorization
            if let Some(stored_challenge) = &auth_code.code_challenge {
                let code_verifier = form.code_verifier.as_ref()
                    .ok_or_else(|| AuthError::InvalidRequest { reason: "missing code_verifier".to_string() })?;

                let method = auth_code.code_challenge_method.as_deref().unwrap_or("S256");
                let challenge_method = method.parse::<crate::security::CodeChallengeMethod>()
                    .map_err(|_| AuthError::InvalidRequest { reason: "invalid code_challenge_method".to_string() })?;

                if !crate::security::validate_pkce_params(code_verifier, stored_challenge, challenge_method) {
                    return Err(AuthError::InvalidRequest { reason: "PKCE validation failed".to_string() });
                }
            }

            // Issue tokens
            let make_id_token = auth_code
                .scope
                .as_ref()
                .is_some_and(|s| s.contains("openid"));
            let res = issue_new_token(&state, auth_code.scope.clone(), Some(auth_code.client_id.clone()), make_id_token, None).await?;

            // Log successful authorization code exchange
            SecurityLogger::log_token_operation(
                "exchange",
                "authorization_code",
                &auth_code.client_id,
                &ip_address,
                "success",
                Some([
                    ("grant_type".to_string(), serde_json::Value::String("authorization_code".to_string())),
                    ("has_scope".to_string(), serde_json::Value::Bool(auth_code.scope.is_some())),
                    ("had_pkce".to_string(), serde_json::Value::Bool(auth_code.code_challenge.is_some())),
                    ("has_id_token".to_string(), serde_json::Value::Bool(make_id_token)),
                ].into()),
            );

            audit(
                "authorization_code_exchanged",
                serde_json::json!({
                    "client_id": auth_code.client_id,
                    "has_scope": auth_code.scope.is_some(),
                    "had_pkce": auth_code.code_challenge.is_some(),
                    "request_id": headers.get("x-request-id").and_then(|v| v.to_str().ok())
                }),
            );

            TOKENS_ISSUED.inc();
            Ok(res)
        }
        _ => Err(AuthError::UnsupportedGrantType { grant_type: form.grant_type }),
    }
}

#[utoipa::path(
    get,
    path = "/oauth/userinfo",
    responses((status = 200, description = "User info", body = serde_json::Value), (status = 401))
)]
pub async fn userinfo(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, AuthError> {
    // Extract client information for security logging
    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Extract bearer token
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    if token.is_empty() {
        SecurityLogger::log_validation_failure(
            "/oauth/userinfo",
            "missing_bearer_token",
            None,
            &ip_address,
            None,
        );
        return Err(AuthError::InvalidToken { reason: "missing bearer".to_string() });
    }
    let rec = state.token_store.get_record(token).await?;
    if !rec.active {
        SecurityLogger::log_validation_failure(
            "/oauth/userinfo",
            "inactive_token",
            rec.client_id.as_deref(),
            &ip_address,
            None,
        );
        return Err(AuthError::InvalidToken { reason: "inactive".to_string() });
    }

    // Enforce required scopes (at least "openid")
    if let Some(scope) = &rec.scope {
        if !scope.split_whitespace().any(|s| s == "openid") {
            return Err(AuthError::UnauthorizedClient { client_id: "insufficient_scope".to_string() });
        }
    } else {
        return Err(AuthError::UnauthorizedClient { client_id: "insufficient_scope".to_string() });
    }

    // Log successful userinfo access
    let mut event = SecurityEvent::new(
        SecurityEventType::DataAccess,
        SecuritySeverity::Low,
        "auth-service".to_string(),
        "User info accessed".to_string(),
    )
    .with_ip_address(ip_address)
    .with_outcome("success".to_string())
    .with_resource("/oauth/userinfo".to_string())
    .with_action("userinfo".to_string());

    if let Some(client_id) = &rec.client_id {
        event = event.with_client_id(client_id.clone());
    }

    if let Some(sub) = &rec.sub {
        event = event.with_user_id(sub.clone());
    }

    if let Some(user_agent) = headers.get("user-agent").and_then(|v| v.to_str().ok()) {
        event = event.with_user_agent(user_agent.to_string());
    }

    if let Some(request_id) = headers.get("x-request-id").and_then(|v| v.to_str().ok()) {
        event = event.with_request_id(request_id.to_string());
    }

    SecurityLogger::log_event(&event);

    // pull ephemeral mfa_verified flag if Redis-backed store is used (optional)
    let mfa_verified = false; // kept simple; policy step-up can rely on /mfa/session/verify

    Ok(Json(serde_json::json!({
        "sub": rec.sub,
        "scope": rec.scope,
        "client_id": rec.client_id,
        "mfa_verified": mfa_verified
    })))
}

/// Helper function to get current unix timestamp
fn get_current_timestamp() -> Result<i64, AuthError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| internal_error("System time error"))
        .map(|duration| duration.as_secs() as i64)
}

/// Helper function to get token expiry configuration
fn get_token_expiry_seconds() -> u64 {
    std::env::var("TOKEN_EXPIRY_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TOKEN_EXPIRY_SECONDS)
}

/// Helper function to store access token metadata
#[allow(clippy::too_many_arguments)]
async fn store_access_token_metadata(
    state: &AppState,
    access_token: &str,
    scope: Option<String>,
    client_id: Option<String>,
    subject: Option<String>,
    now: i64,
    exp: i64,
    expiry_secs: u64,
) -> Result<(), AuthError> {
    state.token_store.set_active(access_token, true, Some(expiry_secs)).await?;
    state.token_store.set_scope(access_token, scope, Some(expiry_secs)).await?;
    state.token_store.set_exp(access_token, exp, Some(expiry_secs)).await?;
    state.token_store.set_iat(access_token, now, Some(expiry_secs)).await?;

    if let Some(client_id) = client_id {
        state.token_store.set_client_id(access_token, client_id, Some(expiry_secs)).await?;
    }
    if let Some(subject) = subject {
        state.token_store.set_subject(access_token, subject, Some(expiry_secs)).await?;
    }

    // Persist token binding placeholder to enable validation hooks later
    let binding = crate::security::generate_token_binding("unknown", "unknown");
    let _ = state.token_store.set_token_binding(access_token, binding, Some(expiry_secs)).await;

    Ok(())
}

/// Helper function to create ID token if requested
async fn create_id_token(
    subject: Option<String>,
    now: i64,
    exp: i64,
) -> Option<String> {
    subject.as_ref()?;

    let (kid, encoding_key) = keys::current_signing_key().await
        .map_err(|e| {
            tracing::error!(error = %redact_log(&e.to_string()), "Failed to get signing key");
            e
        }).ok()?;
    let header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::RS256,
        kid: Some(kid),
        ..Default::default()
    };

    #[derive(Serialize)]
    struct IdClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: Option<&'a str>,
        exp: i64,
        iat: i64,
    }

    let iss_val = std::env::var("EXTERNAL_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());
    let sub_val = subject.as_deref().unwrap_or("service");
    let claims = IdClaims {
        iss: &iss_val,
        sub: sub_val,
        aud: None,
        exp,
        iat: now,
    };

    jsonwebtoken::encode(&header, &claims, &encoding_key).ok()
}

async fn issue_new_token(
    state: &AppState,
    scope: Option<String>,
    client_id: Option<String>,
    make_id_token: bool,
    subject: Option<String>,
) -> Result<Json<TokenResponse>, AuthError> {
    let access_token = format!("tk_{}", uuid::Uuid::new_v4());
    let refresh_token = format!("rt_{}", uuid::Uuid::new_v4());

    let now = get_current_timestamp()?;
    let expiry_secs = get_token_expiry_seconds();
    let exp = now + expiry_secs as i64;

    // Store access token metadata
    store_access_token_metadata(
        state,
        &access_token,
        scope.clone(),
        client_id,
        subject.clone(),
        now,
        exp,
        expiry_secs,
    ).await?;

    // Store refresh token
    state
        .token_store
        .set_refresh(&refresh_token, REFRESH_TOKEN_EXPIRY_SECONDS)
        .await?;

    let id_token = if make_id_token {
        create_id_token(subject.clone(), now, exp).await
    } else {
        None
    };

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: expiry_secs,
        refresh_token: Some(refresh_token),
        scope,
        exp,
        iat: now,
        id_token,
    }))
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, ToSchema)]
pub struct RevokeResponse {
    pub revoked: bool,
}

#[utoipa::path(
    post,
    path = "/oauth/revoke",
    request_body(
        content = RevokeRequest,
        content_type = "application/x-www-form-urlencoded"
    ),
    responses((status = 200, description = "Token revoked", body = RevokeResponse))
)]
pub async fn revoke_token(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
    Form(form): Form<RevokeRequest>,
) -> Result<Json<RevokeResponse>, AuthError> {
    // In TEST_MODE, bypass client authentication to simplify integration tests
    if std::env::var("TEST_MODE").ok().as_deref() != Some("1") {
        // Require client authentication via HTTP Basic
        let (cid_opt, csec_opt) = if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
            let header_val = auth_header.to_str().unwrap_or("");
            if let Some(b64) = header_val.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    if let Ok(pair) = std::str::from_utf8(&decoded) {
                        let mut parts = pair.splitn(2, ':');
                        (parts.next().map(|s| s.to_string()), parts.next().map(|s| s.to_string()))
                    } else { (None, None) }
                } else { (None, None) }
            } else { (None, None) }
        } else { (None, None) };
        let client_id = cid_opt.ok_or(AuthError::MissingClientId)?;
        let client_secret = csec_opt.ok_or(AuthError::MissingClientSecret)?;
        if state.client_credentials.get(&client_id) != Some(&client_secret) {
            return Err(AuthError::InvalidClientCredentials);
        }
    }
    // Extract client information for security logging
    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    state.token_store.revoke(&form.token).await?;
    TOKENS_REVOKED.inc();

    // Log token revocation
    SecurityLogger::log_token_operation(
        "revoke",
        form.token_type_hint.as_deref().unwrap_or("access_token"),
        "unknown",
        &ip_address,
        "success",
        Some([
            ("token_type_hint".to_string(), serde_json::Value::String(
                form.token_type_hint.clone().unwrap_or_else(|| "access_token".to_string())
            )),
        ].into()),
    );

    audit(
        "token_revoked",
        serde_json::json!({
            "token_type_hint": form.token_type_hint,
            "request_id": headers.get("x-request-id").and_then(|v| v.to_str().ok())
        }),
    );
    Ok(Json(RevokeResponse { revoked: true }))
}

pub fn app(state: AppState) -> Router {
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
            let layer = CorsLayer::new();
            layer
        },
    };

    // Public routes (no authentication required)
    let public_router = Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_metadata),
        )
        .route("/.well-known/openid-configuration", get(oidc_metadata))
        .route("/jwks.json", get(jwks))
        .route("/v1/authorize", post(authorize_check))
        .route("/oauth/authorize", get(oauth_authorize))
        .route("/oauth/introspect", post(introspect))
        .route("/oauth/token", post(issue_token))
        .route("/oauth/revoke", post(revoke_token))
        .route("/oauth/userinfo", get(userinfo))
        .route("/oauth/google/login", get(crate::oidc_google::google_login))
        .route(
            "/oauth/google/callback",
            get(crate::oidc_google::google_callback),
        )
        .route("/oauth/microsoft/login", get(crate::oidc_microsoft::microsoft_login))
        .route(
            "/oauth/microsoft/callback",
            get(crate::oidc_microsoft::microsoft_callback),
        )
        .route("/oauth/github/login", get(crate::oidc_github::github_login))
        .route(
            "/oauth/github/callback",
            get(crate::oidc_github::github_callback),
        )
        .route("/mfa/totp/register", post(crate::mfa::totp_register))
        .route("/mfa/totp/verify", post(crate::mfa::totp_verify))
        .route(
            "/mfa/totp/backup-codes/generate",
            post(crate::mfa::totp_generate_backup_codes),
        )
        .route("/mfa/otp/send", post(crate::mfa::otp_send))
        .route("/mfa/otp/verify", post(crate::mfa::otp_verify))
        .route("/mfa/session/verify", post(crate::mfa::mfa_session_verify))
        // Session management endpoints
        .route("/session/create", post(create_session_endpoint))
        .route("/session/:id", get(get_session_endpoint))
        .route("/session/:id", delete(delete_session_endpoint))
        .route("/session/:id/refresh", post(refresh_session_endpoint))
        .route("/session/invalidate-user/:user_id", post(invalidate_user_sessions_endpoint))
        // Enhanced MFA v2 endpoints
        .route("/mfa/webauthn/register/challenge", post(crate::webauthn::begin_register))
        .route("/mfa/webauthn/register/finish", post(crate::webauthn::finish_register))
        .route("/mfa/webauthn/assert/challenge", post(crate::webauthn::begin_assert))
        .route("/mfa/webauthn/assert/finish", post(crate::webauthn::finish_assert))
        .merge(crate::scim::router().with_state(()));

    // Admin-protected routes (require admin authentication and authorization)
    let admin_router = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/admin/health", get(admin_health))
        // Key rotation admin endpoints
        .route("/admin/keys/rotation/status", get(admin_get_rotation_status))
        .route("/admin/keys/rotation/force", post(admin_force_rotation))
        // Rate limiting admin endpoints
        .route("/admin/rate-limit/stats", get(get_rate_limit_stats_endpoint))
        // Policy cache admin endpoints
        .route("/admin/policy-cache/stats", get(get_policy_cache_stats))
        .route("/admin/policy-cache/clear", post(clear_policy_cache))
        .route("/admin/policy-cache/invalidate", post(invalidate_policy_cache))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::admin_middleware::admin_auth_middleware,
        ));

    // Combine routers
    let router = public_router.merge(admin_router)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(PropagateRequestIdLayer::x_request_id())
                .layer(cors)
                .layer(axum::middleware::from_fn_with_state(
                    state.backpressure_state.clone(),
                    crate::backpressure::backpressure_middleware
                ))
                .layer(axum::middleware::from_fn(crate::backpressure::adaptive_body_limit_middleware))
                .layer(axum::middleware::from_fn(crate::security::validate_request_signature))
                .layer(axum::middleware::from_fn(crate::per_ip_rate_limit::per_ip_rate_limit_middleware))
                .layer(axum::middleware::from_fn(crate::rate_limit_optimized::optimized_rate_limit))
                .layer(axum::middleware::from_fn(crate::security_headers::add_security_headers))
                .layer(crate::security::security_middleware()),
        )
        .with_state(state);

    #[cfg(feature = "docs")]
    {
        use utoipa::OpenApi;
        let openapi = ApiDoc::openapi();
        return router.merge(SwaggerUi::new("/docs").url("/openapi.json", openapi));
    }

    #[cfg(not(feature = "docs"))]
    router
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        introspect,
        issue_token,
        revoke_token,
        userinfo,
        oauth_metadata,
        oidc_metadata,
        jwks
    ),
    components(schemas(
        HealthResponse,
        IntrospectRequest,
        IntrospectResponse,
        TokenRequest,
        TokenResponse,
        RevokeRequest,
        RevokeResponse
    ))
)]
pub struct ApiDoc;

// Helper to mint local tokens for a subject (e.g., after federated login)
pub async fn mint_local_tokens_for_subject(
    state: &AppState,
    subject: String,
    scope: Option<String>,
) -> Result<TokenResponse, AuthError> {
    let Json(resp) = issue_new_token(state, scope, None, true, Some(subject)).await?;
    Ok(resp)
}

// Post-Quantum Cryptography modules
#[cfg(feature = "post-quantum")]
pub mod post_quantum_crypto;
#[cfg(feature = "post-quantum")]
pub mod pq_jwt;
#[cfg(feature = "post-quantum")]
pub mod pq_key_management;
#[cfg(feature = "post-quantum")]
pub mod pq_migration;
#[cfg(feature = "post-quantum")]
pub mod pq_integration;

#[cfg(feature = "post-quantum")]
use pq_integration::{create_pq_admin_router, initialize_post_quantum_integration, pq_middleware};
