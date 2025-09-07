//! Application Router
//!
//! Configures the HTTP routes for the application.

use axum::http::{header, HeaderValue, Method};
use axum::{
    middleware::{from_fn, from_fn_with_state},
    routing::{get, post},
    Router,
};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::{self, TraceLayer};

use crate::app::AppContainer;
use crate::auth_api::AuthState;
use crate::backpressure::{
    adaptive_body_limit_middleware, backpressure_middleware, create_backpressure_middleware,
    BackpressureConfig,
};
use crate::config::{Config, CorsConfig};
use crate::handlers;
use crate::infrastructure::http::policy_client;
use crate::middleware::request_id_middleware;
use axum::extract::Extension;
use std::sync::Arc;
// use crate::modules::monitoring::{HealthChecker, MetricsCollector, MetricsMiddleware};  // Modules temporarily disabled

/// Create CORS layer from configuration
fn create_cors_layer_from_config(cors_config: &CorsConfig) -> CorsLayer {
    let mut layer = CorsLayer::new();
    
    // Configure allowed origins
    if !cors_config.allowed_origins.is_empty() {
        for origin in &cors_config.allowed_origins {
            if let Ok(header_value) = origin.parse::<HeaderValue>() {
                layer = layer.allow_origin(header_value);
            }
        }
    }
    
    // Configure allowed methods
    let methods: Vec<Method> = cors_config.allowed_methods
        .iter()
        .filter_map(|method| method.parse().ok())
        .collect();
    if !methods.is_empty() {
        layer = layer.allow_methods(methods);
    }
    
    // Configure allowed headers
    let headers: Vec<header::HeaderName> = cors_config.allowed_headers
        .iter()
        .filter_map(|header| header.parse().ok())
        .collect();
    if !headers.is_empty() {
        layer = layer.allow_headers(headers);
    }
    
    // Configure exposed headers
    if !cors_config.exposed_headers.is_empty() {
        let exposed: Vec<header::HeaderName> = cors_config.exposed_headers
            .iter()
            .filter_map(|header| header.parse().ok())
            .collect();
        layer = layer.expose_headers(exposed);
    }
    
    // Configure credentials and max age
    if cors_config.allow_credentials {
        layer = layer.allow_credentials(true);
    }
    
    layer.max_age(std::time::Duration::from_secs(cors_config.max_age))
}

/// Legacy CORS layer for backward compatibility
fn create_cors_layer() -> CorsLayer {
    // Fall back to environment variable for backward compatibility
    match std::env::var("ALLOWED_ORIGINS") {
        Ok(origins) if !origins.trim().is_empty() => {
            let mut layer = CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);
            for o in origins.split(',') {
                if let Ok(origin) = o.trim().parse::<HeaderValue>() {
                    layer = layer.allow_origin(origin);
                }
            }
            layer
        }
        _ => CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
    }
}

/// Shared configuration for HTTP tracing
fn create_trace_layer() -> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>, fn(&axum::http::Request<axum::body::Body>) -> tracing::Span> {
    TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
        let method = request.method().clone();
        let path = request.uri().path().to_string();
        let req_id = request
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        tracing::info_span!(
            "http_request",
            req_id = %req_id,
            method = %method,
            path = %path
        )
    })
}

/// Create the application router using AppContainer (new modular architecture)
pub fn create_router(container: AppContainer) -> Router {
    create_router_with_config(container, None)
}

/// Create the application router using AppContainer with optional config
pub fn create_router_with_config(container: AppContainer, config: Option<Arc<Config>>) -> Router {
    // Shared configuration
    let cors = if let Some(config) = &config {
        create_cors_layer_from_config(&config.security.cors)
    } else {
        create_cors_layer() // Legacy fallback
    };
    let bp_config = BackpressureConfig::from_env();
    let (timeout_layer, bp_state) = create_backpressure_middleware(&bp_config);
    let trace_layer = create_trace_layer();

    Router::new()
        .route("/api/v1/auth/register", post(handlers::auth::register))
        .route("/api/v1/auth/login", post(handlers::auth::login))
        .route("/api/v1/auth/me", get(handlers::auth::me))
        .route("/api/v1/auth/logout", post(handlers::auth::logout))
        .route("/health", get(health_check))
        .route("/health/detailed", get(detailed_health_check))
        .route("/api/v1/status", get(unified_status))
        .route("/metrics", get(metrics_endpoint))
        // .layer(metrics_middleware)  // Temporarily disabled
        .layer(from_fn(request_id_middleware))
        .layer(trace_layer)
        .layer(from_fn_with_state(
            container.clone(),
            admin_policy_gate_middleware,
        ))
        .layer(from_fn(adaptive_body_limit_middleware))
        .layer(Extension(bp_state))
        .layer(from_fn(backpressure_middleware))
        .layer(ConcurrencyLimitLayer::new(
            bp_config.max_concurrent_requests,
        ))
        .layer(timeout_layer)
        .layer(cors)
        .with_state(container)
}

/// Create a router using `AuthState` (runtime path)
/// Consolidates the main runtime routes used by `main.rs` so routing is defined in one place.
pub fn create_router_with_auth_state(auth_state: AuthState) -> Router {
    create_router_with_auth_state_and_config(auth_state, None)
}

/// Create a router using `AuthState` and config
pub fn create_router_with_auth_state_and_config(auth_state: AuthState, config: Option<Arc<Config>>) -> Router {
    use axum::routing::{get, post};
    use axum::{middleware::from_fn, Router};

    // Shared configuration
    let cors = if let Some(config) = &config {
        create_cors_layer_from_config(&config.security.cors)
    } else {
        create_cors_layer() // Legacy fallback
    };
    let bp_config = BackpressureConfig::from_env();
    let (timeout_layer, bp_state) = create_backpressure_middleware(&bp_config);
    let trace_layer = create_trace_layer();

    // Build router
    #[cfg_attr(not(feature = "metrics"), allow(unused_mut))]
    let mut router = Router::new()
        // Health and status endpoints
        .route("/health", get(unified_health_check))
        .route("/api/v1/status", get(unified_status))
        // CSRF token
        .route(
            "/csrf/token",
            get(crate::middleware::csrf::issue_csrf_token),
        )
        // Auth endpoints
        .route("/api/v1/auth/register", post(crate::auth_api::register))
        .route("/api/v1/auth/login", post(crate::auth_api::login))
        .route("/api/v1/auth/me", get(crate::auth_api::me))
        .route("/api/v1/auth/logout", post(crate::auth_api::logout))
        // JWKS endpoints
        .route("/.well-known/jwks.json", get(jwks_endpoint))
        .route("/jwks.json", get(jwks_endpoint))
        // OAuth 2.0 endpoints
        .route("/oauth/authorize", get(crate::auth_api::authorize))
        .route("/oauth/token", post(crate::auth_api::token))
        // Security monitoring
        .route(
            "/security/threats/metrics",
            get(crate::middleware::threat_metrics),
        )
        // Service Identity and JIT token endpoints
        .route(
            "/service/identity/register",
            post(service_identity_register),
        )
        .route("/token/jit", post(jit_token_request))
        // Middleware stack
        .layer(from_fn(crate::middleware::threat_detection_middleware))
        .layer(from_fn(
            crate::infrastructure::security::security::rate_limit,
        ))
        .layer(from_fn(crate::middleware::csrf::csrf_protect))
        .layer(from_fn(apply_security_headers))
        .layer(from_fn(request_id_middleware))
        .layer(trace_layer)
        .layer(Extension(bp_state))
        .layer(from_fn(backpressure_middleware))
        .layer(ConcurrencyLimitLayer::new(
            bp_config.max_concurrent_requests,
        ))
        .layer(timeout_layer)
        .layer(cors)
        .layer(Extension(auth_state))
        .with_state(());

    // Metrics feature gate
    #[cfg(feature = "metrics")]
    {
        use axum::response::IntoResponse as _;
        router = router.layer(from_fn(crate::metrics::metrics_middleware));
        router = router.route(
            "/metrics",
            get(|| async move {
                if std::env::var("METRICS_PUBLIC").unwrap_or_else(|_| "false".to_string()) == "true"
                {
                    crate::metrics::metrics_handler().into_response()
                } else {
                    match axum::response::Response::builder()
                        .status(axum::http::StatusCode::FORBIDDEN)
                        .body(axum::body::Body::from("metrics disabled"))
                    {
                        Ok(response) => response,
                        Err(_) => axum::response::Response::builder()
                            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                            .body(axum::body::Body::from("failed to build response"))
                            .unwrap_or_else(|_| {
                                // Last resort fallback
                                axum::http::Response::new(axum::body::Body::from("internal error"))
                            }),
                    }
                }
            }),
        );
    }

    router
}

/// Unified health check endpoint used by both routing paths
async fn unified_health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "rust-security-auth-service",
        "version": "2.0.0",
        "features": {
            "user_registration": true,
            "oauth2_flows": true,
            "jwt_authentication": true,
            "multi_factor_auth": false,
            "session_management": true,
            "security_monitoring": true,
            "rate_limiting": true
        }
    }))
}

/// Unified status endpoint used by both routing paths
async fn unified_status() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "service": "rust-security-auth-service",
        "status": "running",
        "version": "2.0.0",
        "features": [
            "user-registration",
            "oauth2-authorization-code",
            "jwt-authentication",
            "session-management",
            "security-monitoring",
            "multi-tenant",
            "rate-limiting",
            "pkce",
            "jwt-blacklisting",
            "request-fingerprinting",
            "adaptive-rate-limiting"
        ],
        "endpoints": {
            "authentication": [
                "POST /api/v1/auth/register",
                "POST /api/v1/auth/login",
                "POST /api/v1/auth/logout",
                "GET /api/v1/auth/me"
            ],
            "oauth2": [
                "GET /oauth/authorize",
                "POST /oauth/token"
            ],
            "jwks": [
                "GET /.well-known/jwks.json",
                "GET /jwks.json"
            ],
            "system": [
                "GET /health",
                "GET /api/v1/status"
            ],
            "security": [
                "GET /security/threats/metrics"
            ],
            "service_identity": [
                "POST /service/identity/register",
                "POST /token/jit"
            ]
        }
    }))
}

async fn jwks_endpoint(_ext: Extension<AuthState>) -> impl axum::response::IntoResponse {
    use axum::Json;

    let jwks = crate::infrastructure::crypto::keys::jwks_document().await;

    let mut headers = header::HeaderMap::new();
    if let Ok(content_type) = "application/json".parse() {
        headers.insert("content-type", content_type);
    }
    if let Ok(cache_control) = "public, max-age=300".parse() {
        headers.insert("cache-control", cache_control);
    }

    (headers, Json(jwks))
}

async fn service_identity_register(
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    use serde_json::json;
    let identity_id = format!("id_{}", uuid::Uuid::new_v4());
    let service_name = payload
        .get("service_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    tracing::info!(
        "Service identity registered: {} -> {}",
        service_name,
        identity_id
    );
    axum::Json(json!({
        "identity_id": identity_id,
        "service_name": service_name,
        "status": "registered",
        "created_at": chrono::Utc::now().to_rfc3339()
    }))
}

async fn jit_token_request(
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    use serde_json::json;
    let identity_id = payload
        .get("identity_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let access_token = format!("jit_token_{}", uuid::Uuid::new_v4());
    tracing::info!("JIT token generated for identity: {}", identity_id);
    let default_scope = json!(["read", "write"]);
    axum::Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": payload.get("scope").unwrap_or(&default_scope),
        "identity_id": identity_id,
        "issued_at": chrono::Utc::now().to_rfc3339()
    }))
}

// Security headers middleware
use axum::{extract::Request, middleware::Next, response::Response};
async fn apply_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers_map = crate::security_enhancements::headers::get_security_headers();
    let response_headers = response.headers_mut();
    for (key, value) in headers_map {
        if let Ok(header_value) = value.parse() {
            response_headers.insert(key, header_value);
        }
    }
    response
}

/// Basic health check endpoint for AppContainer router
async fn health_check() -> axum::Json<serde_json::Value> {
    unified_health_check().await
}

/// Detailed health check endpoint using the monitoring system
async fn detailed_health_check(
    axum::extract::State(container): axum::extract::State<AppContainer>,
) -> Result<axum::Json<serde_json::Value>, crate::shared::error::AppError> {
    let health_status = container
        .health_checker
        .check_health()
        .await
        .map_err(|e| crate::shared::error::AppError::Internal(e.to_string()))?;
    Ok(axum::Json(serde_json::json!(health_status)))
}

/// Prometheus metrics endpoint
async fn metrics_endpoint(
    axum::extract::State(container): axum::extract::State<AppContainer>,
) -> Result<String, crate::shared::error::AppError> {
    let metrics = container
        .metrics_collector
        .gather_metrics()
        .await
        .map_err(|e| crate::shared::error::AppError::Internal(e.to_string()))?;
    Ok(metrics.to_string())
}

// Note: Policy metrics are exported via the Prometheus registry when the `metrics` feature is enabled.

/// Lightweight admin policy gate for AppContainer router
async fn admin_policy_gate_middleware(
    axum::extract::State(_container): axum::extract::State<AppContainer>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, crate::shared::error::AppError> {
    let path = req.uri().path().to_string();
    if !path.starts_with("/admin") {
        return Ok(next.run(req).await);
    }

    if std::env::var("ENABLE_REMOTE_POLICY")
        .unwrap_or_else(|_| "0".to_string())
        .ne("1")
    {
        return Ok(next.run(req).await);
    }

    let method = req.method().as_str().to_string();
    let headers = req.headers().clone();
    let req_id = headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let policy_base = std::env::var("POLICY_SERVICE_BASE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());

    let action = derive_admin_action(&path, &method);

    let payload = policy_client::PolicyAuthorizeRequest {
        request_id: req_id.clone(),
        principal: serde_json::json!({
            "type": "Admin",
            "id": if headers.get(axum::http::header::AUTHORIZATION).is_some() { "with_token" } else { "no_token" }
        }),
        action,
        resource: serde_json::json!({"type":"AdminEndpoint","id": path}),
        context: serde_json::json!({"method": method}),
    };

    match policy_client::authorize_basic(&policy_base, &req_id, &payload).await {
        Ok(decision) if decision.eq_ignore_ascii_case("allow") => Ok(next.run(req).await),
        Ok(decision) => Err(crate::shared::error::AppError::Forbidden {
            reason: format!("Policy decision: {}", decision),
        }),
        Err(e) => {
            let fail_open = std::env::var("POLICY_FAIL_OPEN")
                .unwrap_or_else(|_| "0".to_string())
                .eq("1");
            if fail_open {
                tracing::warn!(request_id = %req_id, error = %e, "Admin policy gate failed; proceeding due to POLICY_FAIL_OPEN=1");
                Ok(next.run(req).await)
            } else {
                Err(crate::shared::error::AppError::ServiceUnavailable {
                    reason: format!("Policy check failed: {}", e),
                })
            }
        }
    }
}

fn derive_admin_action(path: &str, method: &str) -> String {
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if segs.len() >= 2 && segs[0] == "admin" {
        let area = segs[1];
        match area {
            "users" => {
                if segs.len() > 2 {
                    // /admin/users/:id
                    return match method {
                        "GET" => "Admin::users_read_one".to_string(),
                        "PUT" | "PATCH" => "Admin::users_update_one".to_string(),
                        "DELETE" => "Admin::users_delete_one".to_string(),
                        _ => format!("Admin::users_manage_one:{}", method),
                    };
                }
                match method {
                    "GET" => "Admin::users_read".to_string(),
                    "POST" => "Admin::users_create".to_string(),
                    "PUT" | "PATCH" => "Admin::users_update".to_string(),
                    "DELETE" => "Admin::users_delete".to_string(),
                    _ => format!("Admin::users_manage:{}", method),
                }
            }
            "keys" => {
                if segs.get(2) == Some(&"rotate") && matches!(method, "POST" | "PUT") {
                    "Admin::keys_rotate".to_string()
                } else {
                    "Admin::keys_read".to_string()
                }
            }
            "metrics" => "Admin::metrics_read".to_string(),
            "health" => "Admin::health_read".to_string(),
            "billing" => match method {
                "GET" => "Admin::billing_read".to_string(),
                "DELETE" => "Admin::billing_delete".to_string(),
                _ => "Admin::billing_update".to_string(),
            },
            "post-quantum" => {
                if segs.get(2) == Some(&"keys") && segs.get(3) == Some(&"rotate") {
                    "Admin::pq_keys_rotate".to_string()
                } else if segs.get(2) == Some(&"keys") && segs.get(3) == Some(&"stats") {
                    "Admin::pq_keys_stats".to_string()
                } else if segs.get(2) == Some(&"metrics") {
                    "Admin::pq_metrics".to_string()
                } else if segs.get(2) == Some(&"benchmark") {
                    "Admin::pq_benchmark".to_string()
                } else if segs.get(2) == Some(&"config") {
                    "Admin::pq_config".to_string()
                } else if segs.get(2) == Some(&"migration") && segs.get(3) == Some(&"phase") {
                    "Admin::pq_migration_phase".to_string()
                } else if segs.get(2) == Some(&"migration") && segs.get(3) == Some(&"timeline") {
                    "Admin::pq_migration_timeline".to_string()
                } else if segs.get(2) == Some(&"compliance") && segs.get(3) == Some(&"report") {
                    "Admin::pq_compliance_report".to_string()
                } else if segs.get(2) == Some(&"health") {
                    "Admin::pq_health".to_string()
                } else if segs.get(2) == Some(&"emergency") && segs.get(3) == Some(&"rollback") {
                    "Admin::pq_emergency_rollback".to_string()
                } else {
                    format!("Admin::post_quantum_access:{}", method)
                }
            }
            _ => format!("Admin::access:{}", method),
        }
    } else {
        format!("Admin::access:{}", method)
    }
}
