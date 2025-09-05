//! Application Router
//!
//! Configures the HTTP routes for the application.

use axum::{
    middleware::{from_fn, from_fn_with_state},
    routing::{get, post},
    Router,
};
use axum::http::{header, HeaderValue, Method};
use tower_http::cors::CorsLayer;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::trace::{self, TraceLayer};

use crate::app::AppContainer;
use crate::handlers;
use crate::backpressure::{
    adaptive_body_limit_middleware, backpressure_middleware, create_backpressure_middleware,
    BackpressureConfig,
};
use crate::middleware::request_id_middleware;
use crate::infrastructure::http::policy_client;
// use crate::modules::monitoring::{HealthChecker, MetricsCollector, MetricsMiddleware};  // Modules temporarily disabled

/// Create the application router
pub fn create_router(container: AppContainer) -> Router {
    // Secure CORS: default deny; allow only if ALLOWED_ORIGINS is set
    let cors = match std::env::var("ALLOWED_ORIGINS") {
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
    };

    // Backpressure and timeouts
    let bp_config = BackpressureConfig::from_env();
    let (timeout_layer, bp_state) = create_backpressure_middleware(&bp_config);

    // HTTP tracing with request id enrichment
    let trace_layer = TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
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
    });

    Router::new()
        .route("/api/v1/auth/register", post(handlers::auth::register))
        .route("/api/v1/auth/login", post(handlers::auth::login))
        .route("/api/v1/auth/me", get(handlers::auth::me))
        .route("/api/v1/auth/logout", post(handlers::auth::logout))
        .route("/health", get(health_check))
        .route("/health/detailed", get(detailed_health_check))
        .route("/metrics", get(metrics_endpoint))
        // .layer(metrics_middleware)  // Temporarily disabled
        .layer(from_fn(request_id_middleware))
        .layer(trace_layer)
        .layer(from_fn_with_state(container.clone(), admin_policy_gate_middleware))
        .layer(from_fn(adaptive_body_limit_middleware))
        .layer(from_fn_with_state(bp_state, backpressure_middleware))
        .layer(ConcurrencyLimitLayer::new(bp_config.max_concurrent_requests))
        .layer(timeout_layer)
        .layer(cors)
        .with_state(container)
}

/// Basic health check endpoint
async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "rust-security-auth-service",
        "version": "2.0.0",
        "features": {
            "user_registration": true,
            "oauth2_flows": true,
            "jwt_authentication": true,
            "multi_factor_auth": false,
            "session_management": true
        }
    }))
}

/// Detailed health check endpoint using the monitoring system
async fn detailed_health_check(
    axum::extract::State(container): axum::extract::State<AppContainer>,
) -> Result<axum::Json<serde_json::Value>, crate::shared::error::AppError> {
    let health_status = container.health_checker.check_health().await
        .map_err(|e| crate::shared::error::AppError::Internal(e.to_string()))?;
    Ok(axum::Json(serde_json::json!(health_status)))
}

/// Prometheus metrics endpoint
async fn metrics_endpoint(
    axum::extract::State(container): axum::extract::State<AppContainer>,
) -> Result<String, crate::shared::error::AppError> {
    let metrics = container.metrics_collector.gather_metrics().await
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
