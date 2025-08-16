use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use utoipa::ToSchema;

pub mod security;
pub mod store;

fn audit(event: &str, payload: serde_json::Value) {
    tracing::info!(target: "audit", event, payload = %payload);
}

#[derive(Debug)]
pub enum AuthError {
    MissingClientId,
    MissingClientSecret,
    InvalidClientCredentials,
    MissingRefreshToken,
    InvalidRefreshToken,
    InvalidScope,
    InvalidToken(String),
    UnsupportedGrantType(String),
    InternalError(anyhow::Error),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingClientId => {
                (StatusCode::BAD_REQUEST, "missing client_id".to_string())
            }
            AuthError::MissingClientSecret => {
                (StatusCode::BAD_REQUEST, "missing client_secret".to_string())
            }
            AuthError::InvalidClientCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid client credentials".to_string(),
            ),
            AuthError::MissingRefreshToken => {
                (StatusCode::BAD_REQUEST, "missing refresh_token".to_string())
            }
            AuthError::InvalidRefreshToken => (
                StatusCode::UNAUTHORIZED,
                "invalid_refresh_token".to_string(),
            ),
            AuthError::InvalidScope => (StatusCode::BAD_REQUEST, "invalid_scope".to_string()),
            AuthError::InvalidToken(msg) => {
                (StatusCode::BAD_REQUEST, format!("invalid_token: {}", msg))
            }
            AuthError::UnsupportedGrantType(gt) => (
                StatusCode::BAD_REQUEST,
                format!("unsupported grant_type: {}", gt),
            ),
            AuthError::InternalError(err) => {
                tracing::error!("Internal error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        (status, message).into_response()
    }
}

impl From<anyhow::Error> for AuthError {
    fn from(err: anyhow::Error) -> Self {
        AuthError::InternalError(err)
    }
}

impl From<redis::RedisError> for AuthError {
    fn from(err: redis::RedisError) -> Self {
        AuthError::InternalError(err.into())
    }
}

#[derive(Clone)]
pub struct AppState {
    pub token_store: crate::store::TokenStore,
    pub client_credentials: HashMap<String, String>,
    pub allowed_scopes: Vec<String>,
}

// TokenStore moved to store.rs

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct IntrospectionRecord {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
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
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
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
    // Input validation
    crate::security::validate_token_input(&body.token)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

    let rec = state.token_store.get_record(&body.token).await?;
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
    }))
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub refresh_token: Option<String>,
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
    match form.grant_type.as_str() {
        "client_credentials" => {
            let client_id = form.client_id.as_ref().ok_or(AuthError::MissingClientId)?;
            let client_secret = form
                .client_secret
                .as_ref()
                .ok_or(AuthError::MissingClientSecret)?;

            if state.client_credentials.get(client_id) == Some(client_secret) {
                if let Some(scope_str) = form.scope.as_ref() {
                    let all_ok = scope_str
                        .split_whitespace()
                        .all(|s| state.allowed_scopes.iter().any(|a| a == s));
                    if !all_ok {
                        return Err(AuthError::InvalidScope);
                    }
                }
                let res =
                    issue_new_token(&state, form.scope.clone(), Some(client_id.clone())).await?;
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
            let consumed = state.token_store.consume_refresh(rt).await?;
            if !consumed {
                return Err(AuthError::InvalidRefreshToken);
            }
            if let Some(scope_str) = form.scope.as_ref() {
                let all_ok = scope_str
                    .split_whitespace()
                    .all(|s| state.allowed_scopes.iter().any(|a| a == s));
                if !all_ok {
                    return Err(AuthError::InvalidScope);
                }
            }
            let res = issue_new_token(&state, form.scope.clone(), None).await?;
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
        _ => Err(AuthError::UnsupportedGrantType(form.grant_type)),
    }
}

async fn issue_new_token(
    state: &AppState,
    scope: Option<String>,
    client_id: Option<String>,
) -> Result<Json<TokenResponse>, AuthError> {
    let access_token = format!("tk_{}", uuid::Uuid::new_v4());
    let refresh_token = format!("rt_{}", uuid::Uuid::new_v4());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expiry_secs: u64 = std::env::var("TOKEN_EXPIRY_SECONDS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);
    let exp = now + expiry_secs as i64;
    state
        .token_store
        .set_active(&access_token, true, Some(expiry_secs))
        .await?;
    state
        .token_store
        .set_scope(&access_token, scope.clone(), Some(expiry_secs))
        .await?;
    state
        .token_store
        .set_exp(&access_token, exp, Some(expiry_secs))
        .await?;
    state
        .token_store
        .set_iat(&access_token, now, Some(expiry_secs))
        .await?;
    if let Some(client_id) = client_id {
        state
            .token_store
            .set_client_id(&access_token, client_id, Some(expiry_secs))
            .await?;
    }
    state
        .token_store
        .set_refresh(&refresh_token, 14 * 24 * 3600)
        .await?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: expiry_secs,
        refresh_token: Some(refresh_token),
        scope,
        exp,
        iat: now,
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
    state.token_store.revoke(&form.token).await?;
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
        _ => CorsLayer::new().allow_origin(Any),
    };

    Router::new()
        .route("/health", get(health))
        .route("/oauth/introspect", post(introspect))
        .route("/oauth/token", post(issue_token))
        .route("/oauth/revoke", post(revoke_token))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(PropagateRequestIdLayer::x_request_id())
                .layer(cors)
                .layer(axum::middleware::from_fn(crate::security::rate_limit))
                .layer(axum::middleware::from_fn(crate::security::security_headers))
                .layer(crate::security::security_middleware()),
        )
        .with_state(state)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(introspect, issue_token, revoke_token),
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
