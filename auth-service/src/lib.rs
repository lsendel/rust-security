use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use once_cell::sync::Lazy;
use prometheus::{Encoder, IntCounter, Registry, TextEncoder};

static TOKENS_ISSUED: Lazy<IntCounter> =
    Lazy::new(|| IntCounter::new("tokens_issued_total", "tokens issued").unwrap());
static TOKENS_REFRESHED: Lazy<IntCounter> =
    Lazy::new(|| IntCounter::new("tokens_refreshed_total", "tokens refreshed").unwrap());
static TOKENS_REVOKED: Lazy<IntCounter> =
    Lazy::new(|| IntCounter::new("tokens_revoked_total", "tokens revoked").unwrap());
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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
#[cfg(feature = "docs")]
use utoipa::OpenApi;
use utoipa::ToSchema;
#[cfg(feature = "docs")]
use utoipa_swagger_ui::SwaggerUi;

pub mod keys;
pub mod security;
pub mod store;

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
        "grant_types_supported": ["client_credentials", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "id_token_signing_alg_values_supported": ["HS256"],
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
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
        token_type: Some("access_token".to_string()),
        iss: std::env::var("EXTERNAL_BASE_URL").ok(),
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

            if state.client_credentials.get(client_id) == Some(client_secret) {
                if let Some(scope_str) = form.scope.as_ref() {
                    let all_ok = scope_str
                        .split_whitespace()
                        .all(|s| state.allowed_scopes.iter().any(|a| a == s));
                    if !all_ok {
                        return Err(AuthError::InvalidScope);
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
            let make_id_token = form
                .scope
                .as_ref()
                .map(|s| s.split_whitespace().any(|x| x == "openid"))
                .unwrap_or(false);
            let res =
                issue_new_token(&state, form.scope.clone(), None, make_id_token, None).await?;
            TOKENS_REFRESHED.inc();
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
    make_id_token: bool,
    subject: Option<String>,
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

    let id_token = if make_id_token {
        let (kid, encoding_key) = keys::current_signing_key().await;
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
        jsonwebtoken::encode(&header, &claims, &encoding_key)
            .map(Some)
            .unwrap_or(None)
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
    state.token_store.revoke(&form.token).await?;
    TOKENS_REVOKED.inc();
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

    let router = Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_metadata),
        )
        .route("/.well-known/openid-configuration", get(oidc_metadata))
        .route("/jwks.json", get(jwks))
        .route("/metrics", get(metrics_handler))
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
        .with_state(state);

    #[cfg(feature = "docs")]
    {
        use utoipa::OpenApi;
        let openapi = ApiDoc::openapi();
        return router.merge(SwaggerUi::new("/docs").url("/openapi.json", openapi));
    }

    router
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        introspect,
        issue_token,
        revoke_token,
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
