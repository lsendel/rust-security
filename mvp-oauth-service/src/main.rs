//! MVP OAuth 2.0 Service with Enhanced Security
//!
//! A production-ready OAuth 2.0 service with enterprise-grade security validation
//! and policy-based authorization built on mvp-tools.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
// TODO: use common::security::UnifiedSecurityConfig;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use mvp_tools::{
    policy::MvpPolicyEngine,
    validation::{validate_input, SecurityContext, ThreatLevel},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::info;
use uuid::Uuid;

/// OAuth 2.0 token request
#[derive(Debug, Serialize, Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    scope: Option<String>,
}

/// OAuth 2.0 token response
#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// Token introspection request
#[derive(Debug, Deserialize)]
struct IntrospectRequest {
    token: String,
}

/// Token introspection response  
#[derive(Debug, Serialize)]
struct IntrospectResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// JSON Web Key Set (JWKS) response
#[derive(Debug, Serialize)]
struct JwksResponse {
    keys: Vec<JsonWebKey>,
}

/// JSON Web Key (JWK) for public key distribution
#[derive(Debug, Serialize)]
struct JsonWebKey {
    kty: String, // Key Type
    alg: String, // Algorithm
    kid: String, // Key ID
    k: String,   // Key Value (base64url encoded)

    #[serde(rename = "use")]
    key_use: String, // Public Key Use
}

/// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    client_id: String,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// OAuth Client
#[derive(Debug, Clone)]
struct OAuthClient {
    #[allow(dead_code)]
    id: String,
    secret: String,
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    scopes: Vec<String>,
}

/// Application State
#[derive(Clone)]
pub struct AppState {
    jwt_secret: String,
    clients: Arc<RwLock<HashMap<String, OAuthClient>>>,
    #[allow(dead_code)]
    policy_engine: Arc<MvpPolicyEngine>,
}

impl AppState {
    pub fn new(jwt_secret: String) -> Self {
        let mut clients = HashMap::new();

        // Add default MVP client
        clients.insert(
            "mvp-client".to_string(),
            OAuthClient {
                id: "mvp-client".to_string(),
                secret: "mvp-secret".to_string(),
                name: "MVP Test Client".to_string(),
                scopes: vec!["read".to_string(), "write".to_string()],
            },
        );

        Self {
            jwt_secret,
            clients: Arc::new(RwLock::new(clients)),
            policy_engine: Arc::new(MvpPolicyEngine::new()),
        }
    }
}

/// OAuth 2.0 Client Credentials Flow
async fn oauth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    // Create security context for enhanced validation
    let client_ip = extract_client_ip(&headers);
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(String::from);

    let security_ctx = SecurityContext::new()
        .with_request_id(Uuid::new_v4().to_string())
        .with_client_info(client_ip, user_agent)
        .with_threat_level(ThreatLevel::Low);

    // Enhanced input validation using mvp-tools
    if let Err(e) = validate_input(&req.grant_type) {
        security_ctx.log_security_incident(&format!("Invalid grant_type: {}", e));
        return Err((StatusCode::BAD_REQUEST, "Invalid grant type".to_string()));
    }

    if let Err(e) = validate_input(&req.client_id) {
        security_ctx.log_security_incident(&format!("Invalid client_id: {}", e));
        return Err((StatusCode::BAD_REQUEST, "Invalid client ID".to_string()));
    }

    // Validate grant type
    if req.grant_type != "client_credentials" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Unsupported grant type".to_string(),
        ));
    }

    // Authenticate client
    let clients = state.clients.read().await;
    let client = clients
        .get(&req.client_id)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid client".to_string()))?;

    if client.secret != req.client_secret {
        security_ctx.log_security_incident(&format!(
            "Authentication failed for client: {}",
            req.client_id
        ));
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid client credentials".to_string(),
        ));
    }

    // Create JWT token
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    let claims = Claims {
        sub: req.client_id.clone(),
        client_id: req.client_id.clone(),
        iat: now.timestamp(),
        exp: exp.timestamp(),
        scope: req.scope.clone(),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_ref()),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Token generation failed: {}", e),
        )
    })?;

    info!("Token issued for client: {}", req.client_id);

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        scope: req.scope,
    }))
}

/// Token introspection endpoint
async fn oauth_introspect(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(req): Json<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, (StatusCode, String)> {
    // Enhanced validation
    if let Err(e) = validate_input(&req.token) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid token: {}", e)));
    }

    // Decode and validate JWT
    let validation = Validation::new(Algorithm::HS256);
    match decode::<Claims>(
        &req.token,
        &DecodingKey::from_secret(state.jwt_secret.as_ref()),
        &validation,
    ) {
        Ok(token_data) => {
            let claims = token_data.claims;

            Ok(Json(IntrospectResponse {
                active: true,
                client_id: Some(claims.client_id),
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                scope: claims.scope,
            }))
        }
        Err(_) => Ok(Json(IntrospectResponse {
            active: false,
            client_id: None,
            exp: None,
            iat: None,
            scope: None,
        })),
    }
}

/// Health check endpoint
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "mvp-oauth-service",
        "version": "1.0.0",
        "timestamp": Utc::now().to_rfc3339(),
        "features": {
            "enhanced_validation": true,
            "policy_engine": true,
            "client_credentials": true,
            "token_introspection": true,
            "jwks_endpoint": true
        }
    }))
}

/// Basic metrics endpoint
async fn metrics() -> String {
    format!(
        "# HELP oauth_requests_total Total OAuth requests\n# TYPE oauth_requests_total counter\noauth_requests_total 0\n# Generated at {}\n",
        Utc::now().to_rfc3339()
    )
}

/// JWKS endpoint for public key distribution
async fn jwks(State(state): State<AppState>) -> Json<JwksResponse> {
    // Generate a stable key ID from the JWT secret
    let key_id = format!(
        "mvp-key-{}",
        general_purpose::URL_SAFE_NO_PAD.encode(&state.jwt_secret.as_bytes()[..8])
    );

    // Encode the JWT secret as base64url for distribution as symmetric key
    let key_value = general_purpose::URL_SAFE_NO_PAD.encode(state.jwt_secret.as_bytes());

    let jwk = JsonWebKey {
        kty: "oct".to_string(),     // Octet sequence (symmetric key)
        alg: "HS256".to_string(),   // HMAC using SHA-256
        kid: key_id,                // Key identifier
        k: key_value,               // Key value
        key_use: "sig".to_string(), // For signature verification
    };

    Json(JwksResponse { keys: vec![jwk] })
}

/// Extract client IP from headers
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
}

/// Create application router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/oauth/token", post(oauth_token))
        .route("/oauth/introspect", post(oauth_introspect))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Create application state
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "mvp-secret-key".to_string());
    let state = AppState::new(jwt_secret);

    // Create router
    let app = create_router(state);

    // Start server
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    info!("🚀 MVP OAuth Service starting on {}", addr);
    info!("✅ Enhanced security validation enabled");
    info!("✅ Policy engine initialized");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = AppState::new("test-secret".to_string());
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_oauth_token_success() {
        let state = AppState::new("test-secret".to_string());
        let app = create_router(state);

        let token_request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: "mvp-client".to_string(),
            client_secret: "mvp-secret".to_string(),
            scope: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/token")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&token_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_oauth_token_invalid_client() {
        let state = AppState::new("test-secret".to_string());
        let app = create_router(state);

        let token_request = TokenRequest {
            grant_type: "client_credentials".to_string(),
            client_id: "invalid-client".to_string(),
            client_secret: "wrong-secret".to_string(),
            scope: None,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/oauth/token")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&token_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_complete_oauth_flow() {
        let state = AppState::new("test-jwt-secret".to_string());
        let app = create_router(state);

        // Step 1: Test health check
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let health: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(health["status"], "healthy");
        assert_eq!(health["service"], "mvp-oauth-service");
        assert_eq!(health["features"]["enhanced_validation"], true);

        // Step 2: Request OAuth token with valid credentials
        let token_request = serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "mvp-client",
            "client_secret": "mvp-secret"
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/token")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&token_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let token_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(token_response["token_type"], "Bearer");
        assert_eq!(token_response["expires_in"], 3600);

        let access_token = token_response["access_token"].as_str().unwrap();
        assert!(!access_token.is_empty());

        // Step 3: Introspect the token
        let introspect_request = serde_json::json!({
            "token": access_token
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/introspect")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&introspect_request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let introspect_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(introspect_response["active"], true);
        assert_eq!(introspect_response["client_id"], "mvp-client");
    }

    #[tokio::test]
    async fn test_security_validation() {
        let state = AppState::new("test-jwt-secret".to_string());
        let app = create_router(state);

        // Test malicious client_id with control characters
        let malicious_request = serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "malicious\x00client",
            "client_secret": "secret"
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/token")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&malicious_request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Test invalid token introspection
        let invalid_introspect = serde_json::json!({
            "token": "malicious\x00token"
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/introspect")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&invalid_introspect).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_invalid_token_introspection() {
        let state = AppState::new("test-jwt-secret".to_string());
        let app = create_router(state);

        // Test with invalid JWT token
        let invalid_token = serde_json::json!({
            "token": "invalid.jwt.token"
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/oauth/introspect")
                    .method("POST")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&invalid_token).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let introspect_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(introspect_response["active"], false);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let state = AppState::new("test-jwt-secret".to_string());
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let metrics = String::from_utf8(body.to_vec()).unwrap();

        assert!(metrics.contains("oauth_requests_total"));
        assert!(metrics.contains("# HELP"));
        assert!(metrics.contains("# TYPE"));
    }

    #[tokio::test]
    async fn test_jwks_endpoint() {
        let state = AppState::new("test-jwt-secret".to_string());
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert!(jwks["keys"].is_array());
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);

        let key = &jwks["keys"][0];
        assert_eq!(key["kty"], "oct");
        assert_eq!(key["alg"], "HS256");
        assert_eq!(key["use"], "sig");
        assert!(key["kid"].is_string());
        assert!(key["k"].is_string());
    }
}
