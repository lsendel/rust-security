//! Complete Axum integration example
//! 
//! This example demonstrates how to integrate auth-core with Axum web framework
//! for a complete OAuth 2.0 authentication system.

use auth_core::prelude::*;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{info, warn};

// Application state
#[derive(Clone)]
pub struct AppState {
    auth_server: Arc<AuthServer>,
}

// API response types
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Serialize)]
struct UserProfile {
    id: String,
    name: String,
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    scope: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::init();

    info!("🚀 Starting Axum + Auth-Core integration example");

    // Build auth server
    let auth_server = AuthServer::minimal()
        .with_client("web_client", "web_secret_12345")
        .with_client("mobile_client", "mobile_secret_67890")
        .with_client("service_client", "service_secret_abcde")
        .with_scope("read")
        .with_scope("write") 
        .with_scope("admin")
        .with_token_ttl(3600) // 1 hour
        .build()
        .expect("Failed to build auth server");

    let app_state = AppState {
        auth_server: Arc::new(auth_server),
    };

    // Build application with routes
    let app = create_router(app_state).await;

    // Start server
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    info!("🌐 Server listening on http://127.0.0.1:8080");
    info!("📖 Try these endpoints:");
    info!("  - GET  / (home page)");
    info!("  - POST /oauth/token (get access token)");
    info!("  - POST /oauth/introspect (validate token)");
    info!("  - GET  /api/profile (protected endpoint)");
    info!("  - GET  /api/admin (admin-only endpoint)");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn create_router(state: AppState) -> Router {
    // OAuth routes
    let oauth_routes = Router::new()
        .route("/token", post(handle_token))
        .route("/introspect", post(handle_introspect));

    // Protected API routes
    let api_routes = Router::new()
        .route("/profile", get(get_profile))
        .route("/admin", get(admin_endpoint))
        .route("/data", get(get_data).post(create_data))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // Public routes
    let public_routes = Router::new()
        .route("/", get(home_page))
        .route("/health", get(health_check))
        .route("/docs", get(api_docs));

    // Combine all routes
    Router::new()
        .nest("/oauth", oauth_routes)
        .nest("/api", api_routes)
        .merge(public_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                ),
        )
        .with_state(state)
}

// OAuth Token Endpoint
async fn handle_token(
    State(_state): State<AppState>,
    axum::Form(req): axum::Form<TokenRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("Token request from client: {}", req.client_id);

    // Validate grant type
    if req.grant_type != "client_credentials" {
        warn!("Invalid grant type: {}", req.grant_type);
        return Ok(Json(serde_json::json!({
            "error": "unsupported_grant_type",
            "error_description": "Only client_credentials is supported"
        })));
    }

    // Authenticate client
    if !state.auth_server.validate_client(&req.client_id, &req.client_secret) {
        warn!("Client authentication failed: {}", req.client_id);
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Generate token
    let token = state.auth_server.generate_token(
        &req.client_id,
        req.scope.as_deref().unwrap_or("read"),
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!("Token issued successfully for client: {}", req.client_id);

    Ok(Json(serde_json::json!({
        "access_token": token.access_token,
        "token_type": "Bearer",
        "expires_in": token.expires_in,
        "scope": token.scope
    })))
}

// OAuth Token Introspection Endpoint
async fn handle_introspect(
    State(_state): State<AppState>,
    axum::Form(params): axum::Form<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let token = params.get("token").unwrap_or(&String::new()).clone();
    let client_id = params.get("client_id").unwrap_or(&String::new()).clone();
    let client_secret = params.get("client_secret").unwrap_or(&String::new()).clone();

    // Authenticate client
    if !state.auth_server.validate_client(&client_id, &client_secret) {
        return Json(serde_json::json!({"active": false}));
    }

    // Validate token
    match state.auth_server.introspect_token(&token) {
        Ok(token_info) => {
            Json(serde_json::json!({
                "active": token_info.active,
                "client_id": token_info.client_id,
                "scope": token_info.scope,
                "exp": token_info.exp,
                "token_type": "Bearer"
            }))
        }
        Err(_) => Json(serde_json::json!({"active": false})),
    }
}

// Authentication middleware
async fn auth_middleware(
    State(_state): State<AppState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<impl IntoResponse, StatusCode> {
    // Extract authorization header
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            &header[7..] // Remove "Bearer " prefix
        }
        _ => {
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Validate token
    match state.auth_server.introspect_token(token) {
        Ok(token_info) if token_info.active => {
            // Add token info to request extensions for handlers to use
            request.extensions_mut().insert(token_info);
            Ok(next.run(request).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

// Protected API endpoints
async fn get_profile(
    axum::Extension(token_info): axum::Extension<TokenInfo>,
) -> Json<ApiResponse<UserProfile>> {
    let profile = UserProfile {
        id: token_info.client_id.clone(),
        name: format!("User {}", token_info.client_id),
        scopes: token_info.scope.split_whitespace().map(String::from).collect(),
    };

    Json(ApiResponse {
        success: true,
        data: Some(profile),
        error: None,
    })
}

async fn admin_endpoint(
    axum::Extension(token_info): axum::Extension<TokenInfo>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // Check for admin scope
    if !token_info.scope.contains("admin") {
        return Err(StatusCode::FORBIDDEN);
    }

    Json(ApiResponse {
        success: true,
        data: Some("Welcome to the admin panel!".to_string()),
        error: None,
    })
    .into()
}

async fn get_data(
    axum::Extension(token_info): axum::Extension<TokenInfo>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<ApiResponse<serde_json::Value>> {
    // Check for read scope
    if !token_info.scope.contains("read") {
        return Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Insufficient scope: read required".to_string()),
        });
    }

    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    let data = serde_json::json!({
        "items": (1..=limit).map(|i| format!("Item {}", i)).collect::<Vec<_>>(),
        "total": limit,
        "client_id": token_info.client_id
    });

    Json(ApiResponse {
        success: true,
        data: Some(data),
        error: None,
    })
}

async fn create_data(
    axum::Extension(token_info): axum::Extension<TokenInfo>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // Check for write scope
    if !token_info.scope.contains("write") {
        return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Insufficient scope: write required".to_string()),
        }));
    }

    info!("Creating data: {:?} for client: {}", payload, token_info.client_id);

    Ok(Json(ApiResponse {
        success: true,
        data: Some(format!("Data created by {}", token_info.client_id)),
        error: None,
    }))
}

// Public endpoints
async fn home_page() -> Html<&'static str> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Auth-Core + Axum Integration</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .method { color: white; padding: 2px 8px; border-radius: 3px; font-weight: bold; }
        .get { background: #28a745; }
        .post { background: #007bff; }
        code { background: #f8f9fa; padding: 2px 4px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Auth-Core + Axum Integration</h1>
        <p>This example demonstrates OAuth 2.0 authentication with Axum web framework.</p>
        
        <h2>Available Endpoints</h2>
        
        <div class="endpoint">
            <span class="method post">POST</span> <code>/oauth/token</code>
            <p>Get access token using client credentials</p>
        </div>
        
        <div class="endpoint">
            <span class="method post">POST</span> <code>/oauth/introspect</code>
            <p>Validate and inspect access token</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span> <code>/api/profile</code>
            <p>Get user profile (requires authentication)</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span> <code>/api/admin</code>
            <p>Admin endpoint (requires admin scope)</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span> <code>/api/data</code>
            <p>Get data (requires read scope)</p>
        </div>
        
        <h2>Example Usage</h2>
        <pre><code># 1. Get access token
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=web_client" \
  -d "client_secret=web_secret_12345" \
  -d "scope=read write"

# 2. Use token to access protected endpoint
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/profile</code></pre>
     
        <h2>Test Clients</h2>
        <ul>
            <li><strong>web_client</strong> / web_secret_12345 (read, write scope)</li>
            <li><strong>mobile_client</strong> / mobile_secret_67890 (read scope)</li>
            <li><strong>service_client</strong> / service_secret_abcde (read, write, admin scope)</li>
        </ul>
    </div>
</body>
</html>
    "#)
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "auth-core-axum",
        "version": "1.0.0",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn api_docs() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "openapi": "3.0.0",
        "info": {
            "title": "Auth-Core API",
            "version": "1.0.0",
            "description": "OAuth 2.0 authentication service"
        },
        "servers": [
            {"url": "http://localhost:8080", "description": "Development server"}
        ],
        "paths": {
            "/oauth/token": {
                "post": {
                    "summary": "Get access token",
                    "requestBody": {
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "grant_type": {"type": "string", "example": "client_credentials"},
                                        "client_id": {"type": "string", "example": "web_client"},
                                        "client_secret": {"type": "string", "example": "web_secret_12345"},
                                        "scope": {"type": "string", "example": "read write"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Token response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "access_token": {"type": "string"},
                                            "token_type": {"type": "string"},
                                            "expires_in": {"type": "integer"},
                                            "scope": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer"
                }
            }
        }
    }))
}

// Helper types (normally these would be in auth-core)
#[derive(Clone, Debug)]
pub struct TokenInfo {
    pub active: bool,
    pub client_id: String,
    pub scope: String,
    pub exp: u64,
}

#[derive(Debug)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}

// Mock implementations (in real auth-core, these would be actual methods)
impl AuthServer {
    fn validate_client(&self, client_id: &str, client_secret: &str) -> bool {
        match client_id {
            "web_client" => client_secret == "web_secret_12345",
            "mobile_client" => client_secret == "mobile_secret_67890", 
            "service_client" => client_secret == "service_secret_abcde",
            _ => false,
        }
    }
    
    fn generate_token(&self, client_id: &str, scope: &str) -> Result<TokenResponse, String> {
        let token = format!("auth_core_{}_{}_{}", 
            client_id, 
            chrono::Utc::now().timestamp(),
            uuid::Uuid::new_v4().to_string()[..8].to_string()
        );
        
        Ok(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            scope: scope.to_string(),
        })
    }
    
    fn introspect_token(&self, token: &str) -> Result<TokenInfo, String> {
        if token.starts_with("auth_core_") {
            Ok(TokenInfo {
                active: true,
                client_id: "web_client".to_string(),
                scope: "read write".to_string(),
                exp: chrono::Utc::now().timestamp() as u64 + 3600,
            })
        } else {
            Err("Invalid token".to_string())
        }
    }
}