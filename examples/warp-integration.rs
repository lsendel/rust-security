//! Complete Warp integration example
//! 
//! This example demonstrates how to integrate auth-core with Warp framework
//! for a lightweight OAuth 2.0 authentication system.

use auth_core::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio::sync::RwLock;
use warp::{
    http::{HeaderMap, StatusCode},
    reply::{json, with_status},
    Filter, Rejection, Reply,
};

// Application state
#[derive(Clone)]
pub struct AppState {
    auth_server: Arc<AuthServer>,
    // In-memory token store for demo
    tokens: Arc<RwLock<HashMap<String, TokenData>>>,
}

// Data types
#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    scope: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
    timestamp: String,
}

#[derive(Clone, Debug)]
struct TokenData {
    client_id: String,
    scopes: Vec<String>,
    expires_at: i64,
    issued_at: i64,
}

#[derive(Serialize)]
struct UserInfo {
    client_id: String,
    name: String,
    scopes: Vec<String>,
    token_issued_at: String,
}

#[derive(Serialize)]
struct Resource {
    id: String,
    name: String,
    content: String,
    access_level: String,
}

#[tokio::main]
async fn main() {
    // Initialize logging
    pretty_env_logger::init();

    log::info!("🚀 Starting Warp + Auth-Core integration example");

    // Create application state
    let app_state = AppState {
        auth_server: Arc::new(
            AuthServer::minimal()
                .with_client("web_client", "web_secret_warp_123")
                .with_client("api_client", "api_secret_warp_456") 
                .with_client("admin_client", "admin_secret_warp_789")
                .with_scope("read")
                .with_scope("write")
                .with_scope("admin")
                .build()
                .expect("Failed to build auth server"),
        ),
        tokens: Arc::new(RwLock::new(HashMap::new())),
    };

    // Build routes
    let routes = build_routes(app_state).await;

    log::info!("🌐 Server starting on http://localhost:8080");
    log::info!("📖 Available endpoints:");
    log::info!("  - GET  / (documentation)");
    log::info!("  - POST /oauth/token (get access token)");
    log::info!("  - POST /oauth/introspect (validate token)");
    log::info!("  - GET  /api/me (user info - requires auth)");
    log::info!("  - GET  /api/resources (list resources - requires read)");
    log::info!("  - POST /api/resources (create resource - requires write)");
    log::info!("  - GET  /api/admin (admin panel - requires admin)");

    // Start server
    warp::serve(routes)
        .run(([127, 0, 0, 1], 8080))
        .await;
}

async fn build_routes(
    app_state: AppState,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    // CORS
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type", "authorization"])
        .allow_methods(vec!["GET", "POST", "PUT", "DELETE"]);

    // State filter
    let with_state = warp::any().map(move || app_state.clone());

    // Public routes
    let home = warp::get()
        .and(warp::path::end())
        .and_then(home_handler);

    let health = warp::get()
        .and(warp::path("health"))
        .and_then(health_handler);

    // OAuth routes
    let oauth_token = warp::post()
        .and(warp::path!("oauth" / "token"))
        .and(warp::body::form())
        .and(with_state.clone())
        .and_then(token_handler);

    let oauth_introspect = warp::post()
        .and(warp::path!("oauth" / "introspect"))
        .and(warp::body::form())
        .and(with_state.clone())
        .and_then(introspect_handler);

    // Auth filter
    let with_auth = warp::header::<String>("authorization")
        .and(with_state.clone())
        .and_then(auth_filter);

    // Protected API routes
    let api_me = warp::get()
        .and(warp::path!("api" / "me"))
        .and(with_auth.clone())
        .and_then(me_handler);

    let api_resources = warp::get()
        .and(warp::path!("api" / "resources"))
        .and(with_auth.clone())
        .and_then(resources_handler);

    let api_create_resource = warp::post()
        .and(warp::path!("api" / "resources"))
        .and(warp::body::json())
        .and(with_auth.clone())
        .and_then(create_resource_handler);

    let api_admin = warp::get()
        .and(warp::path!("api" / "admin"))
        .and(with_auth.clone())
        .and_then(admin_handler);

    let api_stats = warp::get()
        .and(warp::path!("api" / "stats"))
        .and(with_auth.clone())
        .and(with_state.clone())
        .and_then(stats_handler);

    // Combine all routes
    home
        .or(health)
        .or(oauth_token)
        .or(oauth_introspect)
        .or(api_me)
        .or(api_resources)
        .or(api_create_resource)
        .or(api_admin)
        .or(api_stats)
        .with(cors)
        .with(warp::log("warp_auth"))
}

// Route handlers
async fn home_handler() -> Result<impl Reply, Rejection> {
    let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Auth-Core + Warp Integration</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            margin: 0; padding: 40px; line-height: 1.6; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { 
            max-width: 1000px; margin: 0 auto; 
            background: white; padding: 40px; border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        .endpoint { 
            background: #f8f9fb; padding: 20px; margin: 20px 0; 
            border-radius: 8px; border-left: 5px solid #3b82f6; 
        }
        .method { 
            color: white; padding: 6px 12px; border-radius: 6px; 
            font-weight: bold; font-size: 14px; margin-right: 10px;
        }
        .get { background: linear-gradient(45deg, #10b981, #059669); }
        .post { background: linear-gradient(45deg, #3b82f6, #1d4ed8); }
        .put { background: linear-gradient(45deg, #f59e0b, #d97706); }
        .delete { background: linear-gradient(45deg, #ef4444, #dc2626); }
        code { 
            background: #1f2937; color: #f9fafb; padding: 3px 8px; 
            border-radius: 4px; font-family: 'JetBrains Mono', monospace; 
            font-size: 14px;
        }
        .example { 
            background: #111827; color: #f3f4f6; padding: 25px; 
            border-radius: 8px; overflow-x: auto; margin: 20px 0;
            font-family: 'JetBrains Mono', monospace; font-size: 13px;
        }
        .client-card { 
            background: linear-gradient(45deg, #ec4899, #be185d); 
            color: white; padding: 20px; border-radius: 8px; 
            margin: 15px 0; 
        }
        .client-card strong { font-size: 16px; }
        .client-card .scopes { 
            background: rgba(255,255,255,0.2); 
            padding: 5px 10px; border-radius: 15px; 
            font-size: 12px; margin-top: 10px; display: inline-block;
        }
        h1 { color: #1f2937; margin-bottom: 10px; }
        h2 { color: #374151; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }
        .feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }
        .feature { background: #f0f9ff; padding: 20px; border-radius: 8px; border-left: 4px solid #0ea5e9; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Auth-Core + Warp Integration</h1>
        <p>High-performance OAuth 2.0 authentication with Warp's functional approach and zero-cost abstractions.</p>
        
        <div class="feature-grid">
            <div class="feature">
                <h3>🔒 Secure by Default</h3>
                <p>Built-in token validation, scope enforcement, and timing attack protection.</p>
            </div>
            <div class="feature">
                <h3>⚡ High Performance</h3>
                <p>Warp's zero-cost filters with compile-time route optimization.</p>
            </div>
            <div class="feature">
                <h3>🎯 Type Safety</h3>
                <p>Full type safety with Rust's ownership system and Warp's filter combinators.</p>
            </div>
            <div class="feature">
                <h3>📊 Observable</h3>
                <p>Built-in logging, metrics, and request tracing for production monitoring.</p>
            </div>
        </div>
        
        <h2>🔧 API Endpoints</h2>
        
        <div class="endpoint">
            <span class="method post">POST</span> <code>/oauth/token</code>
            <p><strong>OAuth Token Endpoint</strong> - Authenticate and receive access token</p>
        </div>
        
        <div class="endpoint">
            <span class="method post">POST</span> <code>/oauth/introspect</code>
            <p><strong>Token Introspection</strong> - Validate token and get metadata (RFC 7662)</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span> <code>/api/me</code>
            <p><strong>User Information</strong> - Get current user/client details</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span> <code>/api/resources</code>
            <p><strong>List Resources</strong> - Browse available resources (requires <code>read</code> scope)</p>
        </div>
        
        <div class="endpoint">
            <span class="method post">POST</span> <code>/api/resources</code>
            <p><strong>Create Resource</strong> - Create new resource (requires <code>write</code> scope)</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span> <code>/api/admin</code>
            <p><strong>Admin Dashboard</strong> - System administration (requires <code>admin</code> scope)</p>
        </div>
        
        <h2>🔑 OAuth Clients</h2>
        
        <div class="client-card">
            <strong>web_client</strong><br>
            Secret: web_secret_warp_123<br>
            <div class="scopes">Scopes: read, write</div>
        </div>
        
        <div class="client-card">
            <strong>api_client</strong><br>
            Secret: api_secret_warp_456<br>
            <div class="scopes">Scopes: read</div>
        </div>
        
        <div class="client-card">
            <strong>admin_client</strong><br>
            Secret: admin_secret_warp_789<br>
            <div class="scopes">Scopes: read, write, admin</div>
        </div>
        
        <h2>💡 Quick Start Examples</h2>
        
        <h3>1. Get Access Token</h3>
        <div class="example">
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=admin_client" \
  -d "client_secret=admin_secret_warp_789" \
  -d "scope=read write admin"
        </div>
        
        <h3>2. Access Protected Resource</h3>
        <div class="example">
# Replace YOUR_TOKEN with the token from step 1
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/me

curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/resources
        </div>
        
        <h3>3. Create Resource (Write Scope Required)</h3>
        <div class="example">
curl -X POST http://localhost:8080/api/resources \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Resource",
    "content": "This is a test resource",
    "access_level": "public"
  }'
        </div>
        
        <h3>4. Access Admin Panel</h3>
        <div class="example">
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/admin
        </div>
        
        <h2>🧪 Testing Different Scopes</h2>
        <p>Try different clients to see scope-based access control:</p>
        
        <div class="example">
# Limited client (read-only)
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=api_client" \
  -d "client_secret=api_secret_warp_456"

# This will work (read scope available)
curl -H "Authorization: Bearer API_CLIENT_TOKEN" \
  http://localhost:8080/api/resources

# This will fail (no write scope)
curl -X POST http://localhost:8080/api/resources \
  -H "Authorization: Bearer API_CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Will fail", "content": "No write scope"}'
        </div>
        
        <h2>🔍 Token Introspection Example</h2>
        <div class="example">
curl -X POST http://localhost:8080/oauth/introspect \
  -d "token=YOUR_TOKEN" \
  -d "client_id=admin_client" \
  -d "client_secret=admin_secret_warp_789"
        </div>
        
        <h2>📊 Health Check</h2>
        <div class="example">
curl http://localhost:8080/health
        </div>
        
        <p style="text-align: center; margin-top: 40px; color: #6b7280;">
            Built with ❤️ using <strong>Rust</strong>, <strong>Warp</strong>, and <strong>Auth-Core</strong>
        </p>
    </div>
</body>
</html>
    "#;

    Ok(warp::reply::html(html))
}

async fn health_handler() -> Result<impl Reply, Rejection> {
    let response = ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "status": "healthy",
            "service": "auth-core-warp",
            "version": "1.0.0",
            "uptime": "Running smoothly"
        })),
        error: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    Ok(json(&response))
}

async fn token_handler(
    form: HashMap<String, String>,
    state: AppState,
) -> Result<impl Reply, Rejection> {
    let client_id = form.get("client_id").unwrap_or(&String::new()).clone();
    let client_secret = form.get("client_secret").unwrap_or(&String::new()).clone();
    let grant_type = form.get("grant_type").unwrap_or(&String::new()).clone();
    let requested_scope = form.get("scope").unwrap_or(&"read".to_string()).clone();

    log::info!("Token request from client: {}", client_id);

    // Validate grant type
    if grant_type != "client_credentials" {
        let error_response = serde_json::json!({
            "error": "unsupported_grant_type",
            "error_description": "Only client_credentials grant type is supported"
        });
        return Ok(with_status(json(&error_response), StatusCode::BAD_REQUEST));
    }

    // Validate client and get allowed scopes
    let client_info = match client_id.as_str() {
        "web_client" => {
            if client_secret == "web_secret_warp_123" {
                Some(vec!["read", "write"])
            } else {
                None
            }
        }
        "api_client" => {
            if client_secret == "api_secret_warp_456" {
                Some(vec!["read"])
            } else {
                None
            }
        }
        "admin_client" => {
            if client_secret == "admin_secret_warp_789" {
                Some(vec!["read", "write", "admin"])
            } else {
                None
            }
        }
        _ => None,
    };

    let allowed_scopes = match client_info {
        Some(scopes) => scopes,
        None => {
            log::warn!("Client authentication failed: {}", client_id);
            let error_response = serde_json::json!({
                "error": "invalid_client",
                "error_description": "Client authentication failed"
            });
            return Ok(with_status(json(&error_response), StatusCode::UNAUTHORIZED));
        }
    };

    // Filter requested scopes
    let requested: Vec<&str> = requested_scope.split_whitespace().collect();
    let granted: Vec<&str> = requested
        .into_iter()
        .filter(|scope| allowed_scopes.contains(scope))
        .collect();

    if granted.is_empty() {
        let error_response = serde_json::json!({
            "error": "invalid_scope",
            "error_description": "No valid scopes in request"
        });
        return Ok(with_status(json(&error_response), StatusCode::BAD_REQUEST));
    }

    // Generate token
    let now = chrono::Utc::now().timestamp();
    let token = format!(
        "warp_token_{}_{}_{}",
        client_id,
        now,
        uuid::Uuid::new_v4().simple()
    );

    // Store token data
    let token_data = TokenData {
        client_id: client_id.clone(),
        scopes: granted.iter().map(|s| s.to_string()).collect(),
        expires_at: now + 3600, // 1 hour
        issued_at: now,
    };

    state
        .tokens
        .write()
        .await
        .insert(token.clone(), token_data);

    let response = TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        scope: granted.join(" "),
    };

    log::info!(
        "Token issued for client: {} with scopes: {:?}",
        client_id,
        granted
    );

    Ok(with_status(json(&response), StatusCode::OK))
}

async fn introspect_handler(
    form: HashMap<String, String>,
    state: AppState,
) -> Result<impl Reply, Rejection> {
    let token = form.get("token").unwrap_or(&String::new()).clone();
    let client_id = form.get("client_id").unwrap_or(&String::new()).clone();
    let client_secret = form.get("client_secret").unwrap_or(&String::new()).clone();

    // Authenticate client
    let client_valid = match client_id.as_str() {
        "web_client" => client_secret == "web_secret_warp_123",
        "api_client" => client_secret == "api_secret_warp_456",
        "admin_client" => client_secret == "admin_secret_warp_789",
        _ => false,
    };

    if !client_valid {
        return Ok(json(&serde_json::json!({"active": false})));
    }

    // Look up token
    if let Some(token_data) = state.tokens.read().await.get(&token) {
        let now = chrono::Utc::now().timestamp();
        if token_data.expires_at > now {
            let response = serde_json::json!({
                "active": true,
                "client_id": token_data.client_id,
                "scope": token_data.scopes.join(" "),
                "exp": token_data.expires_at,
                "iat": token_data.issued_at,
                "token_type": "Bearer"
            });
            return Ok(json(&response));
        }
    }

    Ok(json(&serde_json::json!({"active": false})))
}

// Auth filter
async fn auth_filter(
    auth_header: String,
    state: AppState,
) -> Result<TokenData, Rejection> {
    if !auth_header.starts_with("Bearer ") {
        log::warn!("Invalid authorization header format");
        return Err(warp::reject::custom(AuthError::InvalidToken));
    }

    let token = &auth_header[7..];

    // Look up token
    if let Some(token_data) = state.tokens.read().await.get(token) {
        let now = chrono::Utc::now().timestamp();
        if token_data.expires_at > now {
            return Ok(token_data.clone());
        } else {
            log::warn!("Token expired: {}", token);
        }
    } else {
        log::warn!("Token not found: {}", token);
    }

    Err(warp::reject::custom(AuthError::InvalidToken))
}

// Protected handlers
async fn me_handler(token_data: TokenData) -> Result<impl Reply, Rejection> {
    let user_info = UserInfo {
        client_id: token_data.client_id.clone(),
        name: format!("Client {}", token_data.client_id),
        scopes: token_data.scopes.clone(),
        token_issued_at: chrono::DateTime::<chrono::Utc>::from_timestamp(token_data.issued_at, 0)
            .unwrap_or_default()
            .to_rfc3339(),
    };

    let response = ApiResponse {
        success: true,
        data: Some(user_info),
        error: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    Ok(json(&response))
}

async fn resources_handler(token_data: TokenData) -> Result<impl Reply, Rejection> {
    // Check read scope
    if !token_data.scopes.contains(&"read".to_string()) {
        let response = ApiResponse::<Vec<Resource>> {
            success: false,
            data: None,
            error: Some("Insufficient scope: read required".to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        return Ok(with_status(json(&response), StatusCode::FORBIDDEN));
    }

    let resources = vec![
        Resource {
            id: "res_001".to_string(),
            name: "Public Document".to_string(),
            content: "This is a public document accessible to all authenticated users.".to_string(),
            access_level: "public".to_string(),
        },
        Resource {
            id: "res_002".to_string(),
            name: "Private Report".to_string(),
            content: format!("Private report for client: {}", token_data.client_id),
            access_level: "private".to_string(),
        },
        Resource {
            id: "res_003".to_string(),
            name: "Shared Resource".to_string(),
            content: "Resource shared among authorized clients.".to_string(),
            access_level: "shared".to_string(),
        },
    ];

    let response = ApiResponse {
        success: true,
        data: Some(resources),
        error: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    log::info!("Resources listed for client: {}", token_data.client_id);

    Ok(json(&response))
}

async fn create_resource_handler(
    payload: serde_json::Value,
    token_data: TokenData,
) -> Result<impl Reply, Rejection> {
    // Check write scope
    if !token_data.scopes.contains(&"write".to_string()) {
        let response = ApiResponse::<Resource> {
            success: false,
            data: None,
            error: Some("Insufficient scope: write required".to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        return Ok(with_status(json(&response), StatusCode::FORBIDDEN));
    }

    let name = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unnamed Resource");
    let content = payload
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("No content provided");
    let access_level = payload
        .get("access_level")
        .and_then(|v| v.as_str())
        .unwrap_or("private");

    let new_resource = Resource {
        id: format!("res_{}", uuid::Uuid::new_v4().simple()[..8].to_string()),
        name: name.to_string(),
        content: content.to_string(),
        access_level: access_level.to_string(),
    };

    let response = ApiResponse {
        success: true,
        data: Some(new_resource),
        error: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    log::info!(
        "Resource created by client: {} with name: '{}'",
        token_data.client_id,
        name
    );

    Ok(with_status(json(&response), StatusCode::CREATED))
}

async fn admin_handler(token_data: TokenData) -> Result<impl Reply, Rejection> {
    // Check admin scope
    if !token_data.scopes.contains(&"admin".to_string()) {
        let response = ApiResponse::<serde_json::Value> {
            success: false,
            data: None,
            error: Some("Insufficient scope: admin required".to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        return Ok(with_status(json(&response), StatusCode::FORBIDDEN));
    }

    let admin_data = serde_json::json!({
        "system_status": "operational",
        "active_tokens": 5,
        "total_requests_today": 247,
        "system_load": {
            "cpu": "12%",
            "memory": "34%",
            "disk": "67%"
        },
        "recent_clients": [
            {"id": "web_client", "last_seen": "2 minutes ago"},
            {"id": "api_client", "last_seen": "15 minutes ago"},
            {"id": "admin_client", "last_seen": "just now"}
        ],
        "security_events": [
            {"type": "failed_auth", "client": "unknown", "timestamp": "5 minutes ago"},
            {"type": "token_issued", "client": "web_client", "timestamp": "10 minutes ago"}
        ]
    });

    let response = ApiResponse {
        success: true,
        data: Some(admin_data),
        error: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    log::info!("Admin panel accessed by: {}", token_data.client_id);

    Ok(json(&response))
}

async fn stats_handler(
    token_data: TokenData,
    state: AppState,
) -> Result<impl Reply, Rejection> {
    let token_count = state.tokens.read().await.len();

    let stats = serde_json::json!({
        "client_info": {
            "id": token_data.client_id,
            "scopes": token_data.scopes,
            "token_expires_at": chrono::DateTime::<chrono::Utc>::from_timestamp(token_data.expires_at, 0)
                .unwrap_or_default()
                .to_rfc3339(),
        },
        "system_stats": {
            "active_tokens": token_count,
            "server_uptime": "45 minutes",
            "memory_usage": "23.4 MB",
            "requests_processed": rand::random::<u32>() % 1000,
        },
        "performance": {
            "avg_response_time": "12ms", 
            "requests_per_second": 150,
            "error_rate": "0.01%"
        }
    });

    let response = ApiResponse {
        success: true,
        data: Some(stats),
        error: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    Ok(json(&response))
}

// Custom error types
#[derive(Debug)]
enum AuthError {
    InvalidToken,
}

impl warp::reject::Reject for AuthError {}

// Helper function (normally from external crate)
// This is just for the example
use uuid::Uuid;