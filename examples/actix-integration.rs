//! Complete Actix-Web integration example
//! 
//! This example demonstrates how to integrate auth-core with Actix-Web framework
//! for a complete OAuth 2.0 authentication system.

use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    error::{ErrorInternalServerError, ErrorUnauthorized},
    middleware::{Logger, DefaultHeaders},
    web::{self, Data, Form, Json, Query},
    App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Result,
};
use auth_core::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

// Application state
#[derive(Clone)]
pub struct AppState {
    auth_server: Arc<AuthServer>,
}

// Request/Response types
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
}

#[derive(Serialize)]
struct UserProfile {
    id: String,
    name: String,
    email: String,
    scopes: Vec<String>,
}

#[derive(Serialize)]
struct DataItem {
    id: u32,
    title: String,
    description: String,
    created_by: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init();

    log::info!("🚀 Starting Actix-Web + Auth-Core integration example");

    // Build auth server
    let auth_server = AuthServer::minimal()
        .with_client("web_app", "web_secret_secure_123")
        .with_client("mobile_app", "mobile_secret_secure_456")
        .with_client("api_service", "api_secret_secure_789")
        .with_scope("read")
        .with_scope("write")
        .with_scope("delete")
        .with_scope("admin")
        .with_token_ttl(7200) // 2 hours
        .build()
        .expect("Failed to build auth server");

    let app_state = AppState {
        auth_server: Arc::new(auth_server),
    };

    log::info!("🌐 Server starting on http://localhost:8080");
    log::info!("📖 Available endpoints:");
    log::info!("  - GET  / (home page)");
    log::info!("  - POST /oauth/token (get access token)");
    log::info!("  - POST /oauth/introspect (validate token)");
    log::info!("  - GET  /api/profile (protected: get user profile)");
    log::info!("  - GET  /api/items (protected: list items)");
    log::info!("  - POST /api/items (protected: create item)");
    log::info!("  - DELETE /api/items/{{id}} (protected: delete item)");
    log::info!("  - GET  /api/admin (protected: admin only)");

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(app_state.clone()))
            .wrap(Logger::default())
            .wrap(DefaultHeaders::new().add(("X-Version", "1.0")))
            
            // Public routes
            .route("/", web::get().to(home_page))
            .route("/health", web::get().to(health_check))
            
            // OAuth routes
            .service(
                web::scope("/oauth")
                    .route("/token", web::post().to(handle_token))
                    .route("/introspect", web::post().to(handle_introspect))
            )
            
            // Protected API routes
            .service(
                web::scope("/api")
                    .wrap_fn(auth_middleware)
                    .route("/profile", web::get().to(get_profile))
                    .route("/items", web::get().to(list_items))
                    .route("/items", web::post().to(create_item))
                    .route("/items/{id}", web::delete().to(delete_item))
                    .route("/admin", web::get().to(admin_endpoint))
                    .route("/stats", web::get().to(get_stats))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

// OAuth Token Endpoint
async fn handle_token(
    app_state: Data<AppState>,
    form: Form<TokenRequest>,
) -> Result<Json<serde_json::Value>> {
    let req = form.into_inner();
    
    log::info!("Token request from client: {}", req.client_id);

    // Validate grant type
    if req.grant_type != "client_credentials" {
        log::warn!("Invalid grant type: {}", req.grant_type);
        return Ok(Json(serde_json::json!({
            "error": "unsupported_grant_type",
            "error_description": "Only client_credentials grant type is supported"
        })));
    }

    // Authenticate client
    let (valid, allowed_scopes) = match req.client_id.as_str() {
        "web_app" => (
            req.client_secret == "web_secret_secure_123",
            vec!["read", "write"]
        ),
        "mobile_app" => (
            req.client_secret == "mobile_secret_secure_456", 
            vec!["read"]
        ),
        "api_service" => (
            req.client_secret == "api_secret_secure_789",
            vec!["read", "write", "delete", "admin"]
        ),
        _ => (false, vec![])
    };

    if !valid {
        log::warn!("Client authentication failed: {}", req.client_id);
        return Ok(Json(serde_json::json!({
            "error": "invalid_client",
            "error_description": "Client authentication failed"
        })));
    }

    // Validate requested scopes
    let requested_scopes: Vec<&str> = req.scope
        .as_deref()
        .unwrap_or("read")
        .split_whitespace()
        .collect();
    
    let granted_scopes: Vec<&str> = requested_scopes
        .into_iter()
        .filter(|scope| allowed_scopes.contains(scope))
        .collect();

    if granted_scopes.is_empty() {
        return Ok(Json(serde_json::json!({
            "error": "invalid_scope",
            "error_description": "No valid scopes requested"
        })));
    }

    // Generate token
    let token = generate_secure_token(&req.client_id);
    let expires_in = 7200; // 2 hours
    
    log::info!("Token issued for client: {} with scopes: {:?}", req.client_id, granted_scopes);

    Ok(Json(serde_json::json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": granted_scopes.join(" ")
    })))
}

// OAuth Token Introspection Endpoint  
async fn handle_introspect(
    _app_state: Data<AppState>,
    form: Form<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let params = form.into_inner();
    let token = params.get("token").unwrap_or(&String::new());
    let client_id = params.get("client_id").unwrap_or(&String::new());
    let client_secret = params.get("client_secret").unwrap_or(&String::new());

    log::debug!("Token introspection request from client: {}", client_id);

    // Authenticate client (simplified for example)
    let client_valid = match client_id.as_str() {
        "web_app" => client_secret == "web_secret_secure_123",
        "mobile_app" => client_secret == "mobile_secret_secure_456",
        "api_service" => client_secret == "api_secret_secure_789",
        _ => false,
    };

    if !client_valid {
        return Ok(Json(serde_json::json!({"active": false})));
    }

    // Validate token format and extract info
    if token.starts_with("auth_token_") {
        let parts: Vec<&str> = token.split('_').collect();
        if parts.len() >= 3 {
            let token_client_id = parts[2];
            
            Ok(Json(serde_json::json!({
                "active": true,
                "client_id": token_client_id,
                "scope": "read write",
                "token_type": "Bearer",
                "exp": chrono::Utc::now().timestamp() + 7200
            })))
        } else {
            Ok(Json(serde_json::json!({"active": false})))
        }
    } else {
        Ok(Json(serde_json::json!({"active": false})))
    }
}

// Authentication middleware
async fn auth_middleware(
    req: ServiceRequest,
    next: actix_web::dev::Transform<
        actix_web::dev::ServiceRequest,
        actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
        actix_web::Error,
    >,
) -> Result<ServiceResponse<actix_web::body::BoxBody>, actix_web::Error> {
    // Extract authorization header
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|header| header.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => {
            log::warn!("Missing or invalid authorization header");
            return Err(ErrorUnauthorized("Missing or invalid authorization header"));
        }
    };

    // Validate token format and extract client info
    if !token.starts_with("auth_token_") {
        log::warn!("Invalid token format: {}", token);
        return Err(ErrorUnauthorized("Invalid token"));
    }

    let parts: Vec<&str> = token.split('_').collect();
    if parts.len() < 3 {
        return Err(ErrorUnauthorized("Malformed token"));
    }

    let client_id = parts[2];
    
    // Get client scopes
    let scopes = match client_id {
        "web_app" => vec!["read", "write"],
        "mobile_app" => vec!["read"],
        "api_service" => vec!["read", "write", "delete", "admin"],
        _ => {
            log::warn!("Unknown client in token: {}", client_id);
            return Err(ErrorUnauthorized("Invalid client"));
        }
    };

    // Add token info to request extensions
    req.extensions_mut().insert(TokenInfo {
        client_id: client_id.to_string(),
        scopes: scopes.into_iter().map(String::from).collect(),
        expires_at: chrono::Utc::now().timestamp() + 7200,
    });

    let res = next.call(req).await?;
    Ok(res)
}

// Protected endpoint handlers
async fn get_profile(req: HttpRequest) -> Result<Json<ApiResponse<UserProfile>>> {
    let token_info = req
        .extensions()
        .get::<TokenInfo>()
        .ok_or_else(|| ErrorInternalServerError("Token info not found"))?;

    let profile = UserProfile {
        id: token_info.client_id.clone(),
        name: format!("User for {}", token_info.client_id),
        email: format!("{}@example.com", token_info.client_id),
        scopes: token_info.scopes.clone(),
    };

    log::info!("Profile requested by client: {}", token_info.client_id);

    Ok(Json(ApiResponse {
        success: true,
        data: Some(profile),
        error: None,
    }))
}

async fn list_items(
    req: HttpRequest,
    query: Query<HashMap<String, String>>,
) -> Result<Json<ApiResponse<Vec<DataItem>>>> {
    let token_info = req
        .extensions()
        .get::<TokenInfo>()
        .ok_or_else(|| ErrorInternalServerError("Token info not found"))?;

    // Check read permission
    if !token_info.scopes.contains(&"read".to_string()) {
        return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Insufficient scope: read required".to_string()),
        }));
    }

    let limit: usize = query
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
        .min(100); // Cap at 100

    let items: Vec<DataItem> = (1..=limit)
        .map(|i| DataItem {
            id: i as u32,
            title: format!("Item {}", i),
            description: format!("This is item number {} created by {}", i, token_info.client_id),
            created_by: token_info.client_id.clone(),
        })
        .collect();

    log::info!("Listed {} items for client: {}", items.len(), token_info.client_id);

    Ok(Json(ApiResponse {
        success: true,
        data: Some(items),
        error: None,
    }))
}

async fn create_item(
    req: HttpRequest,
    json: Json<serde_json::Value>,
) -> Result<Json<ApiResponse<DataItem>>> {
    let token_info = req
        .extensions()
        .get::<TokenInfo>()
        .ok_or_else(|| ErrorInternalServerError("Token info not found"))?;

    // Check write permission
    if !token_info.scopes.contains(&"write".to_string()) {
        return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Insufficient scope: write required".to_string()),
        }));
    }

    let payload = json.into_inner();
    let title = payload
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("New Item");
    let description = payload
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("No description provided");

    let new_item = DataItem {
        id: rand::random::<u32>(),
        title: title.to_string(),
        description: description.to_string(),
        created_by: token_info.client_id.clone(),
    };

    log::info!("Item created by client: {} with title: '{}'", 
        token_info.client_id, new_item.title);

    Ok(Json(ApiResponse {
        success: true,
        data: Some(new_item),
        error: None,
    }))
}

async fn delete_item(
    req: HttpRequest,
    path: web::Path<u32>,
) -> Result<Json<ApiResponse<String>>> {
    let token_info = req
        .extensions()
        .get::<TokenInfo>()
        .ok_or_else(|| ErrorInternalServerError("Token info not found"))?;

    let item_id = path.into_inner();

    // Check delete permission
    if !token_info.scopes.contains(&"delete".to_string()) {
        return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Insufficient scope: delete required".to_string()),
        }));
    }

    log::info!("Item {} deleted by client: {}", item_id, token_info.client_id);

    Ok(Json(ApiResponse {
        success: true,
        data: Some(format!("Item {} deleted successfully", item_id)),
        error: None,
    }))
}

async fn admin_endpoint(req: HttpRequest) -> Result<Json<ApiResponse<serde_json::Value>>> {
    let token_info = req
        .extensions()
        .get::<TokenInfo>()
        .ok_or_else(|| ErrorInternalServerError("Token info not found"))?;

    // Check admin permission
    if !token_info.scopes.contains(&"admin".to_string()) {
        return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Insufficient scope: admin required".to_string()),
        }));
    }

    let admin_data = serde_json::json!({
        "system_info": {
            "version": "1.0.0",
            "uptime": "2 hours",
            "active_tokens": 42,
            "total_requests": 1337
        },
        "recent_activity": [
            {"client": "web_app", "action": "token_issued", "timestamp": chrono::Utc::now().to_rfc3339()},
            {"client": "mobile_app", "action": "profile_accessed", "timestamp": chrono::Utc::now().to_rfc3339()}
        ]
    });

    log::info!("Admin endpoint accessed by: {}", token_info.client_id);

    Ok(Json(ApiResponse {
        success: true,
        data: Some(admin_data),
        error: None,
    }))
}

async fn get_stats(req: HttpRequest) -> Result<Json<ApiResponse<serde_json::Value>>> {
    let token_info = req
        .extensions()
        .get::<TokenInfo>()
        .ok_or_else(|| ErrorInternalServerError("Token info not found"))?;

    let stats = serde_json::json!({
        "client_id": token_info.client_id,
        "scopes": token_info.scopes,
        "token_expires_at": token_info.expires_at,
        "server_time": chrono::Utc::now().to_rfc3339(),
        "request_count": rand::random::<u32>() % 1000,
    });

    Ok(Json(ApiResponse {
        success: true,
        data: Some(stats),
        error: None,
    }))
}

// Public endpoints
async fn home_page() -> Result<HttpResponse> {
    let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Auth-Core + Actix-Web Integration</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; line-height: 1.6; }
        .container { max-width: 900px; margin: 0 auto; }
        .endpoint { background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #007bff; }
        .method { color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .get { background: #28a745; }
        .post { background: #007bff; }
        .delete { background: #dc3545; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-family: 'Monaco', monospace; }
        .example { background: #2d3748; color: #e2e8f0; padding: 20px; border-radius: 8px; overflow-x: auto; }
        .client-info { background: #fff3cd; padding: 10px; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Auth-Core + Actix-Web Integration</h1>
        <p>This example demonstrates OAuth 2.0 authentication with Actix-Web framework and progressive scopes.</p>
        
        <h2>🔧 Available Endpoints</h2>
        
        <div class="endpoint">
            <span class="method post">POST</span> <code>/oauth/token</code>
            <p><strong>Get access token</strong> using client credentials flow</p>
        </div>
        
        <div class="endpoint">
            <span class="method post">POST</span> <code>/oauth/introspect</code>
            <p><strong>Validate token</strong> and get token metadata</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span> <code>/api/profile</code>
            <p><strong>User profile</strong> (requires any valid scope)</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span> <code>/api/items</code>
            <p><strong>List items</strong> (requires <code>read</code> scope)</p>
        </div>
        
        <div class="endpoint">
            <span class="method post">POST</span> <code>/api/items</code>
            <p><strong>Create item</strong> (requires <code>write</code> scope)</p>
        </div>
        
        <div class="endpoint">
            <span class="method delete">DELETE</span> <code>/api/items/{id}</code>
            <p><strong>Delete item</strong> (requires <code>delete</code> scope)</p>
        </div>
        
        <div class="endpoint">
            <span class="method get">GET</span> <code>/api/admin</code>
            <p><strong>Admin panel</strong> (requires <code>admin</code> scope)</p>
        </div>
        
        <h2>🔑 Test Clients</h2>
        <div class="client-info">
            <strong>web_app</strong> / web_secret_secure_123<br>
            Scopes: <code>read</code>, <code>write</code>
        </div>
        <div class="client-info">
            <strong>mobile_app</strong> / mobile_secret_secure_456<br>
            Scopes: <code>read</code>
        </div>
        <div class="client-info">
            <strong>api_service</strong> / api_secret_secure_789<br>
            Scopes: <code>read</code>, <code>write</code>, <code>delete</code>, <code>admin</code>
        </div>
        
        <h2>💡 Example Usage</h2>
        <div class="example">
<pre># 1. Get access token with full permissions
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=api_service" \
  -d "client_secret=api_secret_secure_789" \
  -d "scope=read write delete admin"

# 2. Use token to access profile
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/profile

# 3. Create a new item
curl -X POST http://localhost:8080/api/items \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "My Item", "description": "A test item"}'

# 4. Access admin endpoint
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/admin</pre>
        </div>
        
        <h2>🧪 Test Different Scopes</h2>
        <p>Try using different clients to see how scope restrictions work:</p>
        <div class="example">
<pre># Limited mobile client (only read scope)
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=mobile_app" \
  -d "client_secret=mobile_secret_secure_456"

# This will work (read scope)
curl -H "Authorization: Bearer MOBILE_TOKEN" \
  http://localhost:8080/api/items

# This will fail (no write scope)  
curl -X POST http://localhost:8080/api/items \
  -H "Authorization: Bearer MOBILE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Will fail"}'</pre>
        </div>
    </div>
</body>
</html>
    "#;

    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

async fn health_check() -> Result<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "service": "auth-core-actix",
        "version": "1.0.0",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "uptime": "Running"
    })))
}

// Helper types and functions
#[derive(Clone, Debug)]
struct TokenInfo {
    client_id: String,
    scopes: Vec<String>,
    expires_at: i64,
}

fn generate_secure_token(client_id: &str) -> String {
    format!(
        "auth_token_{}_{}_{}",
        client_id,
        chrono::Utc::now().timestamp(),
        uuid::Uuid::new_v4().simple()
    )
}