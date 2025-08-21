# 📚 API Reference

Complete reference for the Rust Security OAuth 2.0 platform, covering both the minimal auth-core and full auth-service implementations.

## Table of Contents

1. [Overview](#overview)
2. [Auth-Core API](#auth-core-api)
3. [OAuth 2.0 Endpoints](#oauth-20-endpoints)
4. [Authentication](#authentication)
5. [Error Responses](#error-responses)
6. [Client SDKs](#client-sdks)
7. [Configuration](#configuration)
8. [Examples](#examples)

## Overview

The Rust Security platform provides OAuth 2.0-compliant authentication services through two main components:

- **auth-core**: Minimal OAuth 2.0 server for basic use cases
- **auth-service**: Full-featured enterprise authentication service

### Base URLs

| Environment | Base URL | Purpose |
|-------------|----------|---------|
| Development | `http://localhost:8080` | Local development |
| Staging | `https://auth-staging.example.com` | Integration testing |
| Production | `https://auth.example.com` | Live service |

### Authentication

All API endpoints require proper authentication:
- **Public endpoints**: No authentication required
- **OAuth endpoints**: Client credentials required
- **Admin endpoints**: Bearer token required

## Auth-Core API

### Server Configuration

#### Building a Server

```rust
use auth_core::prelude::*;

let server = AuthServer::minimal()
    .with_client("client_id", "client_secret")
    .with_scope("read")
    .with_scope("write")
    .with_token_ttl(3600) // 1 hour
    .build()
    .expect("Failed to build server");
```

#### Configuration Options

| Method | Description | Default |
|--------|-------------|---------|
| `minimal()` | Create minimal server builder | - |
| `with_client(id, secret)` | Add OAuth client | None |
| `with_scope(scope)` | Add valid scope | `[]` |
| `with_token_ttl(seconds)` | Set token expiration | 3600s |
| `with_rate_limit(requests, window)` | Rate limiting | None |
| `build()` | Finalize configuration | - |

#### Client Configuration

```rust
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub client_secret: String,
    pub allowed_scopes: Vec<String>,
    pub redirect_uris: Vec<String>, // For authorization code flow
    pub grant_types: Vec<GrantType>,
}
```

## OAuth 2.0 Endpoints

### Token Endpoint

**`POST /oauth/token`**

Request access tokens using various OAuth 2.0 flows.

#### Client Credentials Flow

**Request**
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=your_client_id&client_secret=your_client_secret&scope=read%20write
```

**Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grant_type` | string | Yes | Must be `client_credentials` |
| `client_id` | string | Yes | Your application's client identifier |
| `client_secret` | string | Yes | Your application's client secret |
| `scope` | string | No | Space-separated list of requested scopes |

**Response** (200 OK)
```json
{
  "access_token": "auth_core_ABC123...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

**Error Response** (400 Bad Request)
```json
{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid"
}
```

#### cURL Example

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=your_client_id" \
  -d "client_secret=your_client_secret" \
  -d "scope=read write"
```

### Token Introspection

**`POST /oauth/introspect`**

Determine the active state and metadata of a token (RFC 7662).

**Request**
```http
POST /oauth/introspect HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=auth_core_ABC123...&client_id=your_client_id&client_secret=your_client_secret
```

**Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | The token to introspect |
| `client_id` | string | Yes | Client identifier |
| `client_secret` | string | Yes | Client secret |

**Response** (200 OK)
```json
{
  "active": true,
  "client_id": "your_client_id",
  "scope": "read write",
  "exp": 1640995200,
  "token_type": "Bearer"
}
```

**Inactive Token Response**
```json
{
  "active": false
}
```

#### cURL Example

```bash
curl -X POST http://localhost:8080/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=auth_core_ABC123..." \
  -d "client_id=your_client_id" \
  -d "client_secret=your_client_secret"
```

### Health Check

**`GET /health`**

Check server health status.

**Response** (200 OK)
```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime": 3600
}
```

## Authentication

### Bearer Token Authentication

For protected resources, include the access token in the Authorization header:

```http
Authorization: Bearer auth_core_ABC123...
```

### Client Authentication

OAuth endpoints support multiple client authentication methods:

1. **Form-based** (recommended for server-to-server):
   ```
   client_id=your_id&client_secret=your_secret
   ```

2. **Basic Authentication** (alternative):
   ```http
   Authorization: Basic base64(client_id:client_secret)
   ```

## Error Responses

### Standard OAuth 2.0 Errors

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `invalid_request` | 400 | Request is missing a required parameter |
| `invalid_client` | 401 | Client authentication failed |
| `invalid_grant` | 400 | The provided grant is invalid |
| `unauthorized_client` | 401 | Client is not authorized for this grant type |
| `unsupported_grant_type` | 400 | Grant type is not supported |
| `invalid_scope` | 400 | Requested scope is invalid or unknown |

### Extended Error Codes

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `rate_limit_exceeded` | 429 | Too many requests from client |
| `server_error` | 500 | Internal server error |
| `temporarily_unavailable` | 503 | Service temporarily unavailable |

### Error Response Format

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed",
  "error_uri": "https://docs.rust-security.dev/errors/invalid_client"
}
```

## Client SDKs

### Rust Client

```rust
use auth_client::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AuthClient::new("http://localhost:8080")
        .with_credentials("client_id", "client_secret");
    
    let token = client.client_credentials()
        .scope("read write")
        .execute()
        .await?;
    
    println!("Access token: {}", token.access_token);
    Ok(())
}
```

### JavaScript/Node.js

```javascript
import { AuthClient } from '@rust-security/auth-client';

const client = new AuthClient({
  baseUrl: 'http://localhost:8080',
  clientId: 'your_client_id',
  clientSecret: 'your_client_secret'
});

const token = await client.getToken({
  scope: 'read write'
});

console.log('Access token:', token.accessToken);
```

### Python

```python
from rust_security import AuthClient

client = AuthClient(
    base_url='http://localhost:8080',
    client_id='your_client_id',
    client_secret='your_client_secret'
)

token = client.client_credentials(scope='read write')
print(f"Access token: {token.access_token}")
```

### cURL

```bash
#!/bin/bash
# Simple bash client

BASE_URL="http://localhost:8080"
CLIENT_ID="your_client_id"
CLIENT_SECRET="your_client_secret"

# Get token
response=$(curl -s -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "scope=read write")

# Extract token
token=$(echo "$response" | jq -r '.access_token')
echo "Access token: $token"

# Use token
curl -H "Authorization: Bearer $token" \
  "$BASE_URL/api/protected"
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH_BIND_ADDRESS` | Server bind address | `127.0.0.1` |
| `AUTH_PORT` | Server port | `8080` |
| `AUTH_LOG_LEVEL` | Logging level | `info` |
| `AUTH_TOKEN_TTL` | Default token TTL (seconds) | `3600` |
| `AUTH_RATE_LIMIT` | Rate limit (requests/minute) | `1000` |

### Configuration File

```toml
# auth-core.toml
[server]
bind_address = "127.0.0.1"
port = 8080
log_level = "info"

[tokens]
default_ttl = 3600
cleanup_interval = 300

[rate_limiting]
requests_per_minute = 1000
burst_size = 100

[[clients]]
id = "demo_client"
secret = "demo_secret"
scopes = ["read", "write"]
grant_types = ["client_credentials"]

[[clients]]
id = "admin_client"
secret = "admin_secret_very_long"
scopes = ["read", "write", "admin"]
grant_types = ["client_credentials", "authorization_code"]
```

### Programmatic Configuration

```rust
use auth_core::prelude::*;

let server = AuthServer::minimal()
    // Basic client
    .with_client("api_client", "secure_secret_123")
    
    // Client with specific scopes
    .with_client_config("web_client", ClientConfig {
        client_secret: "web_secret_456".to_string(),
        allowed_scopes: vec!["read".to_string(), "profile".to_string()],
        redirect_uris: vec!["http://localhost:3000/callback".to_string()],
        grant_types: vec![GrantType::AuthorizationCode],
    })
    
    // Global scopes
    .with_scope("read")
    .with_scope("write")
    .with_scope("admin")
    
    // Security settings
    .with_token_ttl(3600)
    .with_rate_limit(100, 60) // 100 requests per minute
    
    .build()?;
```

## Examples

### Basic Integration

```rust
use auth_core::prelude::*;
use axum::{Router, routing::get};

#[tokio::main]
async fn main() {
    // Create auth server
    let auth_server = AuthServer::minimal()
        .with_client("web_app", "secret_key")
        .build()
        .expect("Failed to build auth server");
    
    // Create your application routes
    let app_routes = Router::new()
        .route("/api/protected", get(protected_handler))
        .layer(auth_server.middleware());
    
    // Combine with OAuth routes
    let app = auth_server.routes()
        .nest("/api", app_routes);
    
    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    
    axum::serve(listener, app).await.unwrap();
}

async fn protected_handler() -> &'static str {
    "This endpoint requires authentication"
}
```

### Testing Integration

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Client;
    
    #[tokio::test]
    async fn test_oauth_flow() {
        // Start test server
        let server = create_test_server().await;
        let client = Client::new();
        
        // Get token
        let token_response = client
            .post("http://localhost:8080/oauth/token")
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "test_client"),
                ("client_secret", "test_secret"),
            ])
            .send()
            .await
            .unwrap();
        
        assert_eq!(token_response.status(), 200);
        
        let token_data: TokenResponse = token_response.json().await.unwrap();
        assert!(!token_data.access_token.is_empty());
        assert_eq!(token_data.token_type, "Bearer");
        
        // Use token
        let api_response = client
            .get("http://localhost:8080/api/protected")
            .bearer_auth(&token_data.access_token)
            .send()
            .await
            .unwrap();
        
        assert_eq!(api_response.status(), 200);
    }
}
```

### Framework Integration Examples

#### Actix-Web

```rust
use actix_web::{web, App, HttpServer, middleware::Logger};
use auth_core::prelude::*;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let auth_server = AuthServer::minimal()
        .with_client("actix_client", "actix_secret")
        .build()
        .expect("Failed to build auth server");
    
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .configure(auth_server.configure_actix())
            .service(
                web::scope("/api")
                    .wrap(auth_server.actix_middleware())
                    .route("/protected", web::get().to(protected_handler))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

#### Warp

```rust
use warp::Filter;
use auth_core::prelude::*;

#[tokio::main]
async fn main() {
    let auth_server = AuthServer::minimal()
        .with_client("warp_client", "warp_secret")
        .build()
        .expect("Failed to build auth server");
    
    let oauth_routes = auth_server.warp_routes();
    
    let api_routes = warp::path("api")
        .and(warp::path("protected"))
        .and(auth_server.warp_auth_filter())
        .and_then(protected_handler);
    
    let routes = oauth_routes.or(api_routes);
    
    warp::serve(routes)
        .run(([127, 0, 0, 1], 8080))
        .await;
}
```

### Performance Monitoring

```rust
use auth_core::prelude::*;
use prometheus::{Counter, Histogram};

// Create metrics
let request_counter = Counter::new("oauth_requests_total", "Total OAuth requests").unwrap();
let request_duration = Histogram::new("oauth_request_duration_seconds", "OAuth request duration").unwrap();

let server = AuthServer::minimal()
    .with_client("monitored_client", "secret")
    .with_metrics(request_counter, request_duration)
    .build()?;
```

## API Versioning

The API uses semantic versioning. Breaking changes increment the major version.

| Version | Status | Support Until | Changes |
|---------|--------|---------------|---------|
| v1.x | Current | TBD | Initial release |
| v2.x | Planned | TBD | Enhanced security features |

### Version Headers

```http
Accept: application/json; version=1
API-Version: 1.0
```

## Rate Limiting

### Rate Limit Headers

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

### Rate Limit Response

```json
{
  "error": "rate_limit_exceeded",
  "error_description": "Rate limit of 1000 requests per hour exceeded",
  "retry_after": 3600
}
```

## Security Considerations

### Token Security

1. **Storage**: Store tokens securely, never in localStorage
2. **Transmission**: Always use HTTPS in production
3. **Expiration**: Tokens have limited lifetime
4. **Scope**: Request minimal required scopes

### Client Security

1. **Secrets**: Keep client secrets secure
2. **Rotation**: Regularly rotate credentials
3. **Validation**: Validate all responses
4. **Monitoring**: Monitor for suspicious activity

### Best Practices

```rust
// DO: Use secure random secrets
let client_secret = generate_secure_random_string(32);

// DON'T: Use predictable secrets
let client_secret = "password123"; // ❌

// DO: Validate token expiration
if token.expires_at < SystemTime::now() {
    // Refresh token
}

// DON'T: Use expired tokens
// Will result in 401 Unauthorized
```

---

## Need Help?

- 📖 [Getting Started Guide](GETTING_STARTED_SIMPLE.md)
- 💬 [Discord Community](https://discord.gg/rust-security)
- 🐛 [Report Issues](https://github.com/rust-security/auth-service/issues)
- 📧 [Email Support](mailto:support@rust-security.dev)

---

*This API reference is auto-generated from the codebase. Last updated: $(date)*