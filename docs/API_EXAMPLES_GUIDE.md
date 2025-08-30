# API Examples Guide

## Overview

This comprehensive guide provides practical examples for integrating with the Rust Security Platform APIs. Each section includes complete request/response examples, error handling, and best practices.

## Table of Contents

1. [Authentication Examples](#authentication-examples)
2. [Authorization Examples](#authorization-examples)
3. [User Management Examples](#user-management-examples)
4. [Token Management Examples](#token-management-examples)
5. [Error Handling Examples](#error-handling-examples)
6. [Integration Patterns](#integration-patterns)

## Authentication Examples

### 1. OAuth 2.0 Password Grant Flow

```bash
# Request access token using password grant
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=alice&password=SecurePass123!&client_id=myapp&client_secret=mysecret"
```

**Success Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
  "scope": "read write"
}
```

### 2. Client Credentials Grant Flow

```bash
# Request access token using client credentials
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=myapp&client_secret=mysecret&scope=admin"
```

### 3. Token Refresh

```bash
# Refresh an expired access token
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...&client_id=myapp&client_secret=mysecret"
```

## Authorization Examples

### 1. Policy Decision Point (PDP) Query

```bash
# Check if user has permission to perform an action
curl -X POST http://localhost:8081/v1/authorize \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." \
  -d '{
    "principal": {
      "id": "alice",
      "roles": ["user", "developer"],
      "department": "engineering"
    },
    "action": "read",
    "resource": {
      "type": "document",
      "id": "confidential_report.pdf",
      "classification": "internal",
      "department": "engineering"
    },
    "context": {
      "time": "2024-01-15T14:30:00Z",
      "ip_address": "192.168.1.100",
      "user_agent": "MyApp/1.0",
      "location": "office"
    }
  }'
```

**Allow Response:**
```json
{
  "decision": "Allow",
  "policy_id": "engineering_read_policy",
  "obligations": [
    {
      "action": "log_access",
      "parameters": {
        "level": "info",
        "message": "Document access granted"
      }
    }
  ]
}
```

**Deny Response:**
```json
{
  "decision": "Deny",
  "policy_id": "engineering_read_policy",
  "reason": "insufficient_clearance",
  "advice": [
    {
      "action": "request_approval",
      "parameters": {
        "approver_role": "manager",
        "justification_required": true
      }
    }
  ]
}
```

### 2. Bulk Authorization Queries

```bash
# Check multiple permissions in a single request
curl -X POST http://localhost:8081/v1/authorize/bulk \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." \
  -d '{
    "requests": [
      {
        "principal": {"id": "alice", "roles": ["user"]},
        "action": "read",
        "resource": {"type": "file", "path": "/docs/public/*"}
      },
      {
        "principal": {"id": "alice", "roles": ["user"]},
        "action": "write",
        "resource": {"type": "file", "path": "/docs/private/*"}
      }
    ]
  }'
```

## User Management Examples

### 1. Create User

```bash
curl -X POST http://localhost:8080/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." \
  -d '{
    "username": "john.doe",
    "email": "john.doe@company.com",
    "first_name": "John",
    "last_name": "Doe",
    "department": "engineering",
    "roles": ["user", "developer"],
    "require_mfa": true
  }'
```

### 2. Update User Profile

```bash
curl -X PUT http://localhost:8080/users/john.doe \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..." \
  -d '{
    "first_name": "Johnny",
    "department": "platform",
    "roles": ["user", "developer", "platform-engineer"]
  }'
```

### 3. List Users with Filtering

```bash
# Get users by department
curl "http://localhost:8080/users?department=engineering&limit=50" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."

# Get users by role
curl "http://localhost:8080/users?role=admin&status=active" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
```

## Token Management Examples

### 1. Introspect Token

```bash
curl -X POST http://localhost:8080/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
```

**Active Token Response:**
```json
{
  "active": true,
  "client_id": "myapp",
  "username": "alice",
  "scope": "read write",
  "token_type": "Bearer",
  "exp": 1640995200,
  "iat": 1640991600,
  "sub": "alice",
  "aud": "myapp",
  "iss": "rust-security-platform"
}
```

### 2. Revoke Token

```bash
curl -X POST http://localhost:8080/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
```

### 3. List User's Tokens

```bash
curl http://localhost:8080/users/alice/tokens \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."
```

## Error Handling Examples

### 1. Authentication Errors

```bash
# Invalid credentials
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=alice&password=wrongpassword"

# Response: 401 Unauthorized
{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid, expired, or revoked"
}
```

### 2. Authorization Errors

```bash
# Insufficient permissions
curl -X GET http://localhost:8080/admin/users \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9..."

# Response: 403 Forbidden
{
  "error": "insufficient_permissions",
  "error_description": "User does not have required permissions for this operation",
  "required_role": "admin"
}
```

### 3. Rate Limiting

```bash
# Too many requests
curl -X GET http://localhost:8080/api/data

# Response: 429 Too Many Requests
{
  "error": "rate_limit_exceeded",
  "error_description": "Rate limit exceeded. Try again later.",
  "retry_after": 60,
  "limit": 100,
  "remaining": 0,
  "reset_time": "2024-01-15T15:00:00Z"
}
```

## Integration Patterns

### 1. Service-to-Service Authentication

```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct TokenRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    scope: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

async fn get_service_token() -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();

    let token_request = TokenRequest {
        grant_type: "client_credentials".to_string(),
        client_id: "my-service".to_string(),
        client_secret: std::env::var("SERVICE_SECRET")?,
        scope: "read write".to_string(),
    };

    let response = client
        .post("http://auth-service:8080/oauth/token")
        .form(&token_request)
        .send()
        .await?;

    let token_response: TokenResponse = response.json().await?;
    Ok(format!("{} {}", token_response.token_type, token_response.access_token))
}
```

### 2. Policy-Based Access Control

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct AuthorizationRequest {
    principal: Principal,
    action: String,
    resource: Resource,
    context: Option<AuthContext>,
}

#[derive(Serialize)]
struct Principal {
    id: String,
    roles: Vec<String>,
    attributes: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct Resource {
    r#type: String,
    id: String,
    attributes: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct AuthContext {
    time: String,
    ip_address: String,
    user_agent: String,
}

async fn check_permission(
    user_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    token: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let auth_request = AuthorizationRequest {
        principal: Principal {
            id: user_id.to_string(),
            roles: vec!["user".to_string()], // In real app, fetch from user service
            attributes: std::collections::HashMap::new(),
        },
        action: action.to_string(),
        resource: Resource {
            r#type: resource_type.to_string(),
            id: resource_id.to_string(),
            attributes: std::collections::HashMap::new(),
        },
        context: Some(AuthContext {
            time: chrono::Utc::now().to_rfc3339(),
            ip_address: "127.0.0.1".to_string(),
            user_agent: "MyService/1.0".to_string(),
        }),
    };

    let response = client
        .post("http://policy-service:8081/v1/authorize")
        .header("Authorization", format!("Bearer {}", token))
        .json(&auth_request)
        .send()
        .await?;

    #[derive(Deserialize)]
    struct AuthResponse {
        decision: String,
    }

    let auth_response: AuthResponse = response.json().await?;
    Ok(auth_response.decision == "Allow")
}
```

### 3. Error Handling Pattern

```rust
use std::time::Duration;

async fn resilient_api_call() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let mut attempt = 0;
    let max_attempts = 3;

    loop {
        attempt += 1;

        let response = client
            .get("http://api-service:8080/data")
            .header("Authorization", "Bearer <token>")
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                // Handle successful response
                return Ok(());
            }
            Ok(resp) if resp.status() == 401 => {
                // Token expired, refresh and retry
                if attempt < max_attempts {
                    refresh_token().await?;
                    continue;
                } else {
                    return Err("Authentication failed after retries".into());
                }
            }
            Ok(resp) if resp.status() == 429 => {
                // Rate limited, wait and retry
                if attempt < max_attempts {
                    let retry_after = resp.headers()
                        .get("retry-after")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(60);

                    tokio::time::sleep(Duration::from_secs(retry_after)).await;
                    continue;
                }
            }
            Ok(resp) => {
                return Err(format!("API error: {}", resp.status()).into());
            }
            Err(e) if attempt < max_attempts => {
                // Network error, retry with backoff
                let delay = Duration::from_millis(500 * attempt as u64);
                tokio::time::sleep(delay).await;
                continue;
            }
            Err(e) => {
                return Err(format!("Network error after {} attempts: {}", max_attempts, e).into());
            }
        }
    }
}

async fn refresh_token() -> Result<(), Box<dyn std::error::Error>> {
    // Implement token refresh logic
    Ok(())
}
```

## Best Practices

### 1. Token Management
- Always validate tokens before use
- Implement token refresh before expiration
- Store tokens securely (never in localStorage for web apps)
- Use short-lived access tokens with long-lived refresh tokens

### 2. Error Handling
- Handle all HTTP status codes appropriately
- Implement exponential backoff for retries
- Log errors with sufficient context for debugging
- Provide meaningful error messages to users

### 3. Security
- Use HTTPS for all API communications
- Validate all input parameters
- Implement rate limiting on client side
- Never log sensitive information

### 4. Performance
- Cache authorization decisions when appropriate
- Use connection pooling for multiple requests
- Implement request batching for bulk operations
- Monitor response times and implement timeouts

### 5. Monitoring
- Log all authentication and authorization events
- Monitor API response times and error rates
- Implement health checks for all services
- Set up alerts for critical failures

## SDK Examples

### JavaScript/Node.js Client

```javascript
class SecurityPlatformClient {
  constructor(baseUrl = 'http://localhost:8080') {
    this.baseUrl = baseUrl;
    this.client = axios.create({
      baseURL: baseUrl,
      timeout: 10000,
    });
  }

  async authenticate(username, password) {
    try {
      const response = await this.client.post('/oauth/token', {
        grant_type: 'password',
        username,
        password,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
      });

      this.accessToken = response.data.access_token;
      this.refreshToken = response.data.refresh_token;

      return response.data;
    } catch (error) {
      throw new Error(`Authentication failed: ${error.response?.data?.error_description || error.message}`);
    }
  }

  async authorize(action, resource) {
    try {
      const response = await this.client.post('/v1/authorize', {
        principal: { id: 'current-user' },
        action,
        resource,
      }, {
        headers: {
          'Authorization': `Bearer ${this.accessToken}`
        }
      });

      return response.data.decision === 'Allow';
    } catch (error) {
      if (error.response?.status === 401) {
        await this.refreshToken();
        return this.authorize(action, resource);
      }
      throw error;
    }
  }

  async refreshToken() {
    const response = await this.client.post('/oauth/token', {
      grant_type: 'refresh_token',
      refresh_token: this.refreshToken,
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
    });

    this.accessToken = response.data.access_token;
    this.refreshToken = response.data.refresh_token;
  }
}
```

### Python Client

```python
import requests
import time
from typing import Dict, Any, Optional

class SecurityPlatformClient:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.timeout = 30
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[float] = None

    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user and get tokens."""
        response = self.session.post(f"{self.base_url}/oauth/token", data={
            'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': 'myapp',
            'client_secret': 'mysecret'
        })

        if response.status_code == 200:
            data = response.json()
            self.access_token = data['access_token']
            self.refresh_token = data['refresh_token']
            self.token_expires_at = time.time() + data['expires_in']
            self.session.headers.update({
                'Authorization': f"Bearer {self.access_token}"
            })
            return data
        else:
            raise Exception(f"Authentication failed: {response.text}")

    def _ensure_valid_token(self):
        """Ensure we have a valid access token."""
        if not self.access_token or time.time() > (self.token_expires_at or 0) - 60:
            if self.refresh_token:
                self._refresh_token()
            else:
                raise Exception("No valid token available")

    def _refresh_token(self):
        """Refresh the access token."""
        response = self.session.post(f"{self.base_url}/oauth/token", data={
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': 'myapp',
            'client_secret': 'mysecret'
        })

        if response.status_code == 200:
            data = response.json()
            self.access_token = data['access_token']
            self.refresh_token = data.get('refresh_token', self.refresh_token)
            self.token_expires_at = time.time() + data['expires_in']
            self.session.headers.update({
                'Authorization': f"Bearer {self.access_token}"
            })
        else:
            raise Exception(f"Token refresh failed: {response.text}")

    def authorize(self, action: str, resource: Dict[str, Any]) -> bool:
        """Check if action is authorized for the given resource."""
        self._ensure_valid_token()

        payload = {
            "principal": {"id": "current-user"},  # In real app, get from user context
            "action": action,
            "resource": resource
        }

        response = self.session.post(f"{self.base_url}/v1/authorize", json=payload)

        if response.status_code == 200:
            return response.json()['decision'] == 'Allow'
        elif response.status_code == 401:
            self._refresh_token()
            return self.authorize(action, resource)
        else:
            raise Exception(f"Authorization failed: {response.text}")

    def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        """Get user profile information."""
        self._ensure_valid_token()

        response = self.session.get(f"{self.base_url}/users/{user_id}")

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to get user profile: {response.text}")
```

This comprehensive API examples guide provides everything needed to successfully integrate applications with the Rust Security Platform.
