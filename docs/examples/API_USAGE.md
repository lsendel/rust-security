# API Usage Examples

## Overview

This document provides comprehensive examples for using the Rust Security Platform API, covering common authentication, authorization, and security scenarios.

## Authentication Examples

### User Registration and Login

#### Register New User
```bash
curl -X POST http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

**Response:**
```json
{
  "success": true,
  "user_id": "user_123456",
  "message": "User registered successfully. Please check your email for verification."
}
```

#### Login with Password
```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd123"
  }'
```

**Response:**
```json
{
  "success": true,
  "token": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "refresh_token_here",
    "expires_in": 3600,
    "token_type": "Bearer"
  },
  "user": {
    "id": "user_123456",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "roles": ["user"],
    "mfa_enabled": false
  }
}
```

#### Login with MFA
```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd123",
    "mfa_code": "123456"
  }'
```

### Multi-Factor Authentication Setup

#### Setup TOTP MFA
```bash
curl -X POST http://localhost:8080/v1/auth/mfa/setup \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "totp"
  }'
```

**Response:**
```json
{
  "success": true,
  "method": "totp",
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/RustSecurity:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=RustSecurity",
  "backup_codes": [
    "12345678",
    "87654321",
    "11223344"
  ]
}
```

#### Verify MFA Code
```bash
curl -X POST http://localhost:8080/v1/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{
    "mfa_token": "mfa_token_from_setup",
    "code": "123456"
  }'
```

### Token Management

#### Refresh Access Token
```bash
curl -X POST http://localhost:8080/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your_refresh_token_here"
  }'
```

#### Logout
```bash
curl -X POST http://localhost:8080/v1/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Authorization Examples

### Check User Permissions

#### Get Current User Permissions
```bash
curl -X GET http://localhost:8080/v1/auth/permissions \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**
```json
{
  "permissions": [
    "read:users",
    "write:users",
    "read:security_events",
    "write:security_events"
  ],
  "roles": [
    "user",
    "security_analyst"
  ]
}
```

#### Check Specific Permission
```bash
curl -X POST http://localhost:8080/v1/auth/check \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "permission": "write:users",
    "resource": "user:123"
  }'
```

**Response:**
```json
{
  "allowed": true,
  "reason": null
}
```

### Role Management

#### Get Available Roles
```bash
curl -X GET http://localhost:8080/v1/auth/roles \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**
```json
{
  "roles": [
    {
      "id": "admin",
      "name": "Administrator",
      "description": "Full system access",
      "permissions": [
        "read:*",
        "write:*",
        "delete:*"
      ]
    },
    {
      "id": "user",
      "name": "User",
      "description": "Standard user access",
      "permissions": [
        "read:profile",
        "write:profile"
      ]
    }
  ]
}
```

#### Get User Roles
```bash
curl -X GET http://localhost:8080/v1/auth/roles/user_123456 \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Security Monitoring Examples

### Get Security Threats
```bash
curl -X GET "http://localhost:8080/v1/security/threats?severity=high&status=active" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**
```json
{
  "threats": [
    {
      "id": "threat_123",
      "title": "Suspicious Login Attempts",
      "description": "Multiple failed login attempts from IP 192.168.1.100",
      "severity": "high",
      "status": "active",
      "detected_at": "2024-01-15T10:30:00Z",
      "source": "authentication_service",
      "indicators": [
        "192.168.1.100",
        "failed_login",
        "brute_force"
      ]
    }
  ],
  "total": 1
}
```

### Resolve Security Threat
```bash
curl -X POST http://localhost:8080/v1/security/threats/threat_123/resolve \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resolution": "resolved",
    "notes": "IP address blocked and user notified"
  }'
```

## Audit Examples

### Get Audit Events
```bash
curl -X GET "http://localhost:8080/v1/audit/events?user_id=user_123&action=LOGIN&limit=10" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**
```json
{
  "events": [
    {
      "id": "audit_456",
      "timestamp": "2024-01-15T10:25:00Z",
      "user_id": "user_123",
      "action": "LOGIN",
      "resource": "authentication_service",
      "success": true,
      "details": {
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "method": "password"
      },
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0..."
    }
  ],
  "total": 1
}
```

### Get Specific Audit Event
```bash
curl -X GET http://localhost:8080/v1/audit/events/audit_456 \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Performance Monitoring Examples

### Get Performance Metrics
```bash
curl -X GET "http://localhost:8080/v1/performance/metrics?metric_type=response_time&timeframe=15m" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**
```json
{
  "metrics": {
    "response_time": {
      "current": 45.2,
      "average": 42.8,
      "min": 12.5,
      "max": 125.8,
      "p95": 78.3,
      "p99": 95.1
    },
    "throughput": {
      "current": 1250,
      "average": 1180,
      "min": 850,
      "max": 1450,
      "p95": 1320,
      "p99": 1380
    }
  },
  "timeframe": "15m",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Get Performance Bottlenecks
```bash
curl -X GET http://localhost:8080/v1/performance/bottlenecks \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**
```json
{
  "bottlenecks": [
    {
      "component": "database_connection_pool",
      "issue_type": "throughput",
      "severity": "medium",
      "description": "Connection pool utilization at 85%",
      "impact_score": 7.2,
      "recommendations": [
        "Increase connection pool size",
        "Optimize database queries",
        "Consider read replicas"
      ]
    }
  ],
  "total_impact": 7.2
}
```

## Quality Gates Examples

### Get Quality Gate Status
```bash
curl -X GET http://localhost:8080/v1/quality/gates/status \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Response:**
```json
{
  "overall_status": "passed",
  "gates": [
    {
      "name": "security_scan",
      "status": "passed",
      "score": 95,
      "issues": []
    },
    {
      "name": "performance_test",
      "status": "passed",
      "score": 88,
      "issues": [
        {
          "severity": "low",
          "message": "Response time slightly above threshold",
          "file": "performance_test.log",
          "line": 0
        }
      ]
    }
  ],
  "last_run": "2024-01-15T10:30:00Z"
}
```

### Run Quality Gates Manually
```bash
curl -X POST http://localhost:8080/v1/quality/gates/run \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Health Check Examples

### System Health Check
```bash
curl -X GET http://localhost:8080/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.4.0",
  "uptime_seconds": 86400,
  "services": {
    "auth": "healthy",
    "database": "healthy",
    "redis": "healthy",
    "security": "healthy"
  }
}
```

### Service-Specific Health Check
```bash
curl -X GET http://localhost:8080/health/auth
```

**Response:**
```json
{
  "service": "authentication",
  "status": "healthy",
  "version": "1.4.0",
  "uptime_seconds": 86400,
  "metrics": {
    "active_connections": 145,
    "requests_per_second": 1250,
    "average_response_time_ms": 45.2,
    "error_rate_percent": 0.1
  }
}
```

## Error Handling Examples

### Authentication Error
```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "wrong_password"
  }'
```

**Response:**
```json
{
  "success": false,
  "error": {
    "code": "AUTHENTICATION_FAILED",
    "message": "Invalid email or password",
    "details": {},
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req_123456789"
  }
}
```

### Authorization Error
```bash
curl -X GET http://localhost:8080/v1/admin/users \
  -H "Authorization: Bearer INSUFFICIENT_PERMISSIONS_TOKEN"
```

**Response:**
```json
{
  "success": false,
  "error": {
    "code": "INSUFFICIENT_PERMISSIONS",
    "message": "Access denied",
    "details": {
      "required_permission": "read:users",
      "user_permissions": ["read:profile"]
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req_123456790"
  }
}
```

## Rate Limiting Examples

### Rate Limit Exceeded
```bash
# After making too many requests
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'
```

**Response:**
```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
    "details": {
      "retry_after_seconds": 60,
      "limit": 100,
      "remaining": 0
    },
    "timestamp": "2024-01-15T10:30:00Z",
    "request_id": "req_123456791"
  }
}
```

## Client Libraries

### Rust Client Example
```rust
use rust_security_client::{AuthClient, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new("http://localhost:8080");
    let client = AuthClient::new(config);

    // Login
    let response = client.login("user@example.com", "password").await?;
    println!("Access token: {}", response.token.access_token);

    // Get user permissions
    let permissions = client.get_permissions(&response.token.access_token).await?;
    println!("Permissions: {:?}", permissions.permissions);

    Ok(())
}
```

### JavaScript/TypeScript Client Example
```javascript
import { RustSecurityClient } from 'rust-security-client';

const client = new RustSecurityClient({
  baseUrl: 'http://localhost:8080',
  timeout: 5000
});

// Login
const response = await client.login('user@example.com', 'password');
console.log('Access token:', response.token.access_token);

// Get permissions
const permissions = await client.getPermissions(response.token.access_token);
console.log('Permissions:', permissions.permissions);
```

### Python Client Example
```python
from rust_security_client import AuthClient

client = AuthClient(base_url="http://localhost:8080")

# Login
response = client.login("user@example.com", "password")
print(f"Access token: {response.token.access_token}")

# Get permissions
permissions = client.get_permissions(response.token.access_token)
print(f"Permissions: {permissions.permissions}")
```

## Integration Examples

### Web Application Integration
```javascript
// Frontend authentication integration
class AuthService {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.token = localStorage.getItem('auth_token');
  }

  async login(email, password) {
    const response = await fetch(`${this.baseUrl}/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    if (!response.ok) {
      throw new Error('Login failed');
    }

    const data = await response.json();
    this.token = data.token.access_token;
    localStorage.setItem('auth_token', this.token);

    return data;
  }

  async logout() {
    await fetch(`${this.baseUrl}/v1/auth/logout`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${this.token}` }
    });

    this.token = null;
    localStorage.removeItem('auth_token');
  }

  async getPermissions() {
    const response = await fetch(`${this.baseUrl}/v1/auth/permissions`, {
      headers: { 'Authorization': `Bearer ${this.token}` }
    });

    return await response.json();
  }
}
```

### Backend API Integration
```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct AuthRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    success: bool,
    token: Option<TokenResponse>,
    error: Option<ErrorResponse>,
}

struct SecurityClient {
    client: Client,
    base_url: String,
}

impl SecurityClient {
    async fn authenticate(&self, email: &str, password: &str) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        let request = AuthRequest {
            email: email.to_string(),
            password: password.to_string(),
        };

        let response = self.client
            .post(&format!("{}/v1/auth/login", self.base_url))
            .json(&request)
            .send()
            .await?;

        let auth_response: AuthResponse = response.json().await?;

        if auth_response.success {
            auth_response.token.ok_or("No token in successful response".into())
        } else {
            Err(auth_response.error.unwrap().message.into())
        }
    }

    async fn check_permission(&self, token: &str, permission: &str, resource: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let request = PermissionCheckRequest {
            permission: permission.to_string(),
            resource: resource.to_string(),
        };

        let response = self.client
            .post(&format!("{}/v1/auth/check", self.base_url))
            .bearer_auth(token)
            .json(&request)
            .send()
            .await?;

        let result: PermissionCheckResponse = response.json().await?;
        Ok(result.allowed)
    }
}
```

## Best Practices

### Error Handling
```javascript
// Always handle errors gracefully
try {
  const response = await client.login(email, password);
  // Success handling
} catch (error) {
  if (error.code === 'RATE_LIMIT_EXCEEDED') {
    // Handle rate limiting
    await delay(error.details.retry_after_seconds * 1000);
    return this.login(email, password);
  } else if (error.code === 'AUTHENTICATION_FAILED') {
    // Handle auth failure
    showError('Invalid credentials');
  } else {
    // Handle other errors
    showError('Login failed');
  }
}
```

### Token Management
```javascript
// Implement automatic token refresh
class TokenManager {
  constructor(client) {
    this.client = client;
    this.refreshPromise = null;
  }

  async getValidToken() {
    const token = this.getStoredToken();

    if (this.isTokenExpired(token)) {
      return await this.refreshToken();
    }

    return token;
  }

  async refreshToken() {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.client.refreshToken(this.getRefreshToken());

    try {
      const response = await this.refreshPromise;
      this.storeToken(response.token);
      return response.token.access_token;
    } finally {
      this.refreshPromise = null;
    }
  }
}
```

### Security Headers
```javascript
// Always validate security headers
const response = await fetch('/api/data', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'X-Requested-With': 'XMLHttpRequest'  // CSRF protection
  }
});

// Validate response headers
if (!response.headers.get('x-content-type-options') === 'nosniff') {
  throw new Error('Security header missing');
}
```

---

**For complete API documentation, visit: [API Reference](https://docs.rust-security.org/api)**
**For SDKs and client libraries: [GitHub Repository](https://github.com/lsendel/rust-security)**
