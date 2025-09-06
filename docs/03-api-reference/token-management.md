# Token Management API

## Overview

The Token Management API provides endpoints for managing OAuth 2.0 tokens, including introspection, revocation, and monitoring. This API is essential for maintaining security and controlling access to protected resources.

## Base URL

```
http://localhost:8080
```

## Token Introspection

### Introspect Token

**POST /oauth/introspect**

Determine the active state and metadata of a token (RFC 7662).

**Request:**
```http
POST /oauth/introspect HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Form Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | The token to introspect |
| `token_type_hint` | string | No | Hint about the type of token (access_token or refresh_token) |

**Response (200 OK) - Active Token:**
```json
{
  "active": true,
  "client_id": "myapp",
  "username": "alice",
  "scope": "read write",
  "token_type": "Bearer",
  "exp": 1640995200,
  "iat": 1640991600,
  "nbf": 1640991600,
  "sub": "alice",
  "aud": ["https://api.example.com"],
  "iss": "https://auth.example.com",
  "jti": "token-123",
  "cnf": {
    "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
  }
}
```

**Response (200 OK) - Inactive Token:**
```json
{
  "active": false
}
```

## Token Revocation

### Revoke Token

**POST /oauth/revoke**

Revoke an access or refresh token (RFC 7009).

**Request:**
```http
POST /oauth/revoke HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&token_type_hint=access_token
```

**Form Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | The token to revoke |
| `token_type_hint` | string | No | Hint about the type of token (access_token or refresh_token) |

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Token revoked successfully"
}
```

## Token Management (Admin)

### List Tokens

**GET /admin/tokens**

List all active tokens with filtering options (admin only).

**Request:**
```http
GET /admin/tokens?client_id=myapp&username=alice&limit=50 HTTP/1.1
Authorization: Bearer admin_access_token
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `client_id` | string | No | Filter by client ID |
| `username` | string | No | Filter by username |
| `token_type` | string | No | Filter by token type (access_token, refresh_token) |
| `active_only` | boolean | No | Only show active tokens (default: true) |
| `limit` | integer | No | Number of results per page (default: 20, max: 100) |
| `page` | integer | No | Page number (default: 1) |

**Response (200 OK):**
```json
{
  "tokens": [
    {
      "id": "token-123",
      "client_id": "myapp",
      "username": "alice",
      "token_type": "access_token",
      "scope": "read write",
      "active": true,
      "expires_at": "2024-01-15T11:00:00Z",
      "issued_at": "2024-01-15T10:00:00Z",
      "last_used": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 20,
  "total_pages": 1
}
```

### Get Token Details

**GET /admin/tokens/{token_id}**

Get detailed information about a specific token (admin only).

**Request:**
```http
GET /admin/tokens/token-123 HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "id": "token-123",
  "client_id": "myapp",
  "username": "alice",
  "token_type": "access_token",
  "scope": "read write",
  "active": true,
  "expires_at": "2024-01-15T11:00:00Z",
  "issued_at": "2024-01-15T10:00:00Z",
  "last_used": "2024-01-15T10:30:00Z",
  "issuer": "https://auth.example.com",
  "audience": ["https://api.example.com"],
  "ip_addresses": ["192.168.1.100"],
  "user_agent": "MyApp/1.0"
}
```

### Revoke Token (Admin)

**DELETE /admin/tokens/{token_id}**

Revoke a specific token (admin only).

**Request:**
```http
DELETE /admin/tokens/token-123 HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Token revoked successfully"
}
```

### Revoke User Tokens

**DELETE /admin/users/{user_id}/tokens**

Revoke all tokens for a specific user (admin only).

**Request:**
```http
DELETE /admin/users/user-123/tokens HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "All tokens revoked for user successfully",
  "count": 3
}
```

### Revoke Client Tokens

**DELETE /admin/clients/{client_id}/tokens**

Revoke all tokens for a specific client (admin only).

**Request:**
```http
DELETE /admin/clients/myapp/tokens HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "All tokens revoked for client successfully",
  "count": 5
}
```

## Client Token Management

### List Client Tokens

**GET /clients/{client_id}/tokens**

List all tokens issued to a specific client.

**Request:**
```http
GET /clients/myapp/tokens HTTP/1.1
Authorization: Bearer client_access_token
```

**Response (200 OK):**
```json
{
  "tokens": [
    {
      "id": "token-123",
      "username": "alice",
      "token_type": "access_token",
      "scope": "read write",
      "active": true,
      "expires_at": "2024-01-15T11:00:00Z",
      "issued_at": "2024-01-15T10:00:00Z",
      "last_used": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### Revoke Client Token

**DELETE /clients/{client_id}/tokens/{token_id}**

Revoke a specific token issued to the client.

**Request:**
```http
DELETE /clients/myapp/tokens/token-123 HTTP/1.1
Authorization: Bearer client_access_token
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Token revoked successfully"
}
```

## User Token Management

### List User Tokens

**GET /users/{user_id}/tokens**

List all tokens issued for a specific user.

**Request:**
```http
GET /users/user-123/tokens HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "tokens": [
    {
      "id": "token-123",
      "client_id": "myapp",
      "token_type": "access_token",
      "scope": "read write",
      "active": true,
      "expires_at": "2024-01-15T11:00:00Z",
      "issued_at": "2024-01-15T10:00:00Z",
      "last_used": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### Revoke User Token

**DELETE /users/{user_id}/tokens/{token_id}**

Revoke a specific token for the user.

**Request:**
```http
DELETE /users/user-123/tokens/token-123 HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Token revoked successfully"
}
```

## Token Statistics

### Get Token Statistics

**GET /admin/tokens/stats**

Get statistics about token usage and distribution (admin only).

**Request:**
```http
GET /admin/tokens/stats?period=24h HTTP/1.1
Authorization: Bearer admin_access_token
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `period` | string | No | Time period (1h, 24h, 7d, 30d) |
| `client_id` | string | No | Filter by client ID |
| `username` | string | No | Filter by username |

**Response (200 OK):**
```json
{
  "total_tokens": 1250,
  "active_tokens": 890,
  "expired_tokens": 360,
  "revoked_tokens": 45,
  "token_types": {
    "access_token": 780,
    "refresh_token": 470
  },
  "top_clients": [
    {
      "client_id": "myapp",
      "token_count": 320
    }
  ],
  "top_users": [
    {
      "username": "alice",
      "token_count": 25
    }
  ],
  "usage_trend": [
    {
      "timestamp": "2024-01-15T00:00:00Z",
      "issued": 45,
      "revoked": 5,
      "expired": 12
    }
  ]
}
```

## Token Templates

### Create Token Template

**POST /admin/token-templates**

Create a token template for consistent token issuance (admin only).

**Request:**
```http
POST /admin/token-templates HTTP/1.1
Content-Type: application/json
Authorization: Bearer admin_access_token

{
  "name": "standard_access",
  "description": "Standard access token template",
  "token_type": "access_token",
  "default_scope": "read",
  "expires_in": 3600,
  "audience": ["https://api.example.com"],
  "issuer": "https://auth.example.com"
}
```

**Response (201 Created):**
```json
{
  "id": "template-123",
  "name": "standard_access",
  "description": "Standard access token template",
  "token_type": "access_token",
  "default_scope": "read",
  "expires_in": 3600,
  "audience": ["https://api.example.com"],
  "issuer": "https://auth.example.com",
  "created_at": "2024-01-15T12:00:00Z",
  "updated_at": "2024-01-15T12:00:00Z"
}
```

### List Token Templates

**GET /admin/token-templates**

List all token templates (admin only).

**Request:**
```http
GET /admin/token-templates HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "templates": [
    {
      "id": "template-123",
      "name": "standard_access",
      "description": "Standard access token template",
      "token_type": "access_token",
      "default_scope": "read",
      "expires_in": 3600,
      "audience": ["https://api.example.com"],
      "issuer": "https://auth.example.com",
      "created_at": "2024-01-15T12:00:00Z",
      "updated_at": "2024-01-15T12:00:00Z"
    }
  ]
}
```

## Token Validation

### Validate Token Format

**POST /admin/tokens/validate**

Validate the format and structure of a JWT token without checking its validity (admin only).

**Request:**
```http
POST /admin/tokens/validate HTTP/1.1
Content-Type: application/json
Authorization: Bearer admin_access_token

{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**
```json
{
  "valid_format": true,
  "header": {
    "alg": "RS256",
    "typ": "JWT"
  },
  "payload": {
    "iss": "https://auth.example.com",
    "sub": "alice",
    "aud": ["https://api.example.com"],
    "exp": 1640995200,
    "iat": 1640991600,
    "scope": "read write"
  },
  "signature_valid": true,
  "not_expired": true,
  "not_before_valid": true
}
```

## Error Responses

### Standard Token Errors

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `invalid_request` | 400 | Malformed request or missing required parameters |
| `invalid_token` | 400 | The token is invalid or malformed |
| `unauthorized` | 401 | Missing or invalid authentication credentials |
| `forbidden` | 403 | Insufficient permissions to perform the operation |
| `not_found` | 404 | Token or resource not found |
| `unsupported_token_type` | 400 | The token type is not supported |
| `too_many_requests` | 429 | Rate limit exceeded |
| `internal_server_error` | 500 | Internal server error |

### Error Response Format

```json
{
  "error": "invalid_token",
  "error_description": "The token is invalid or expired",
  "details": {
    "token_id": "token-123",
    "reason": "expired"
  }
}
```