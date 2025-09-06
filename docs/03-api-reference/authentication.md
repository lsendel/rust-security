# Authentication API

## Overview

The Authentication API provides endpoints for user authentication, OAuth 2.0 flows, and token management. It supports multiple authentication methods and is compliant with OAuth 2.0 and OpenID Connect standards.

## Base URL

```
http://localhost:8080
```

## OAuth 2.0 Endpoints

### Token Endpoint

**POST /oauth/token**

Request access tokens using various OAuth 2.0 flows.

#### Client Credentials Flow

Request an access token using client credentials for service-to-service authentication.

**Request:**
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=your_client_id&client_secret=your_client_secret&scope=read%20write
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grant_type` | string | Yes | Must be `client_credentials` |
| `client_id` | string | Yes | Your application's client identifier |
| `client_secret` | string | Yes | Your application's client secret |
| `scope` | string | No | Space-separated list of requested scopes |

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

**Error Response (400 Bad Request):**
```json
{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid"
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=your_client_id" \
  -d "client_secret=your_client_secret" \
  -d "scope=read write"
```

#### Password Grant Flow

Authenticate a user with username and password.

**Request:**
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=user@example.com&password=SecurePass123!&client_id=your_client_id&client_secret=your_client_secret
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grant_type` | string | Yes | Must be `password` |
| `username` | string | Yes | User's username or email |
| `password` | string | Yes | User's password |
| `client_id` | string | Yes | Your application's client identifier |
| `client_secret` | string | Yes | Your application's client secret |
| `scope` | string | No | Space-separated list of requested scopes |

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "read write"
}
```

#### Refresh Token Flow

Renew an access token using a refresh token.

**Request:**
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=your_refresh_token&client_id=your_client_id&client_secret=your_client_secret
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grant_type` | string | Yes | Must be `refresh_token` |
| `refresh_token` | string | Yes | The refresh token |
| `client_id` | string | Yes | Your application's client identifier |
| `client_secret` | string | Yes | Your application's client secret |

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "read write"
}
```

### Token Introspection

**POST /oauth/introspect**

Determine the active state and metadata of a token (RFC 7662).

**Request:**
```http
POST /oauth/introspect HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=your_access_token&client_id=your_client_id&client_secret=your_client_secret
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | The token to introspect |
| `client_id` | string | Yes | Client identifier |
| `client_secret` | string | Yes | Client secret |

**Response (200 OK) - Active Token:**
```json
{
  "active": true,
  "client_id": "your_client_id",
  "username": "user@example.com",
  "scope": "read write",
  "exp": 1640995200,
  "iat": 1640991600,
  "sub": "user@example.com",
  "token_type": "Bearer"
}
```

**Response (200 OK) - Inactive Token:**
```json
{
  "active": false
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:8080/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=your_access_token" \
  -d "client_id=your_client_id" \
  -d "client_secret=your_client_secret"
```

### Token Revocation

**POST /oauth/revoke**

Revoke an access or refresh token.

**Request:**
```http
POST /oauth/revoke HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=your_token&client_id=your_client_id&client_secret=your_client_secret
```

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | The token to revoke |
| `client_id` | string | Yes | Client identifier |
| `client_secret` | string | Yes | Client secret |
| `token_type_hint` | string | No | Hint about the type of token (access_token or refresh_token) |

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Token revoked successfully"
}
```

## OpenID Connect Endpoints

### User Info

**GET /oauth/userinfo**

Get user information for an access token.

**Request:**
```http
GET /oauth/userinfo HTTP/1.1
Authorization: Bearer your_access_token
```

**Response (200 OK):**
```json
{
  "sub": "user@example.com",
  "name": "John Doe",
  "email": "user@example.com",
  "email_verified": true,
  "preferred_username": "johndoe",
  "given_name": "John",
  "family_name": "Doe"
}
```

### Discovery

**GET /.well-known/openid-configuration**

Get OpenID Connect configuration information.

**Response (200 OK):**
```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/oauth/authorize",
  "token_endpoint": "http://localhost:8080/oauth/token",
  "userinfo_endpoint": "http://localhost:8080/oauth/userinfo",
  "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email", "read", "write"],
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
}
```

### JWKS

**GET /.well-known/jwks.json**

Get JSON Web Key Set for JWT token verification.

**Response (200 OK):**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-1",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbPFRP_gdHPfSn...",
      "e": "AQAB"
    }
  ]
}
```

## User Management Endpoints

### Create User

**POST /users**

Create a new user account.

**Request:**
```http
POST /users HTTP/1.1
Content-Type: application/json
Authorization: Bearer admin_access_token

{
  "username": "johndoe",
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe",
  "require_mfa": true
}
```

**Response (201 Created):**
```json
{
  "id": "user-123",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "require_mfa": true,
  "email_verified": false
}
```

### Get User

**GET /users/{user_id}**

Get user information.

**Request:**
```http
GET /users/user-123 HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "id": "user-123",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "require_mfa": true,
  "email_verified": true
}
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