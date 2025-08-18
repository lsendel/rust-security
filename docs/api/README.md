# API Reference Documentation

The Rust Authentication Service provides a comprehensive REST API implementing OAuth2, OpenID Connect, SCIM 2.0, and proprietary security features.

## Base URLs

| Environment | URL |
|-------------|-----|
| Production | `https://auth.yourcompany.com` |
| Staging | `https://auth-staging.yourcompany.com` |
| Development | `http://localhost:8080` |

## API Versioning

The API uses URL-based versioning for breaking changes:
- Current version: v1 (default)
- Legacy support: Available for previous versions
- Version header: `Accept: application/json; version=1`

## Authentication

### API Authentication Methods

1. **Client Credentials** (Machine-to-Machine)
2. **HTTP Basic Authentication** (Admin endpoints)
3. **Bearer Token** (User context)
4. **Request Signing** (High-security operations)

### Rate Limiting

All endpoints are subject to rate limiting:

| Tier | Requests/Minute | Burst Allowance |
|------|----------------|-----------------|
| Default | 100 | 20 |
| Authenticated | 300 | 50 |
| Admin | 1000 | 100 |

Rate limit headers:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1634567890
X-RateLimit-Retry-After: 60
```

## Core Endpoints

### OAuth2/OpenID Connect

#### Discovery Endpoints

##### OpenID Configuration
```http
GET /.well-known/openid-configuration
```

Returns OpenID Connect discovery document.

**Response:**
```json
{
  "issuer": "https://auth.yourcompany.com",
  "authorization_endpoint": "https://auth.yourcompany.com/oauth/authorize",
  "token_endpoint": "https://auth.yourcompany.com/oauth/token",
  "userinfo_endpoint": "https://auth.yourcompany.com/oauth/userinfo",
  "jwks_uri": "https://auth.yourcompany.com/jwks.json",
  "scopes_supported": ["openid", "profile", "email", "admin"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "code_challenge_methods_supported": ["S256"]
}
```

##### JSON Web Key Set
```http
GET /jwks.json
```

Returns public keys for JWT verification.

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2023-10-01",
      "n": "0vx7agoebGcQ...",
      "e": "AQAB"
    }
  ]
}
```

#### Authorization Flow

##### Authorization Endpoint
```http
GET /oauth/authorize
```

Initiates OAuth2 authorization code flow with PKCE support.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `response_type` | string | Yes | Must be "code" |
| `client_id` | string | Yes | Client identifier |
| `redirect_uri` | string | Yes | Callback URL (must be registered) |
| `scope` | string | No | Space-separated scopes |
| `state` | string | Recommended | CSRF protection |
| `code_challenge` | string | Recommended | PKCE code challenge |
| `code_challenge_method` | string | No | Must be "S256" if challenge provided |

**Example Request:**
```http
GET /oauth/authorize?response_type=code&client_id=webapp&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid%20profile&state=xyz123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

**Success Response:**
```http
HTTP/1.1 302 Found
Location: https://app.example.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz123
```

**Error Response:**
```http
HTTP/1.1 302 Found
Location: https://app.example.com/callback?error=invalid_request&error_description=Missing%20client_id&state=xyz123
```

##### Token Endpoint
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
```

Exchanges authorization code for access tokens.

**Grant Types:**

1. **Authorization Code Grant:**
```http
grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback
&client_id=webapp
&client_secret=secret
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

2. **Client Credentials Grant:**
```http
grant_type=client_credentials
&client_id=service
&client_secret=secret
&scope=api:read api:write
```

3. **Refresh Token Grant:**
```http
grant_type=refresh_token
&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
&client_id=webapp
&client_secret=secret
```

**Success Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "scope": "openid profile",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error Response:**
```json
{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid"
}
```

#### Token Management

##### Token Introspection
```http
POST /oauth/introspect
Authorization: Basic Y2xpZW50OnNlY3JldA==
Content-Type: application/x-www-form-urlencoded
```

**Request:**
```http
token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
&token_type_hint=access_token
```

**Response:**
```json
{
  "active": true,
  "scope": "openid profile",
  "client_id": "webapp",
  "exp": 1634567890,
  "iat": 1634564290,
  "sub": "user123",
  "token_type": "access_token",
  "iss": "https://auth.yourcompany.com"
}
```

##### Token Revocation
```http
POST /oauth/revoke
Authorization: Basic Y2xpZW50OnNlY3JldA==
Content-Type: application/x-www-form-urlencoded
```

**Request:**
```http
token=tGzv3JOkF0XG5Qx2TlKWIA
&token_type_hint=refresh_token
```

**Response:**
```json
{
  "revoked": true
}
```

#### User Information

##### UserInfo Endpoint
```http
GET /oauth/userinfo
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response:**
```json
{
  "sub": "user123",
  "scope": "openid profile email",
  "client_id": "webapp",
  "mfa_verified": true
}
```

### Multi-Factor Authentication

#### TOTP (Time-based One-Time Password)

##### Register TOTP
```http
POST /mfa/totp/register
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request:**
```json
{
  "user_id": "user123"
}
```

**Response:**
```json
{
  "secret_base32": "JBSWY3DPEHPK3PXP",
  "otpauth_url": "otpauth://totp/Example:user123?secret=JBSWY3DPEHPK3PXP&issuer=Example"
}
```

##### Verify TOTP
```http
POST /mfa/totp/verify
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request:**
```json
{
  "user_id": "user123",
  "code": "123456"
}
```

**Response:**
```json
{
  "verified": true
}
```

##### Generate Backup Codes
```http
POST /mfa/totp/backup-codes/generate
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Response:**
```json
{
  "codes": [
    "a1b2c3d4",
    "e5f6g7h8",
    "i9j0k1l2"
  ]
}
```

#### WebAuthn

##### Begin Registration
```http
POST /mfa/webauthn/register/challenge
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request:**
```json
{
  "user_id": "user123",
  "user_name": "john.doe",
  "display_name": "John Doe"
}
```

##### Finish Registration
```http
POST /mfa/webauthn/register/finish
Authorization: Bearer {access_token}
Content-Type: application/json
```

##### Begin Authentication
```http
POST /mfa/webauthn/assert/challenge
Authorization: Bearer {access_token}
Content-Type: application/json
```

##### Finish Authentication
```http
POST /mfa/webauthn/assert/finish
Authorization: Bearer {access_token}
Content-Type: application/json
```

#### SMS OTP

##### Send OTP
```http
POST /mfa/otp/send
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request:**
```json
{
  "user_id": "user123",
  "phone_number": "+1234567890"
}
```

##### Verify OTP
```http
POST /mfa/otp/verify
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request:**
```json
{
  "user_id": "user123",
  "code": "123456"
}
```

#### MFA Session Management

##### Verify MFA Session
```http
POST /mfa/session/verify
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request:**
```json
{
  "user_id": "user123",
  "method": "totp",
  "code": "123456"
}
```

**Response:**
```json
{
  "verified": true,
  "session_token": "mfa_session_token",
  "expires_at": 1634567890
}
```

### Session Management

#### Create Session
```http
POST /session/create
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request:**
```json
{
  "user_id": "user123",
  "client_id": "webapp",
  "duration": 3600
}
```

**Response:**
```json
{
  "session_id": "sess_abc123",
  "expires_at": 1634567890,
  "csrf_token": "csrf_xyz789"
}
```

#### Get Session
```http
GET /session/{session_id}
Authorization: Bearer {access_token}
```

**Response:**
```json
{
  "id": "sess_abc123",
  "user_id": "user123",
  "client_id": "webapp",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "created_at": 1634564290,
  "expires_at": 1634567890,
  "csrf_token": "csrf_xyz789"
}
```

#### Refresh Session
```http
POST /session/{session_id}/refresh
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request:**
```json
{
  "duration": 7200
}
```

#### Delete Session
```http
DELETE /session/{session_id}
Authorization: Bearer {access_token}
```

#### Invalidate User Sessions
```http
POST /session/invalidate-user/{user_id}
Authorization: Bearer {access_token}
```

### Authorization (ABAC)

#### Check Authorization
```http
POST /v1/authorize
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request:**
```json
{
  "action": "read",
  "resource": {
    "type": "document",
    "id": "doc123",
    "attributes": {
      "classification": "confidential",
      "department": "engineering"
    }
  },
  "context": {
    "ip_address": "192.168.1.100",
    "time": "2023-10-01T12:00:00Z"
  },
  "mfa_required": true,
  "mfa_verified": true
}
```

**Response:**
```json
{
  "decision": "Allow"
}
```

### SCIM 2.0 User Management

#### List Users
```http
GET /scim/v2/Users
Authorization: Bearer {access_token}
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `startIndex` | integer | Start index (default: 1) |
| `count` | integer | Results per page (default: 20) |
| `filter` | string | SCIM filter expression |

**Response:**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 100,
  "Resources": [
    {
      "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
      "id": "user123",
      "userName": "john.doe",
      "name": {
        "formatted": "John Doe",
        "familyName": "Doe",
        "givenName": "John"
      },
      "emails": [{
        "value": "john.doe@example.com",
        "primary": true
      }],
      "active": true,
      "meta": {
        "resourceType": "User",
        "created": "2023-01-01T00:00:00Z",
        "lastModified": "2023-10-01T12:00:00Z"
      }
    }
  ]
}
```

#### Get User
```http
GET /scim/v2/Users/{user_id}
Authorization: Bearer {access_token}
```

#### Create User
```http
POST /scim/v2/Users
Authorization: Bearer {access_token}
Content-Type: application/scim+json
```

**Request:**
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "jane.smith",
  "name": {
    "familyName": "Smith",
    "givenName": "Jane"
  },
  "emails": [{
    "value": "jane.smith@example.com",
    "primary": true
  }],
  "active": true
}
```

#### Update User
```http
PUT /scim/v2/Users/{user_id}
Authorization: Bearer {access_token}
Content-Type: application/scim+json
```

#### Delete User
```http
DELETE /scim/v2/Users/{user_id}
Authorization: Bearer {access_token}
```

### Federated Authentication

#### Google OAuth
```http
GET /oauth/google/login
```

Redirects to Google OAuth authorization.

```http
GET /oauth/google/callback
```

Handles Google OAuth callback.

#### Microsoft OAuth
```http
GET /oauth/microsoft/login
```

```http
GET /oauth/microsoft/callback
```

#### GitHub OAuth
```http
GET /oauth/github/login
```

```http
GET /oauth/github/callback
```

### Administrative Endpoints

All administrative endpoints require an access token with the `admin` scope.

#### Key Management

##### Key Rotation Status
```http
GET /admin/keys/rotation/status
Authorization: Bearer {admin_token}
```

**Response:**
```json
{
  "current_key_id": "2023-10-01",
  "next_rotation": "2023-11-01T00:00:00Z",
  "rotation_policy": "monthly",
  "keys_count": 3
}
```

##### Force Key Rotation
```http
POST /admin/keys/rotation/force
Authorization: Bearer {admin_token}
```

#### Rate Limiting

##### Get Rate Limiting Stats
```http
GET /admin/rate-limit/stats
Authorization: Bearer {admin_token}
```

**Response:**
```json
{
  "total_entries": 1500,
  "shard_count": 16,
  "shard_sizes": [95, 92, 88, 103],
  "config": {
    "requests_per_window": 100,
    "window_duration_secs": 60,
    "burst_allowance": 20,
    "cleanup_interval_secs": 300
  }
}
```

#### Security Monitoring

##### Get Security Alerts
```http
GET /admin/security/alerts
Authorization: Bearer {admin_token}
```

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | integer | Maximum alerts to return |
| `active_only` | boolean | Only return active alerts |

**Response:**
```json
{
  "alerts": [
    {
      "id": "alert_123",
      "type": "suspicious_login",
      "severity": "high",
      "timestamp": "2023-10-01T12:00:00Z",
      "description": "Multiple failed login attempts",
      "user_id": "user456",
      "ip_address": "192.168.1.200",
      "resolved": false
    }
  ],
  "total": 5
}
```

##### Resolve Security Alert
```http
POST /admin/security/alerts/{alert_id}/resolve
Authorization: Bearer {admin_token}
Content-Type: application/json
```

**Request:**
```json
{
  "resolution_notes": "False positive - legitimate user"
}
```

##### Get Security Configuration
```http
GET /admin/security/config
Authorization: Bearer {admin_token}
```

##### Update Security Configuration
```http
POST /admin/security/config
Authorization: Bearer {admin_token}
Content-Type: application/json
```

### Monitoring and Health

#### Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "ok"
}
```

#### Metrics
```http
GET /metrics
```

Returns Prometheus-formatted metrics.

## Error Handling

### Error Response Format

All errors follow a consistent format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable error description",
  "error_uri": "https://docs.example.com/errors/error_code",
  "correlation_id": "req_abc123"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request |
| `unauthorized_client` | 401 | Invalid client credentials |
| `access_denied` | 403 | Access denied |
| `unsupported_response_type` | 400 | Invalid response_type |
| `invalid_scope` | 400 | Invalid or unsupported scope |
| `server_error` | 500 | Internal server error |
| `temporarily_unavailable` | 503 | Service temporarily unavailable |

### Rate Limiting Errors

When rate limits are exceeded:

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1634567890
Retry-After: 60

{
  "error": "rate_limit_exceeded",
  "error_description": "Rate limit exceeded. Try again in 60 seconds.",
  "retry_after": 60
}
```

## Security Considerations

### Request Signing

For high-security operations, requests can be signed using HMAC-SHA256:

```http
POST /oauth/token
Authorization: Bearer {token}
X-Signature: sha256=abc123...
X-Timestamp: 1634567890
Content-Type: application/json
```

### Token Binding

Tokens can be bound to client characteristics for enhanced security:

```http
X-Client-IP: 192.168.1.100
X-User-Agent: Mozilla/5.0...
```

### PKCE Enforcement

PKCE is enforced for all authorization code flows:
- Only S256 challenge method is supported
- Plain text challenges are rejected
- Code verifier must be 43-128 characters

### Input Validation

All inputs are validated:
- Maximum request body size: 1MB
- Token format validation
- URL validation for redirect URIs
- Scope validation against allowed scopes

## SDKs and Examples

See the [Integration Guide](../integration/README.md) for:
- JavaScript/TypeScript SDK
- Python SDK
- Go SDK
- cURL examples
- Postman collection

## Testing

### Test Environment

Use the test mode configuration for integration testing:

```env
TEST_MODE=1
```

This disables certain security checks for easier testing.

### Mock Endpoints

Test endpoints are available in test mode:
- Mock SCIM provider
- Mock MFA provider
- Test client credentials

## Changelog and Deprecation

### API Versioning Policy

- Breaking changes require a new API version
- Non-breaking changes are additive
- Deprecated features are supported for 12 months
- Advance notice is provided for deprecations

### Current Deprecations

None at this time.

## Support

For API support:
- **Documentation**: This reference
- **Issues**: [GitHub Issues](https://github.com/your-org/rust-security/issues)
- **API Status**: [Status Page](https://status.yourcompany.com)
- **Rate Limits**: Contact support for increases