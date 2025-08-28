# 🔐 Comprehensive API Documentation

**Rust Authentication Service - Enterprise Security Platform**
**Version**: 2.0.0
**API Version**: v1

## 📋 Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Core Endpoints](#core-endpoints)
4. [Security Features](#security-features)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Examples](#examples)
8. [SDK Integration](#sdk-integration)

## 🌟 Overview

The Rust Authentication Service provides enterprise-grade authentication and authorization capabilities with:

- **OAuth2/OIDC Compliance**: Full RFC-compliant implementation
- **Zero-Trust Architecture**: Continuous verification and validation
- **Advanced Security**: IDOR protection, TOTP replay prevention, PKCE enforcement
- **Performance Optimized**: 10-100x improvements over standard implementations
- **Real-time Monitoring**: Threat detection and automated response

### **Base URL**
```
Production: https://auth.yourcompany.com
Staging: https://auth-staging.yourcompany.com
Development: http://localhost:8080
```

### **Supported Features**
- ✅ OAuth2 Authorization Code Flow with PKCE
- ✅ Multi-Factor Authentication (TOTP/SMS)
- ✅ Session Management with Security Controls
- ✅ Token Introspection and Validation
- ✅ Rate Limiting and DDoS Protection
- ✅ Real-time Security Monitoring

## 🔐 Authentication

All API requests must include appropriate authentication credentials. The service supports multiple authentication methods:

### **Bearer Token Authentication**
```http
Authorization: Bearer <access_token>
```

### **Basic Authentication** (for client credentials)
```http
Authorization: Basic <base64(client_id:client_secret)>
```

### **API Key Authentication** (for system integrations)
```http
X-API-Key: <api_key>
```

## 🚀 Core Endpoints

### **Health Check**

#### `GET /health`
Returns the service health status.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-08-17T20:30:00Z",
  "version": "2.0.0",
  "features": {
    "redis_connected": true,
    "database_connected": true,
    "threat_hunting_active": true,
    "soar_enabled": true
  }
}
```

### **OAuth2 Authorization**

#### `GET /oauth/authorize`
Initiates the OAuth2 authorization flow with enhanced security.

**Parameters:**
- `response_type` (required): `code`
- `client_id` (required): Client identifier
- `redirect_uri` (required): Callback URL
- `scope` (optional): Requested permissions
- `state` (required): CSRF protection token
- `code_challenge` (required): PKCE challenge (S256 method only)
- `code_challenge_method` (required): Must be `S256`

**Security Features:**
- ✅ PKCE enforcement (plain method disabled)
- ✅ Redirect URI validation
- ✅ State parameter requirement
- ✅ Rate limiting (10 requests/minute per IP)

**Example Request:**
```http
GET /oauth/authorize?response_type=code&client_id=my_app&redirect_uri=https://myapp.com/callback&scope=read%20write&state=random_state_token&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

**Response:**
- **Success**: 302 redirect to authorization page
- **Error**: 400 with error details

### **Token Exchange**

#### `POST /oauth/token`
Exchanges authorization code for access tokens with security validations.

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**
- `grant_type` (required): `authorization_code` or `client_credentials`
- `code` (required for auth code): Authorization code
- `client_id` (required): Client identifier
- `redirect_uri` (required for auth code): Original redirect URI
- `code_verifier` (required for auth code): PKCE verifier

**Security Features:**
- ✅ Code expiration validation (10 minutes)
- ✅ PKCE verification (S256 only)
- ✅ Client authentication
- ✅ One-time code usage enforcement

**Example Request:**
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=auth_code_123&client_id=my_app&redirect_uri=https://myapp.com/callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Response:**
```json
{
  "access_token": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_123",
  "scope": "read write",
  "id_token": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
}
```

### **Token Introspection**

#### `POST /oauth/introspect`
Validates and returns metadata about access tokens.

**Content-Type:** `application/json`

**Parameters:**
```json
{
  "token": "access_token_to_validate"
}
```

**Security Features:**
- ✅ Token signature validation
- ✅ Expiration checking
- ✅ Scope verification
- ✅ Client authorization validation

**Response:**
```json
{
  "active": true,
  "client_id": "my_app",
  "username": "user@example.com",
  "scope": "read write",
  "exp": 1692315000,
  "iat": 1692311400,
  "sub": "user_123",
  "aud": ["my_app"],
  "iss": "https://auth.yourcompany.com"
}
```

### **Multi-Factor Authentication**

#### `POST /mfa/totp/verify`
Verifies TOTP codes with replay protection.

**Authentication:** Bearer token required

**Request:**
```json
{
  "totp_code": "123456",
  "user_id": "user_123"
}
```

**Security Features:**
- ✅ TOTP replay prevention (Redis nonce tracking)
- ✅ Time window validation (±30 seconds)
- ✅ Rate limiting (5 attempts/minute)
- ✅ Failed attempt logging

**Response:**
```json
{
  "verified": true,
  "message": "TOTP verification successful",
  "expires_at": "2025-08-17T21:00:00Z"
}
```

### **Session Management**

#### `GET /sessions`
Lists user sessions with ownership validation.

**Authentication:** Bearer token required

**Security Features:**
- ✅ IDOR protection (user ownership validation)
- ✅ Session enumeration prevention
- ✅ Secure session metadata

**Response:**
```json
{
  "sessions": [
    {
      "session_id": "sess_123",
      "created_at": "2025-08-17T20:00:00Z",
      "expires_at": "2025-08-18T20:00:00Z",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "is_current": true
    }
  ]
}
```

#### `DELETE /sessions/{session_id}`
Terminates a specific session with ownership validation.

**Authentication:** Bearer token required

**Security Features:**
- ✅ Session ownership validation
- ✅ Secure session termination
- ✅ Activity logging

**Response:**
```json
{
  "message": "Session terminated successfully",
  "session_id": "sess_123"
}
```

### **User Information**

#### `GET /userinfo`
Returns user profile information.

**Authentication:** Bearer token required

**Response:**
```json
{
  "sub": "user_123",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "picture": "https://example.com/avatar.jpg",
  "updated_at": "2025-08-17T20:00:00Z"
}
```

## 🛡️ Security Features

### **IDOR Protection**
All endpoints implement Insecure Direct Object Reference protection:
- User sessions validated for ownership
- Resource access verified per user
- Enumeration attacks prevented

### **TOTP Replay Prevention**
Multi-factor authentication includes replay protection:
- Redis-based nonce tracking
- One-time code enforcement
- Time window validation

### **PKCE Enforcement**
OAuth2 flows require Proof Key for Code Exchange:
- S256 method mandatory
- Plain text method disabled
- Code challenge validation

### **Rate Limiting**
Comprehensive rate limiting protects against abuse:
- Per-IP request limits
- Per-user action limits
- Trusted proxy support
- DDoS protection

## ⚠️ Error Handling

### **Standard Error Response**
```json
{
  "error": "invalid_request",
  "error_description": "The request is missing a required parameter.",
  "error_uri": "https://docs.yourcompany.com/errors/invalid_request",
  "correlation_id": "req_123456789"
}
```

### **Common Error Codes**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request |
| `unauthorized` | 401 | Authentication required |
| `forbidden` | 403 | Insufficient permissions |
| `not_found` | 404 | Resource not found |
| `rate_limit_exceeded` | 429 | Too many requests |
| `internal_error` | 500 | Server error |

### **Security Error Responses**

#### **Rate Limit Exceeded**
```json
{
  "error": "rate_limit_exceeded",
  "error_description": "Too many requests. Try again later.",
  "retry_after": 60,
  "correlation_id": "req_123456789"
}
```

#### **Invalid TOTP Code**
```json
{
  "error": "invalid_totp",
  "error_description": "TOTP code is invalid or has been used.",
  "remaining_attempts": 3,
  "correlation_id": "req_123456789"
}
```

## 🚥 Rate Limiting

### **Rate Limit Headers**
All responses include rate limiting headers:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1692315000
X-RateLimit-Window: 3600
```

### **Rate Limits by Endpoint**

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/oauth/authorize` | 10/min | Per IP |
| `/oauth/token` | 20/min | Per Client |
| `/mfa/totp/verify` | 5/min | Per User |
| `/userinfo` | 100/hour | Per User |
| `/sessions` | 50/hour | Per User |

## 📚 Examples

### **Complete OAuth2 Flow with PKCE**

1. **Generate PKCE Challenge**
```javascript
const codeVerifier = generateRandomString(128);
const codeChallenge = base64URLEncode(sha256(codeVerifier));
```

2. **Authorization Request**
```http
GET /oauth/authorize?response_type=code&client_id=my_app&redirect_uri=https://myapp.com/callback&scope=read&state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

3. **Token Exchange**
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=auth_code&client_id=my_app&client_secret=YOUR_CLIENT_SECRET&redirect_uri=https://myapp.com/callback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### **MFA Authentication Flow**

1. **Request MFA Challenge**
```http
POST /mfa/challenge
Authorization: Bearer access_token
Content-Type: application/json

{
  "method": "totp"
}
```

2. **Verify TOTP Code**
```http
POST /mfa/totp/verify
Authorization: Bearer access_token
Content-Type: application/json

{
  "totp_code": "123456"
}
```

## 🔧 SDK Integration

### **JavaScript/TypeScript**
```typescript
import { AuthClient } from '@yourcompany/auth-sdk';

const auth = new AuthClient({
  baseUrl: 'https://auth.yourcompany.com',
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET
});

// OAuth2 with PKCE
const { authUrl, codeVerifier } = await auth.getAuthorizationUrl({
  redirectUri: 'https://yourapp.com/callback',
  scope: ['read', 'write'],
  state: 'random_state'
});

// Token exchange
const tokens = await auth.exchangeCode({
  code: 'authorization_code',
  codeVerifier,
  redirectUri: 'https://yourapp.com/callback'
});
```

### **Python**
```python
import os
from auth_sdk import AuthClient

auth = AuthClient(
    base_url='https://auth.yourcompany.com',
    client_id=os.environ.get('CLIENT_ID'),
    client_secret=os.environ.get('CLIENT_SECRET')
)

# OAuth2 with PKCE
auth_url, code_verifier = auth.get_authorization_url(
    redirect_uri='https://yourapp.com/callback',
    scope=['read', 'write'],
    state='random_state'
)

# Token exchange
tokens = auth.exchange_code(
    code='authorization_code',
    code_verifier=code_verifier,
    redirect_uri='https://yourapp.com/callback'
)
```

## 🔍 Security Considerations

### **Best Practices**
1. **Always use HTTPS** in production
2. **Validate redirect URIs** against registered URLs
3. **Use state parameter** for CSRF protection
4. **Implement proper token storage** (httpOnly cookies recommended)
5. **Monitor rate limits** and implement retry logic
6. **Validate all tokens** server-side

### **Security Headers**
The API returns security headers:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

## 📞 Support

### **Documentation**
- [Security Guide](./SECURITY_GUIDE.md)
- [Integration Examples](./INTEGRATION_EXAMPLES.md)
- [Troubleshooting](./TROUBLESHOOTING.md)

### **Contact**
- **Security Issues**: security@yourcompany.com
- **Technical Support**: support@yourcompany.com
- **Documentation**: docs@yourcompany.com

---

**Last Updated**: August 17, 2025
**API Version**: v1
**Documentation Version**: 2.0.0
