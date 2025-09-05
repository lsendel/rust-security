# API Integration Guide

## Overview

This guide documents the comprehensive API architecture and integration patterns for the Rust Security Platform. The API system uses a microservices approach to provide scalable authentication, authorization, and security monitoring capabilities.

## Architecture

### Phase 1: Core API Services ✅
- REST API endpoints with OpenAPI 3.0 specification
- JWT-based authentication and authorization
- Rate limiting and request validation
- Comprehensive error handling and logging

### Phase 2: Security Integration ✅  
- **File**: `auth-service/src/auth_api.rs`
- **Purpose**: Core authentication API endpoints
- **Key Features**:
  - OAuth 2.0 token introspection
  - Multi-factor authentication flows
  - Session management and refresh tokens
  - Security event logging

### Phase 3: Advanced APIs ✅
- **File**: `auth-service/src/threat_adapter.rs` 
- **Purpose**: Threat detection API integration
- **Key Components**:
  - Real-time threat analysis endpoints
  - Security orchestration workflows
  - Incident response automation
  - Compliance reporting APIs

## Key Components

### 1. Authentication API (`/auth/*`)
```http
POST /auth/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "scope": "read:users write:users"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:users write:users"
}
```

### 2. Token Introspection (`/auth/introspect`)
```http
POST /auth/introspect
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...&token_type_hint=access_token
```

**Response:**
```json
{
  "active": true,
  "scope": "read:users write:users",
  "client_id": "your-client-id",
  "exp": 1640995200,
  "iat": 1640991600
}
```

### 3. Policy Authorization (`/policy/authorize`)
```http
POST /policy/authorize
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "principal": "user:alice",
  "action": "read",
  "resource": "document:confidential.pdf",
  "context": {
    "ip_address": "192.168.1.100",
    "time_of_day": "business_hours"
  }
}
```

## Feature Flags

The API system supports feature-based endpoint availability:

```toml
# Core API features
[features]
api-keys = []
rate-limiting = []
security-monitoring = []
threat-hunting = []
```

When features are disabled, related endpoints return `404 Not Found`.

**Base URLs:**
- **Auth Service**: `http://localhost:8001` (development) | `https://api.rust-security.com/auth` (production)
- **Policy Service**: `http://localhost:8002` (development) | `https://api.rust-security.com/policy` (production)
- **SOAR Service**: `http://localhost:8003` (development) | `https://api.rust-security.com/soar` (production)

## Authentication & Security

### Authentication Methods

**1. Bearer Token (JWT)**
```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**2. API Key**
```http
X-API-Key: your-api-key-here
```

**3. OAuth 2.0**
- Authorization Code Flow
- Client Credentials Flow
- PKCE (for public clients)

### Security Headers

All API responses include standard security headers:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

---

# Auth Service API

The Auth Service handles authentication, user management, multi-factor authentication, SCIM provisioning, and OAuth 2.0 flows.

## Core Authentication Endpoints

### POST /api/v1/auth/register

**Register a new user account**

```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "full_name": "John Doe"
}
```

**Response (201):**
```json
{
  "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
  "email": "user@example.com",
  "full_name": "John Doe",
  "email_verified": false,
  "created_at": "2025-01-28T10:30:00Z",
  "requires_mfa_setup": true
}
```

**Error Responses:**
```json
// 409 - User already exists
{
  "error": "user_exists",
  "message": "A user with this email already exists",
  "details": {
    "email": "user@example.com",
    "suggested_action": "use_password_reset"
  }
}

// 422 - Validation Error
{
  "error": "validation_failed",
  "message": "Password does not meet security requirements",
  "details": {
    "password": [
      "Must be at least 12 characters long",
      "Must contain uppercase, lowercase, number, and symbol"
    ]
  }
}
```

### POST /api/v1/auth/login

**Authenticate user with credentials**

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "remember_device": true,
  "mfa_code": "123456"
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_2N4d7Hx9Kp1mQ8fR...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
    "email": "user@example.com",
    "full_name": "John Doe",
    "roles": ["user"],
    "permissions": ["read:profile", "write:profile"]
  },
  "session": {
    "session_id": "sess_8Kx2Nv5mP9qR4tY7",
    "expires_at": "2025-01-29T10:30:00Z",
    "device_trusted": true
  }
}
```

**MFA Required Response (202):**
```json
{
  "requires_mfa": true,
  "mfa_methods": ["totp", "sms", "webauthn"],
  "challenge_token": "mfa_ch_5Qx8Nv2mP4tR9yF6",
  "backup_codes_available": 8
}
```

### GET /api/v1/auth/me

**Get current user information**

```http
GET /api/v1/auth/me
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "user": {
    "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
    "email": "user@example.com",
    "full_name": "John Doe",
    "email_verified": true,
    "phone_verified": false,
    "mfa_enabled": true,
    "created_at": "2025-01-28T10:30:00Z",
    "last_login": "2025-01-28T15:45:00Z",
    "roles": ["user", "beta_tester"],
    "permissions": [
      "read:profile",
      "write:profile",
      "read:notifications"
    ]
  },
  "security": {
    "password_last_changed": "2025-01-28T10:30:00Z",
    "active_sessions": 3,
    "trusted_devices": 2,
    "mfa_methods": ["totp", "webauthn"],
    "security_score": 85
  }
}
```

## OAuth 2.0 Endpoints

### GET /oauth/authorize

**OAuth 2.0 authorization endpoint**

```http
GET /oauth/authorize?response_type=code&client_id=demo-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=read%20write&state=xyz123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

**Response (302) - Redirect to login or consent:**
```http
Location: https://auth.rust-security.com/login?continue=%2Foauth%2Fauthorize%3Fresponse_type%3Dcode...
```

**Success Redirect (302):**
```http
Location: https://app.example.com/callback?code=auth_code_2N4d7Hx9Kp1mQ8fR&state=xyz123
```

### POST /oauth/token

**Exchange authorization code for access token**

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=auth_code_2N4d7Hx9Kp1mQ8fR&
redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&
client_id=demo-client&
client_secret=demo-secret&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Response (200):**
```json
{
  "access_token": "at_2N4d7Hx9Kp1mQ8fR...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "rt_8Kx2Nv5mP9qR4tY7...",
  "scope": "read write",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Client Credentials Flow:**
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic ZGVtby1jbGllbnQ6ZGVtby1zZWNyZXQ=

grant_type=client_credentials&scope=api:read api:write
```

## Multi-Factor Authentication (MFA)

### POST /api/v1/mfa/totp/register

**Register TOTP (Authenticator App) for MFA**

```http
POST /api/v1/mfa/totp/register
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
  "display_name": "John's Account",
  "security_level": "high"
}
```

**Response (200):**
```json
{
  "secret_base32": "JBSWY3DPEHPK3PXP",
  "otpauth_url": "otpauth://totp/Rust%20Security:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Rust%20Security",
  "qr_code_data_url": "data:image/png;base64,iVBORw0KGgoAAAANSUhE...",
  "backup_codes": [
    "1a2b-3c4d",
    "5e6f-7g8h",
    "9i0j-1k2l"
  ],
  "recovery_codes": 8
}
```

### POST /api/v1/mfa/totp/verify

**Verify TOTP code**

```http
POST /api/v1/mfa/totp/verify
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
  "code": "123456",
  "remember_device": true
}
```

**Response (200):**
```json
{
  "verified": true,
  "session_timeout": 86400,
  "requires_step_up": false,
  "backup_codes_remaining": 7,
  "device_trusted": true
}
```

**Failed Verification (401):**
```json
{
  "verified": false,
  "reason": "invalid_code",
  "attempts_remaining": 4,
  "lockout_time": 300,
  "alternative_methods": ["backup_code", "webauthn"]
}
```

## WebAuthn (FIDO2) Authentication

### POST /api/v1/webauthn/register/begin

**Begin WebAuthn registration**

```http
POST /api/v1/webauthn/register/begin
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
  "username": "user@example.com"
}
```

**Response (200):**
```json
{
  "public_key": {
    "rp": {
      "id": "rust-security.com",
      "name": "Rust Security Platform"
    },
    "user": {
      "id": "dXNyXzJONGQ3SHg5S3AxbVE4ZlI",
      "name": "user@example.com",
      "displayName": "John Doe"
    },
    "challenge": "Y2hhbGxlbmdlLWRhdGEtaGVyZQ",
    "pubKeyCredParams": [
      {"type": "public-key", "alg": -7},
      {"type": "public-key", "alg": -257}
    ],
    "timeout": 60000,
    "attestation": "none",
    "authenticatorSelection": {
      "userVerification": "preferred",
      "requireResidentKey": false
    },
    "extensions": {
      "credProps": true
    }
  }
}
```

### POST /api/v1/webauthn/register/finish

**Complete WebAuthn registration**

```http
POST /api/v1/webauthn/register/finish
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
  "credential": {
    "id": "credential-id-here",
    "rawId": "Y3JlZGVudGlhbC1pZC1oZXJl",
    "response": {
      "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAFGNyZWRlbnRpYWwtaWQtaGVyZaUBAgMmIAEhWCA...",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWTJoaGJHeGxibWRsWkdGMFlTMW9aWEpsIiwib3JpZ2luIjoiaHR0cHM6Ly9ydXN0LXNlY3VyaXR5LmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
    },
    "type": "public-key"
  }
}
```

**Response (200):**
```json
{
  "registered": true,
  "credential_id": "credential-id-here",
  "nickname": "Chrome on MacBook Pro",
  "created_at": "2025-01-28T10:30:00Z"
}
```

## SCIM 2.0 User Provisioning

### POST /scim/v2/Users

**Create user via SCIM**

```http
POST /scim/v2/Users
Content-Type: application/scim+json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "bjensen@example.com",
  "name": {
    "formatted": "Ms. Barbara J Jensen III",
    "familyName": "Jensen",
    "givenName": "Barbara",
    "middleName": "Jane"
  },
  "displayName": "Babs Jensen",
  "emails": [
    {
      "value": "bjensen@example.com",
      "type": "work",
      "primary": true
    }
  ],
  "phoneNumbers": [
    {
      "value": "+1-555-555-8377",
      "type": "work"
    }
  ],
  "active": true,
  "groups": [
    {
      "value": "group-id-1",
      "display": "Engineers"
    }
  ]
}
```

**Response (201):**
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "scim_user_2N4d7Hx9Kp1mQ8fR",
  "externalId": "bjensen",
  "userName": "bjensen@example.com",
  "name": {
    "formatted": "Ms. Barbara J Jensen III",
    "familyName": "Jensen",
    "givenName": "Barbara",
    "middleName": "Jane"
  },
  "displayName": "Babs Jensen",
  "emails": [
    {
      "value": "bjensen@example.com",
      "type": "work",
      "primary": true
    }
  ],
  "phoneNumbers": [
    {
      "value": "+1-555-555-8377",
      "type": "work"
    }
  ],
  "active": true,
  "groups": [
    {
      "value": "group-id-1",
      "display": "Engineers"
    }
  ],
  "meta": {
    "resourceType": "User",
    "created": "2025-01-28T10:30:00Z",
    "lastModified": "2025-01-28T10:30:00Z",
    "location": "https://api.rust-security.com/scim/v2/Users/scim_user_2N4d7Hx9Kp1mQ8fR",
    "version": "W/\"1\""
  }
}
```

### GET /scim/v2/Users

**List users with filtering and pagination**

```http
GET /scim/v2/Users?startIndex=1&count=10&filter=userName+eq+"bjensen@example.com"
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 1,
  "itemsPerPage": 10,
  "startIndex": 1,
  "Resources": [
    {
      "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
      "id": "scim_user_2N4d7Hx9Kp1mQ8fR",
      "userName": "bjensen@example.com",
      "displayName": "Babs Jensen",
      "active": true,
      "meta": {
        "resourceType": "User",
        "created": "2025-01-28T10:30:00Z",
        "lastModified": "2025-01-28T10:30:00Z"
      }
    }
  ]
}
```

## Session Management

### GET /api/v1/sessions

**List active user sessions**

```http
GET /api/v1/sessions?page=1&limit=20
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "sessions": [
    {
      "session_id": "sess_8Kx2Nv5mP9qR4tY7",
      "device_info": {
        "type": "desktop",
        "os": "macOS 14.2",
        "browser": "Chrome 120.0.0",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)..."
      },
      "location": {
        "ip_address": "192.168.1.100",
        "country": "US",
        "city": "San Francisco",
        "approximate": true
      },
      "created_at": "2025-01-28T10:30:00Z",
      "last_activity": "2025-01-28T15:45:00Z",
      "expires_at": "2025-02-11T10:30:00Z",
      "is_current": true,
      "trusted_device": true
    },
    {
      "session_id": "sess_3Yt9Bx6nM2pQ5sF8",
      "device_info": {
        "type": "mobile",
        "os": "iOS 17.2",
        "browser": "Safari 17.2",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)..."
      },
      "location": {
        "ip_address": "10.0.0.50",
        "country": "US",
        "city": "New York",
        "approximate": true
      },
      "created_at": "2025-01-27T14:20:00Z",
      "last_activity": "2025-01-28T09:15:00Z",
      "expires_at": "2025-02-10T14:20:00Z",
      "is_current": false,
      "trusted_device": false
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 2,
    "total_pages": 1
  }
}
```

### DELETE /api/v1/sessions/{sessionId}

**Revoke a specific session**

```http
DELETE /api/v1/sessions/sess_3Yt9Bx6nM2pQ5sF8
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (204):**
```
HTTP/1.1 204 No Content
```

---

# Policy Service API

The Policy Service handles Cedar policy evaluation, authorization decisions, and policy management using Amazon's Cedar policy language.

## Authorization Endpoints

### POST /v1/authorize

**Evaluate authorization request against policies**

```http
POST /v1/authorize
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "request_id": "req_2N4d7Hx9Kp1mQ8fR",
  "principal": {
    "type": "User",
    "id": "user_alice"
  },
  "action": {
    "type": "Action",
    "id": "Document::Read"
  },
  "resource": {
    "type": "Document",
    "id": "doc_confidential_report"
  },
  "context": {
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "timestamp": "2025-01-28T15:45:00Z",
    "device_trusted": true,
    "mfa_verified": true,
    "security_clearance": "secret"
  }
}
```

**Response (200) - Allow:**
```json
{
  "decision": "Allow",
  "request_id": "req_2N4d7Hx9Kp1mQ8fR",
  "evaluation_time_ms": 15.2,
  "applied_policies": [
    {
      "policy_id": "policy_document_access",
      "policy_name": "Document Access Control",
      "effect": "allow",
      "conditions_matched": [
        "user has security clearance >= secret",
        "device is trusted",
        "MFA verified within last hour"
      ]
    }
  ],
  "reasons": [
    "User alice has sufficient security clearance for secret documents",
    "Device is registered and trusted",
    "Multi-factor authentication verified"
  ]
}
```

**Response (200) - Deny:**
```json
{
  "decision": "Deny",
  "request_id": "req_2N4d7Hx9Kp1mQ8fR",
  "evaluation_time_ms": 12.8,
  "applied_policies": [
    {
      "policy_id": "policy_time_based_access",
      "policy_name": "Business Hours Access",
      "effect": "deny",
      "conditions_matched": [
        "current time outside business hours",
        "resource classified as sensitive"
      ]
    }
  ],
  "reasons": [
    "Access denied: Current time (23:45 UTC) is outside allowed business hours (09:00-17:00 UTC)",
    "Resource classification 'sensitive' requires business hours access"
  ],
  "suggestions": [
    "Request emergency access override",
    "Wait until business hours (next: 09:00 UTC)",
    "Use non-sensitive alternative resource"
  ]
}
```

### POST /v1/authorize/batch

**Batch authorization evaluation for multiple requests**

```http
POST /v1/authorize/batch
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "requests": [
    {
      "id": "req_1",
      "principal": {"type": "User", "id": "user_alice"},
      "action": {"type": "Action", "id": "Document::Read"},
      "resource": {"type": "Document", "id": "doc_1"},
      "context": {"security_clearance": "secret"}
    },
    {
      "id": "req_2",
      "principal": {"type": "User", "id": "user_alice"},
      "action": {"type": "Action", "id": "Document::Write"},
      "resource": {"type": "Document", "id": "doc_1"},
      "context": {"security_clearance": "secret"}
    }
  ]
}
```

**Response (200):**
```json
{
  "results": [
    {
      "request_id": "req_1",
      "decision": "Allow",
      "evaluation_time_ms": 8.5
    },
    {
      "request_id": "req_2",
      "decision": "Deny",
      "evaluation_time_ms": 6.2,
      "reasons": ["Write access requires top-secret clearance"]
    }
  ],
  "total_time_ms": 14.7,
  "summary": {
    "total_requests": 2,
    "allowed": 1,
    "denied": 1,
    "errors": 0
  }
}
```

## Policy Management

### GET /v1/policies

**List all policies with filtering**

```http
GET /v1/policies?type=RBAC&status=active&search=document&page=1&limit=20
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "policies": [
    {
      "id": "pol_2N4d7Hx9Kp1mQ8fR",
      "name": "Document Access Control",
      "description": "Controls access to classified documents based on security clearance",
      "type": "ABAC",
      "status": "active",
      "version": 3,
      "created_at": "2025-01-20T10:30:00Z",
      "updated_at": "2025-01-28T15:45:00Z",
      "created_by": "admin@example.com",
      "tags": ["security", "classification", "documents"],
      "rules_count": 5,
      "evaluations_count": 1250
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  }
}
```

### POST /v1/policies

**Create a new policy**

```http
POST /v1/policies
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "name": "API Rate Limiting Policy",
  "description": "Enforces rate limits on API endpoints",
  "type": "ABAC",
  "rules": [
    {
      "name": "Basic Rate Limit",
      "description": "Standard users get 1000 requests per hour",
      "effect": "allow",
      "priority": 100,
      "conditions": [
        {
          "type": "attribute",
          "field": "user.subscription",
          "operator": "eq",
          "value": "basic"
        },
        {
          "type": "context",
          "field": "request_count_1h",
          "operator": "lte",
          "value": 1000
        }
      ],
      "resources": ["api/*"],
      "actions": ["read", "write"]
    },
    {
      "name": "Premium Rate Limit",
      "description": "Premium users get 10000 requests per hour",
      "effect": "allow",
      "priority": 90,
      "conditions": [
        {
          "type": "attribute",
          "field": "user.subscription",
          "operator": "eq",
          "value": "premium"
        },
        {
          "type": "context",
          "field": "request_count_1h",
          "operator": "lte",
          "value": 10000
        }
      ],
      "resources": ["api/*"],
      "actions": ["read", "write"]
    }
  ],
  "tags": ["rate-limiting", "api", "subscription"]
}
```

**Response (201):**
```json
{
  "policy": {
    "id": "pol_8Kx2Nv5mP9qR4tY7",
    "name": "API Rate Limiting Policy",
    "description": "Enforces rate limits on API endpoints",
    "type": "ABAC",
    "status": "draft",
    "version": 1,
    "created_at": "2025-01-28T16:00:00Z",
    "updated_at": "2025-01-28T16:00:00Z",
    "created_by": "admin@example.com",
    "tags": ["rate-limiting", "api", "subscription"],
    "rules": [
      {
        "id": "rule_3Yt9Bx6nM2pQ5sF8",
        "name": "Basic Rate Limit",
        "description": "Standard users get 1000 requests per hour",
        "effect": "allow",
        "priority": 100
      },
      {
        "id": "rule_7Qw5Cx8mN4sR9vG2",
        "name": "Premium Rate Limit",
        "description": "Premium users get 10000 requests per hour",
        "effect": "allow",
        "priority": 90
      }
    ]
  }
}
```

### PUT /v1/policies/{policyId}

**Update an existing policy**

```http
PUT /v1/policies/pol_8Kx2Nv5mP9qR4tY7
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "name": "Enhanced API Rate Limiting Policy",
  "description": "Updated rate limits with enterprise tier support",
  "rules": [
    {
      "name": "Enterprise Rate Limit",
      "description": "Enterprise users get unlimited requests",
      "effect": "allow",
      "priority": 80,
      "conditions": [
        {
          "type": "attribute",
          "field": "user.subscription",
          "operator": "eq",
          "value": "enterprise"
        }
      ],
      "resources": ["api/*"],
      "actions": ["read", "write", "admin"]
    }
  ],
  "tags": ["rate-limiting", "api", "subscription", "enterprise"]
}
```

### POST /v1/policies/{policyId}/activate

**Activate a draft policy**

```http
POST /v1/policies/pol_8Kx2Nv5mP9qR4tY7/activate
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "policy": {
    "id": "pol_8Kx2Nv5mP9qR4tY7",
    "name": "Enhanced API Rate Limiting Policy",
    "status": "active",
    "version": 2,
    "activated_at": "2025-01-28T16:15:00Z"
  }
}
```

## Policy Simulation & Testing

### Simulation (Future)

The legacy simulation endpoint is not part of the current MVP. Policy decisions should be obtained via `POST /v1/authorize`.

```http
# Placeholder; simulation API not available in MVP
# POST /v1/authorize/simulate (future)
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "policy": {
    "name": "Test Time-Based Access",
    "type": "ABAC",
    "rules": [
      {
        "name": "Business Hours Only",
        "effect": "allow",
        "conditions": [
          {
            "type": "time",
            "field": "current_hour",
            "operator": "gte",
            "value": 9
          },
          {
            "type": "time",
            "field": "current_hour",
            "operator": "lt",
            "value": 17
          }
        ],
        "resources": ["sensitive/*"],
        "actions": ["read", "write"]
      }
    ]
  },
  "evaluation_request": {
    "principal": {"type": "User", "id": "test_user"},
    "action": {"type": "Action", "id": "Document::Read"},
    "resource": {"type": "Document", "id": "sensitive/report"},
    "context": {
      "current_hour": 14,
      "timezone": "UTC"
    }
  }
}
```

**Response (200):**
```json
{
  "result": {
    "decision": "Allow",
    "evaluation_time_ms": 3.2,
    "applied_policies": [
      {
        "policy_name": "Test Time-Based Access",
        "effect": "allow"
      }
    ]
  },
  "trace": [
    {
      "step": 1,
      "rule_id": "temp_rule_1",
      "rule_name": "Business Hours Only",
      "matched": true,
      "details": "Time condition met: 14 >= 9 and 14 < 17"
    }
  ],
  "debug_info": {
    "context_evaluation": {
      "current_hour": "14 (valid integer)",
      "timezone": "UTC (valid timezone)"
    },
    "condition_results": [
      {
        "condition": "current_hour >= 9",
        "result": true,
        "evaluated_value": 14
      },
      {
        "condition": "current_hour < 17",
        "result": true,
        "evaluated_value": 14
      }
    ]
  }
}
```

---

# SOAR & Threat Detection API

The SOAR (Security Orchestration, Automation, and Response) service handles security incidents, threat detection, and automated response workflows.

## Incident Management

### POST /api/v1/incidents

**Create a new security incident**

```http
POST /api/v1/incidents
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "title": "Suspicious Login Activity Detected",
  "description": "Multiple failed login attempts from unusual geographic locations",
  "severity": "medium",
  "category": "authentication_anomaly",
  "source": "auth_monitoring_system",
  "affected_assets": [
    {
      "type": "user_account",
      "identifier": "user@example.com",
      "criticality": "high"
    },
    {
      "type": "ip_address",
      "identifier": "203.0.113.45",
      "location": "Unknown"
    }
  ],
  "evidence": [
    {
      "type": "log_entry",
      "timestamp": "2025-01-28T15:30:00Z",
      "source": "auth-service",
      "data": {
        "event": "login_failed",
        "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
        "ip_address": "203.0.113.45",
        "user_agent": "curl/7.68.0",
        "failure_reason": "invalid_password"
      }
    }
  ],
  "context": {
    "detection_method": "behavioral_analysis",
    "confidence_score": 0.85,
    "risk_score": 75,
    "tags": ["brute_force", "geographic_anomaly", "automated_tool"]
  }
}
```

**Response (201):**
```json
{
  "incident": {
    "incident_id": "inc_2N4d7Hx9Kp1mQ8fR",
    "title": "Suspicious Login Activity Detected",
    "description": "Multiple failed login attempts from unusual geographic locations",
    "severity": "medium",
    "category": "authentication_anomaly",
    "status": "open",
    "priority": "P2",
    "created_at": "2025-01-28T16:00:00Z",
    "updated_at": "2025-01-28T16:00:00Z",
    "created_by": "system:threat_detection",
    "assigned_to": null,
    "sla": {
      "response_time_hours": 4,
      "resolution_time_hours": 24,
      "due_date": "2025-01-29T16:00:00Z"
    },
    "workflow_status": {
      "current_step": "initial_assessment",
      "automated_actions": [
        {
          "action": "account_monitoring",
          "status": "initiated",
          "timestamp": "2025-01-28T16:00:05Z"
        },
        {
          "action": "ip_reputation_check",
          "status": "completed",
          "result": "malicious_ip_confirmed",
          "timestamp": "2025-01-28T16:00:12Z"
        }
      ]
    }
  }
}
```

### GET /api/v1/incidents

**List security incidents with filtering**

```http
GET /api/v1/incidents?severity=high,medium&status=open&assigned_to=analyst1&from=2025-01-01T00:00:00Z&to=2025-01-28T23:59:59Z&page=1&limit=20
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "incidents": [
    {
      "incident_id": "inc_2N4d7Hx9Kp1mQ8fR",
      "title": "Suspicious Login Activity Detected",
      "severity": "medium",
      "category": "authentication_anomaly",
      "status": "open",
      "priority": "P2",
      "created_at": "2025-01-28T16:00:00Z",
      "updated_at": "2025-01-28T16:00:00Z",
      "assigned_to": "analyst1@security.com",
      "affected_assets_count": 2,
      "evidence_count": 5,
      "time_to_resolve_hours": null,
      "tags": ["brute_force", "geographic_anomaly"]
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 1,
    "total_pages": 1
  },
  "summary": {
    "total_open": 15,
    "total_in_progress": 8,
    "total_resolved": 342,
    "severity_breakdown": {
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 2
    }
  }
}
```

### PUT /api/v1/incidents/{incidentId}

**Update incident details**

```http
PUT /api/v1/incidents/inc_2N4d7Hx9Kp1mQ8fR
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "severity": "high",
  "assigned_to": "senior_analyst@security.com",
  "status": "in_progress",
  "notes": "Confirmed malicious activity. Escalating to senior analyst.",
  "additional_evidence": [
    {
      "type": "threat_intelligence",
      "source": "external_feed",
      "data": {
        "ip_reputation": {
          "ip": "203.0.113.45",
          "reputation_score": 95,
          "categories": ["botnet", "brute_force"],
          "first_seen": "2025-01-20T00:00:00Z",
          "last_seen": "2025-01-28T15:45:00Z"
        }
      }
    }
  ]
}
```

**Response (200):**
```json
{
  "incident": {
    "incident_id": "inc_2N4d7Hx9Kp1mQ8fR",
    "severity": "high",
    "status": "in_progress",
    "assigned_to": "senior_analyst@security.com",
    "updated_at": "2025-01-28T16:30:00Z",
    "priority": "P1",
    "sla": {
      "response_time_hours": 1,
      "resolution_time_hours": 8,
      "due_date": "2025-01-29T00:00:00Z"
    }
  }
}
```

## Playbook Automation

### POST /api/v1/playbooks/{playbookId}/execute

**Execute a security response playbook**

```http
POST /api/v1/playbooks/pb_incident_response_auth_anomaly/execute
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "incident_id": "inc_2N4d7Hx9Kp1mQ8fR",
  "execution_mode": "automated",
  "parameters": {
    "affected_user": "user@example.com",
    "source_ip": "203.0.113.45",
    "block_ip": true,
    "notify_user": true,
    "require_password_reset": true
  },
  "approvals_required": false
}
```

**Response (202):**
```json
{
  "execution": {
    "execution_id": "exec_8Kx2Nv5mP9qR4tY7",
    "playbook_id": "pb_incident_response_auth_anomaly",
    "playbook_name": "Authentication Anomaly Response",
    "incident_id": "inc_2N4d7Hx9Kp1mQ8fR",
    "status": "running",
    "execution_mode": "automated",
    "started_at": "2025-01-28T16:45:00Z",
    "estimated_completion": "2025-01-28T16:50:00Z",
    "current_step": {
      "step_number": 2,
      "step_name": "Block Malicious IP",
      "status": "running",
      "started_at": "2025-01-28T16:45:30Z"
    },
    "completed_steps": [
      {
        "step_number": 1,
        "step_name": "Gather Additional Evidence",
        "status": "completed",
        "started_at": "2025-01-28T16:45:00Z",
        "completed_at": "2025-01-28T16:45:25Z",
        "result": "success",
        "output": {
          "evidence_collected": 3,
          "threat_score_updated": 85
        }
      }
    ],
    "pending_steps": [
      {
        "step_number": 3,
        "step_name": "Notify Affected User",
        "estimated_start": "2025-01-28T16:46:00Z"
      },
      {
        "step_number": 4,
        "step_name": "Force Password Reset",
        "estimated_start": "2025-01-28T16:47:00Z"
      }
    ]
  }
}
```

### GET /api/v1/playbooks/{playbookId}/executions/{executionId}

**Get playbook execution status**

```http
GET /api/v1/playbooks/pb_incident_response_auth_anomaly/executions/exec_8Kx2Nv5mP9qR4tY7
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "execution": {
    "execution_id": "exec_8Kx2Nv5mP9qR4tY7",
    "playbook_id": "pb_incident_response_auth_anomaly",
    "status": "completed",
    "result": "success",
    "started_at": "2025-01-28T16:45:00Z",
    "completed_at": "2025-01-28T16:48:30Z",
    "duration_seconds": 210,
    "steps_completed": 4,
    "steps_total": 4,
    "steps": [
      {
        "step_number": 1,
        "step_name": "Gather Additional Evidence",
        "status": "completed",
        "result": "success",
        "duration_seconds": 25,
        "output": {
          "evidence_collected": 3,
          "threat_intelligence_queries": 2,
          "risk_score": 85
        }
      },
      {
        "step_number": 2,
        "step_name": "Block Malicious IP",
        "status": "completed",
        "result": "success",
        "duration_seconds": 35,
        "output": {
          "ip_blocked": "203.0.113.45",
          "firewall_rules_updated": 3,
          "block_duration_hours": 24
        }
      },
      {
        "step_number": 3,
        "step_name": "Notify Affected User",
        "status": "completed",
        "result": "success",
        "duration_seconds": 15,
        "output": {
          "notification_sent": true,
          "notification_method": "email",
          "user_acknowledged": false
        }
      },
      {
        "step_number": 4,
        "step_name": "Force Password Reset",
        "status": "completed",
        "result": "success",
        "duration_seconds": 10,
        "output": {
          "password_reset_token_sent": true,
          "account_temporarily_locked": true,
          "unlock_requires_verification": true
        }
      }
    ],
    "metrics": {
      "incident_resolution_improvement": "180 seconds faster than manual process",
      "actions_automated": 4,
      "human_interventions": 0,
      "cost_savings_estimated": "$450"
    }
  }
}
```

## Threat Intelligence

### GET /api/v1/threat-intelligence/indicators

**Get threat intelligence indicators**

```http
GET /api/v1/threat-intelligence/indicators?type=ip,domain&confidence=high&active=true&page=1&limit=50
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "indicators": [
    {
      "indicator_id": "ind_2N4d7Hx9Kp1mQ8fR",
      "type": "ip",
      "value": "203.0.113.45",
      "confidence": "high",
      "threat_types": ["botnet", "brute_force", "malware_c2"],
      "severity": "high",
      "first_seen": "2025-01-20T00:00:00Z",
      "last_seen": "2025-01-28T16:45:00Z",
      "sources": [
        {
          "name": "threat_feed_provider_a",
          "reputation": 95,
          "last_updated": "2025-01-28T16:00:00Z"
        },
        {
          "name": "internal_honeypot",
          "reputation": 100,
          "last_updated": "2025-01-28T16:45:00Z"
        }
      ],
      "context": {
        "geolocation": {
          "country": "Unknown",
          "asn": "AS64512",
          "organization": "Suspicious Hosting Ltd"
        },
        "attack_patterns": [
          "T1110.001", // Brute Force: Password Guessing
          "T1078.001"  // Valid Accounts: Default Accounts
        ],
        "campaigns": ["campaign_auth_bruteforce_2025_01"]
      },
      "actions_taken": [
        {
          "action": "blocked_at_firewall",
          "timestamp": "2025-01-28T16:45:30Z",
          "duration_hours": 24
        }
      ],
      "expires_at": "2025-02-28T00:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 1,
    "total_pages": 1
  },
  "summary": {
    "total_active_indicators": 15642,
    "by_type": {
      "ip": 8924,
      "domain": 4521,
      "hash": 1897,
      "url": 300
    },
    "by_confidence": {
      "high": 12453,
      "medium": 2847,
      "low": 342
    }
  }
}
```

### POST /api/v1/threat-intelligence/indicators

**Add new threat intelligence indicator**

```http
POST /api/v1/threat-intelligence/indicators
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "type": "domain",
  "value": "malicious-example.com",
  "confidence": "high",
  "threat_types": ["phishing", "malware_hosting"],
  "severity": "medium",
  "source": "internal_analysis",
  "context": {
    "description": "Domain hosting phishing pages targeting our users",
    "attack_patterns": ["T1566.002"], // Phishing: Spearphishing Link
    "ttps": [
      {
        "technique": "T1566.002",
        "tactic": "Initial Access",
        "description": "Spearphishing link targeting employee credentials"
      }
    ],
    "related_campaigns": ["phishing_wave_2025_01"]
  },
  "expires_at": "2025-07-28T00:00:00Z",
  "action_recommended": "block"
}
```

**Response (201):**
```json
{
  "indicator": {
    "indicator_id": "ind_8Kx2Nv5mP9qR4tY7",
    "type": "domain",
    "value": "malicious-example.com",
    "confidence": "high",
    "threat_types": ["phishing", "malware_hosting"],
    "severity": "medium",
    "created_at": "2025-01-28T17:00:00Z",
    "created_by": "analyst@security.com",
    "status": "active",
    "automatic_actions": [
      {
        "action": "dns_sinkhole",
        "status": "initiated",
        "timestamp": "2025-01-28T17:00:05Z"
      },
      {
        "action": "email_filter_update",
        "status": "completed",
        "timestamp": "2025-01-28T17:00:15Z"
      }
    ]
  }
}
```

## Behavioral Analysis

### GET /api/v1/behavioral-analysis/users/{userId}/profile

**Get user behavioral analysis profile**

```http
GET /api/v1/behavioral-analysis/users/usr_2N4d7Hx9Kp1mQ8fR/profile
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200):**
```json
{
  "user_profile": {
    "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
    "profile_created": "2025-01-15T00:00:00Z",
    "last_updated": "2025-01-28T17:00:00Z",
    "baseline_established": true,
    "risk_score": 25,
    "risk_level": "low",
    "patterns": {
      "login_times": {
        "typical_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
        "typical_days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
        "timezone": "America/New_York"
      },
      "locations": {
        "frequent_locations": [
          {
            "city": "New York",
            "country": "US",
            "frequency": 0.85,
            "ip_ranges": ["192.168.1.0/24", "10.0.0.0/8"]
          }
        ],
        "travel_pattern": "low_mobility"
      },
      "devices": {
        "trusted_devices": [
          {
            "device_fingerprint": "dev_Abc123Def456",
            "device_type": "desktop",
            "os": "macOS 14.2",
            "browser": "Chrome 120.0.0",
            "frequency": 0.90,
            "last_seen": "2025-01-28T16:45:00Z"
          }
        ],
        "device_consistency": "high"
      },
      "activity_patterns": {
        "typical_session_duration_minutes": 120,
        "typical_actions_per_session": 25,
        "preferred_features": ["dashboard", "reports", "profile"],
        "activity_rhythm": "consistent"
      }
    },
    "anomalies_detected": [
      {
        "anomaly_type": "unusual_login_time",
        "detected_at": "2025-01-28T02:30:00Z",
        "severity": "low",
        "description": "Login at 02:30 is outside typical hours (08:00-17:00)",
        "resolved": true,
        "resolution": "User confirmed legitimate late-night work session"
      }
    ],
    "learning_status": {
      "data_points_collected": 1250,
      "confidence_score": 0.92,
      "model_accuracy": 0.88,
      "last_model_update": "2025-01-28T00:00:00Z"
    }
  }
}
```

### POST /api/v1/behavioral-analysis/evaluate

**Evaluate current activity against behavioral baseline**

```http
POST /api/v1/behavioral-analysis/evaluate
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
  "activity": {
    "timestamp": "2025-01-28T23:45:00Z",
    "action": "login",
    "source_ip": "203.0.113.45",
    "user_agent": "curl/7.68.0",
    "location": {
      "country": "RO",
      "city": "Bucharest"
    },
    "device_fingerprint": "unknown"
  },
  "context": {
    "authentication_method": "password_only",
    "session_requested": true,
    "previous_failed_attempts": 15
  }
}
```

**Response (200):**
```json
{
  "evaluation_result": {
    "risk_score": 95,
    "risk_level": "critical",
    "anomalies_detected": [
      {
        "type": "unusual_time",
        "severity": "medium",
        "description": "Login at 23:45 UTC is 6+ hours outside typical schedule",
        "confidence": 0.85
      },
      {
        "type": "geographic_impossible_travel",
        "severity": "high",
        "description": "Geographic location (Bucharest, RO) impossible given last location (New York, US) 2 hours ago",
        "confidence": 0.98
      },
      {
        "type": "suspicious_user_agent",
        "severity": "high",
        "description": "User agent 'curl/7.68.0' inconsistent with typical browser usage",
        "confidence": 0.92
      },
      {
        "type": "unknown_device",
        "severity": "medium",
        "description": "Device fingerprint not recognized from user's trusted devices",
        "confidence": 0.78
      }
    ],
    "recommended_actions": [
      {
        "action": "block_login",
        "priority": "immediate",
        "reasoning": "Multiple critical risk indicators suggest compromised credentials"
      },
      {
        "action": "require_additional_authentication",
        "priority": "high",
        "reasoning": "If login is legitimate, additional verification is essential"
      },
      {
        "action": "notify_security_team",
        "priority": "high",
        "reasoning": "Pattern indicates potential account takeover"
      },
      {
        "action": "force_password_reset",
        "priority": "medium",
        "reasoning": "Precautionary measure if account compromise is suspected"
      }
    ],
    "confidence": 0.94,
    "evaluation_time_ms": 45.2
  }
}
```

---

# SDK Integration Guides

## TypeScript/Node.js SDK

### Installation

```bash
npm install @rust-security/sdk
```

### Basic Setup

```typescript
import { RustSecuritySDK, AuthService, PolicyService, SoarService } from '@rust-security/sdk';

const sdk = new RustSecuritySDK({
  baseUrl: 'https://api.rust-security.com',
  apiKey: process.env.RUST_SECURITY_API_KEY,
  // Optional: Custom timeouts and retry configuration
  timeout: 30000,
  retries: 3,
  retryDelay: 1000
});

// Access individual services
const auth = sdk.auth;
const policy = sdk.policy;
const soar = sdk.soar;
```

### Authentication Examples

```typescript
// User registration
try {
  const user = await auth.register({
    email: 'user@example.com',
    password: 'SecurePassword123!',
    fullName: 'John Doe'
  });
  
  console.log('User registered:', user.userId);
} catch (error) {
  if (error.code === 'USER_EXISTS') {
    console.log('User already exists, redirect to login');
  } else if (error.code === 'VALIDATION_FAILED') {
    console.log('Validation errors:', error.details);
  }
  throw error;
}

// User login with MFA handling
try {
  const loginResult = await auth.login({
    email: 'user@example.com',
    password: 'SecurePassword123!',
    rememberDevice: true
  });
  
  if (loginResult.requiresMfa) {
    // Handle MFA challenge
    const mfaCode = await promptUserForMfaCode();
    const finalResult = await auth.completeMfaChallenge({
      challengeToken: loginResult.challengeToken,
      mfaCode: mfaCode,
      mfaMethod: 'totp'
    });
    
    // Store tokens securely
    secureStorage.setTokens(finalResult.accessToken, finalResult.refreshToken);
  } else {
    // Direct login success
    secureStorage.setTokens(loginResult.accessToken, loginResult.refreshToken);
  }
} catch (error) {
  console.error('Login failed:', error.message);
}

// OAuth 2.0 Authorization Code Flow
const authUrl = auth.getAuthorizationUrl({
  clientId: 'your-client-id',
  redirectUri: 'https://your-app.com/callback',
  scope: ['read', 'write'],
  state: 'random-state-value',
  codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  codeChallengeMethod: 'S256'
});

// Redirect user to authUrl, then handle callback
const tokens = await auth.exchangeCodeForTokens({
  code: 'auth_code_from_callback',
  redirectUri: 'https://your-app.com/callback',
  codeVerifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
});
```

### Policy Evaluation Examples

```typescript
// Simple authorization check
const isAuthorized = await policy.authorize({
  principal: { type: 'User', id: 'user_alice' },
  action: { type: 'Action', id: 'Document::Read' },
  resource: { type: 'Document', id: 'doc_confidential_report' },
  context: {
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    timestamp: new Date().toISOString(),
    mfaVerified: true
  }
});

if (isAuthorized.decision === 'Allow') {
  // Proceed with action
  return await getConfidentialDocument('doc_confidential_report');
} else {
  throw new Error(`Access denied: ${isAuthorized.reasons.join(', ')}`);
}

// Batch authorization for multiple resources
const batchRequests = documents.map(doc => ({
  id: doc.id,
  principal: { type: 'User', id: currentUserId },
  action: { type: 'Action', id: 'Document::Read' },
  resource: { type: 'Document', id: doc.id },
  context: { securityClearance: userClearance }
}));

const batchResults = await policy.batchAuthorize({ requests: batchRequests });

const authorizedDocuments = documents.filter(doc => {
  const result = batchResults.results.find(r => r.requestId === doc.id);
  return result && result.decision === 'Allow';
});
```

### SOAR Integration Examples

```typescript
// Create security incident
const incident = await soar.incidents.create({
  title: 'Suspicious API Activity Detected',
  description: 'Unusual API usage patterns detected for user account',
  severity: 'medium',
  category: 'api_abuse',
  affectedAssets: [
    {
      type: 'user_account',
      identifier: 'user@example.com',
      criticality: 'high'
    }
  ],
  evidence: [
    {
      type: 'api_log',
      timestamp: new Date().toISOString(),
      source: 'api-gateway',
      data: {
        endpoint: '/api/v1/sensitive-data',
        method: 'GET',
        responseSize: 1024000, // 1MB
        requestsInLastHour: 500
      }
    }
  ],
  context: {
    detectionMethod: 'rate_limiting_exceeded',
    confidenceScore: 0.78,
    riskScore: 65
  }
});

console.log('Incident created:', incident.incidentId);

// Execute automated response playbook
const execution = await soar.playbooks.execute('pb_api_abuse_response', {
  incidentId: incident.incidentId,
  executionMode: 'automated',
  parameters: {
    affectedUser: 'user@example.com',
    temporaryBlock: true,
    notifyUser: true
  }
});

// Monitor playbook execution
const executionStatus = await soar.playbooks.getExecutionStatus(
  'pb_api_abuse_response',
  execution.executionId
);

console.log('Playbook status:', executionStatus.status);
console.log('Completed steps:', executionStatus.stepsCompleted);

// Get threat intelligence for IP address
const threatInfo = await soar.threatIntelligence.getIndicators({
  type: 'ip',
  value: '203.0.113.45'
});

if (threatInfo.indicators.length > 0) {
  const indicator = threatInfo.indicators[0];
  console.log(`IP ${indicator.value} threat score: ${indicator.severity}`);
  console.log('Threat types:', indicator.threatTypes.join(', '));
}
```

### Error Handling and Retry Logic

```typescript
import { RustSecurityError, RateLimitError, AuthenticationError } from '@rust-security/sdk';

try {
  const result = await auth.login(credentials);
} catch (error) {
  if (error instanceof RateLimitError) {
    // Handle rate limiting
    const retryAfter = error.retryAfter;
    console.log(`Rate limited. Retry after ${retryAfter} seconds`);
    
    // Wait and retry
    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
    return await auth.login(credentials);
    
  } else if (error instanceof AuthenticationError) {
    // Handle authentication failures
    if (error.code === 'INVALID_CREDENTIALS') {
      throw new Error('Invalid username or password');
    } else if (error.code === 'MFA_REQUIRED') {
      // Handle MFA flow
      return await handleMfaChallenge(error.challengeToken);
    }
    
  } else if (error instanceof RustSecurityError) {
    // Handle other API errors
    console.error('API Error:', error.message);
    console.error('Error code:', error.code);
    console.error('Request ID:', error.requestId);
    
    // Optionally implement custom retry logic
    if (error.isRetryable) {
      return await retryWithExponentialBackoff(() => auth.login(credentials));
    }
  }
  
  throw error;
}
```

## Python SDK

### Installation

```bash
pip install rust-security-sdk
```

### Basic Setup

```python
from rust_security_sdk import RustSecuritySDK
from rust_security_sdk.exceptions import (
    RustSecurityError, 
    AuthenticationError, 
    RateLimitError
)
import os

sdk = RustSecuritySDK(
    base_url='https://api.rust-security.com',
    api_key=os.getenv('RUST_SECURITY_API_KEY'),
    timeout=30,
    max_retries=3
)

# Access services
auth = sdk.auth
policy = sdk.policy
soar = sdk.soar
```

### Authentication Examples

```python
# User registration
try:
    user = auth.register(
        email='user@example.com',
        password='SecurePassword123!',
        full_name='John Doe'
    )
    print(f'User registered: {user.user_id}')
    
except RustSecurityError as e:
    if e.code == 'USER_EXISTS':
        print('User already exists')
    elif e.code == 'VALIDATION_FAILED':
        print(f'Validation errors: {e.details}')
    raise

# TOTP MFA Setup
mfa_setup = auth.setup_totp(
    user_id='usr_2N4d7Hx9Kp1mQ8fR',
    display_name='Python App Access'
)

print(f'TOTP Secret: {mfa_setup.secret_base32}')
print(f'QR Code URL: {mfa_setup.qr_code_data_url}')
print(f'Backup codes: {mfa_setup.backup_codes}')

# Verify TOTP
verification = auth.verify_totp(
    user_id='usr_2N4d7Hx9Kp1mQ8fR',
    code='123456',
    remember_device=True
)

if verification.verified:
    print('MFA verification successful')
else:
    print(f'MFA verification failed: {verification.reason}')
```

### Policy Evaluation with Context Managers

```python
from contextlib import contextmanager

@contextmanager
def authorization_context(user_id, resource_type, action):
    """Context manager for policy evaluation with automatic logging"""
    start_time = time.time()
    try:
        result = policy.authorize(
            principal={'type': 'User', 'id': user_id},
            action={'type': 'Action', 'id': action},
            resource={'type': resource_type, 'id': 'resource_id'},
            context={
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'python_sdk',
                'request_id': str(uuid.uuid4())
            }
        )
        
        if result.decision == 'Allow':
            yield result
        else:
            raise PermissionError(f"Access denied: {', '.join(result.reasons)}")
            
    except Exception as e:
        print(f"Authorization failed: {e}")
        raise
    finally:
        duration = time.time() - start_time
        print(f"Authorization check took {duration:.2f}s")

# Usage
try:
    with authorization_context('user_alice', 'Document', 'Document::Read'):
        # Perform authorized action
        document = get_sensitive_document('doc_123')
        print(f"Access granted to document: {document.title}")
        
except PermissionError as e:
    print(f"Access denied: {e}")
```

### Incident Management

```python
import asyncio
from datetime import datetime, timezone

async def handle_security_incident():
    # Create incident
    incident = await soar.incidents.create(
        title='Automated Threat Detection Alert',
        description='ML model detected anomalous user behavior',
        severity='high',
        category='behavioral_anomaly',
        affected_assets=[
            {
                'type': 'user_account',
                'identifier': 'user@example.com',
                'criticality': 'high'
            }
        ],
        evidence=[
            {
                'type': 'ml_detection',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'behavioral_analysis_engine',
                'data': {
                    'anomaly_score': 0.92,
                    'detection_model': 'user_behavior_v2.1',
                    'features_triggered': [
                        'unusual_login_time',
                        'geographic_impossible_travel',
                        'api_usage_spike'
                    ]
                }
            }
        ]
    )
    
    print(f'Incident created: {incident.incident_id}')
    
    # Execute response playbook
    execution = await soar.playbooks.execute(
        playbook_id='pb_behavioral_anomaly_response',
        incident_id=incident.incident_id,
        parameters={
            'user_id': 'user@example.com',
            'severity_level': 'high',
            'auto_remediate': True
        }
    )
    
    # Monitor execution
    while execution.status in ['running', 'pending']:
        await asyncio.sleep(5)  # Check every 5 seconds
        execution = await soar.playbooks.get_execution_status(
            playbook_id='pb_behavioral_anomaly_response',
            execution_id=execution.execution_id
        )
        print(f'Playbook status: {execution.status}')
        
    if execution.status == 'completed':
        print('Automated response completed successfully')
        for step in execution.steps:
            print(f'  - {step.step_name}: {step.result}')
    else:
        print(f'Playbook execution failed: {execution.result}')

# Run async incident handling
asyncio.run(handle_security_incident())
```

## Go SDK

### Installation

```bash
go get github.com/rust-security/go-sdk
```

### Basic Setup

```go
package main

import (
    "context"
    "log"
    "os"
    "time"
    
    rustsecurity "github.com/rust-security/go-sdk"
)

func main() {
    client, err := rustsecurity.NewClient(&rustsecurity.Config{
        BaseURL: "https://api.rust-security.com",
        APIKey:  os.Getenv("RUST_SECURITY_API_KEY"),
        Timeout: 30 * time.Second,
        Retries: 3,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Access services
    authService := client.Auth()
    policyService := client.Policy()
    soarService := client.SOAR()
}
```

### Authentication with JWT Validation

```go
package main

import (
    "context"
    "fmt"
    "net/http"
    
    rustsecurity "github.com/rust-security/go-sdk"
)

// Middleware for JWT validation
func authMiddleware(client *rustsecurity.Client) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            token := r.Header.Get("Authorization")
            if token == "" {
                http.Error(w, "Authorization header required", http.StatusUnauthorized)
                return
            }
            
            // Remove "Bearer " prefix
            if len(token) > 7 && token[:7] == "Bearer " {
                token = token[7:]
            }
            
            // Validate token
            validation, err := client.Auth().VerifyToken(context.Background(), token)
            if err != nil {
                http.Error(w, "Token validation failed", http.StatusUnauthorized)
                return
            }
            
            if !validation.Valid {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }
            
            // Add user information to request context
            ctx := context.WithValue(r.Context(), "user_id", validation.Claims.Subject)
            ctx = context.WithValue(ctx, "roles", validation.Claims.Roles)
            
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// Protected endpoint example
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    roles := r.Context().Value("roles").([]string)
    
    fmt.Fprintf(w, "Hello user %s with roles: %v", userID, roles)
}
```

### Policy Evaluation in Middleware

```go
func policyMiddleware(client *rustsecurity.Client, action string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            userID := r.Context().Value("user_id").(string)
            if userID == "" {
                http.Error(w, "User not authenticated", http.StatusUnauthorized)
                return
            }
            
            // Extract resource from URL path or request
            resource := extractResourceFromRequest(r)
            
            // Evaluate policy
            authReq := &rustsecurity.AuthorizationRequest{
                RequestID: generateRequestID(),
                Principal: rustsecurity.Principal{
                    Type: "User",
                    ID:   userID,
                },
                Action: rustsecurity.Action{
                    Type: "Action",
                    ID:   action,
                },
                Resource: rustsecurity.Resource{
                    Type: "API",
                    ID:   resource,
                },
                Context: map[string]interface{}{
                    "ip_address":  getClientIP(r),
                    "user_agent":  r.UserAgent(),
                    "method":      r.Method,
                    "path":        r.URL.Path,
                    "timestamp":   time.Now().UTC().Format(time.RFC3339),
                },
            }
            
            result, err := client.Policy().Authorize(context.Background(), authReq)
            if err != nil {
                http.Error(w, "Authorization check failed", http.StatusInternalServerError)
                return
            }
            
            if result.Decision != "Allow" {
                http.Error(w, fmt.Sprintf("Access denied: %s", 
                    strings.Join(result.Reasons, ", ")), http.StatusForbidden)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}

func extractResourceFromRequest(r *http.Request) string {
    // Extract resource identifier from URL, headers, or request body
    // Implementation depends on your API structure
    return fmt.Sprintf("%s:%s", r.Method, r.URL.Path)
}

func getClientIP(r *http.Request) string {
    // Check X-Forwarded-For header
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        return strings.Split(xff, ",")[0]
    }
    
    // Check X-Real-IP header
    if xri := r.Header.Get("X-Real-IP"); xri != "" {
        return xri
    }
    
    // Fall back to RemoteAddr
    return r.RemoteAddr
}

func generateRequestID() string {
    return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
```

### Structured Error Handling

```go
type APIError struct {
    Code       string                 `json:"code"`
    Message    string                 `json:"message"`
    Details    map[string]interface{} `json:"details,omitempty"`
    RequestID  string                 `json:"request_id,omitempty"`
    Timestamp  time.Time             `json:"timestamp"`
}

func (e APIError) Error() string {
    return fmt.Sprintf("[%s] %s (Request ID: %s)", e.Code, e.Message, e.RequestID)
}

func handleRustSecurityError(err error) *APIError {
    switch e := err.(type) {
    case *rustsecurity.AuthenticationError:
        return &APIError{
            Code:      "AUTHENTICATION_FAILED",
            Message:   "Authentication failed",
            Details:   map[string]interface{}{"reason": e.Reason},
            RequestID: e.RequestID,
            Timestamp: time.Now(),
        }
        
    case *rustsecurity.AuthorizationError:
        return &APIError{
            Code:      "ACCESS_DENIED",
            Message:   "Access denied",
            Details:   map[string]interface{}{"reasons": e.Reasons},
            RequestID: e.RequestID,
            Timestamp: time.Now(),
        }
        
    case *rustsecurity.RateLimitError:
        return &APIError{
            Code:      "RATE_LIMITED",
            Message:   "Rate limit exceeded",
            Details:   map[string]interface{}{
                "retry_after": e.RetryAfter,
                "limit":       e.Limit,
                "remaining":   e.Remaining,
            },
            RequestID: e.RequestID,
            Timestamp: time.Now(),
        }
        
    default:
        return &APIError{
            Code:      "INTERNAL_ERROR",
            Message:   "Internal server error",
            Timestamp: time.Now(),
        }
    }
}
```

---

# OpenAPI Specifications

## Accessing OpenAPI Documentation

**Live Documentation URLs:**
- **Auth Service**: `http://localhost:8001/openapi.json` | `https://api.rust-security.com/auth/openapi.json`
- **Policy Service**: `http://localhost:8002/openapi.json` | `https://api.rust-security.com/policy/openapi.json`
- **SOAR Service**: `http://localhost:8003/openapi.json` | `https://api.rust-security.com/soar/openapi.json`

**Interactive Swagger UI:**
- **Auth Service**: `http://localhost:8001/swagger-ui/` | `https://api.rust-security.com/auth/docs/`
- **Policy Service**: `http://localhost:8002/swagger-ui/` | `https://api.rust-security.com/policy/docs/`
- **SOAR Service**: `http://localhost:8003/swagger-ui/` | `https://api.rust-security.com/soar/docs/`

## Generating Client SDKs

### Using OpenAPI Generator

```bash
# Generate TypeScript SDK
openapi-generator-cli generate \
  -i https://api.rust-security.com/auth/openapi.json \
  -g typescript-axios \
  -o ./generated-sdk/typescript \
  --additional-properties=npmName=@yourcompany/rust-security-auth-client

# Generate Python SDK
openapi-generator-cli generate \
  -i https://api.rust-security.com/policy/openapi.json \
  -g python \
  -o ./generated-sdk/python \
  --additional-properties=packageName=rust_security_policy_client

# Generate Go SDK
openapi-generator-cli generate \
  -i https://api.rust-security.com/soar/openapi.json \
  -g go \
  -o ./generated-sdk/go \
  --additional-properties=packageName=soarclient
```

### Custom SDK Generation with Templates

```bash
# Create custom templates directory
mkdir -p sdk-templates/typescript

# Generate with custom templates
openapi-generator-cli generate \
  -i https://api.rust-security.com/auth/openapi.json \
  -g typescript-axios \
  -t ./sdk-templates/typescript \
  -o ./custom-sdk/typescript \
  --additional-properties=withInterfaces=true,supportsES6=true
```

---

# Error Handling

## Standard Error Response Format

All API endpoints return errors in a consistent format:

```json
{
  "error": {
    "code": "AUTHENTICATION_FAILED",
    "message": "Invalid or expired access token",
    "details": {
      "token_expired_at": "2025-01-28T15:30:00Z",
      "current_time": "2025-01-28T16:45:00Z"
    },
    "field_errors": {
      "email": ["Invalid email format"],
      "password": ["Password too weak", "Must contain special characters"]
    }
  },
  "meta": {
    "request_id": "req_2N4d7Hx9Kp1mQ8fR",
    "timestamp": "2025-01-28T16:45:00Z",
    "api_version": "1.0.0"
  }
}
```

## HTTP Status Codes

| Status | Code | Description | Common Causes |
|--------|------|-------------|---------------|
| 200 | OK | Successful request | Standard success response |
| 201 | Created | Resource created successfully | User registration, policy creation |
| 202 | Accepted | Request accepted for processing | Async operations, playbook execution |
| 204 | No Content | Successful request with no response body | DELETE operations, logout |
| 400 | Bad Request | Invalid request format or parameters | Malformed JSON, missing required fields |
| 401 | Unauthorized | Authentication required or failed | Missing/invalid token, expired credentials |
| 403 | Forbidden | Access denied by authorization policies | Insufficient permissions, policy violation |
| 404 | Not Found | Requested resource does not exist | Invalid user ID, non-existent policy |
| 409 | Conflict | Resource already exists or conflict | Duplicate email, concurrent modification |
| 422 | Unprocessable Entity | Validation failed | Invalid email format, weak password |
| 429 | Too Many Requests | Rate limit exceeded | API quota exceeded, too many login attempts |
| 500 | Internal Server Error | Server-side error | Database connectivity, service unavailable |
| 502 | Bad Gateway | Upstream service error | Policy service unavailable |
| 503 | Service Unavailable | Service temporarily unavailable | Maintenance mode, overload |

## Error Codes Reference

### Authentication Errors (AUTH_*)

| Code | HTTP Status | Description | Resolution |
|------|-------------|-------------|------------|
| `AUTH_TOKEN_MISSING` | 401 | No authorization token provided | Include Authorization header |
| `AUTH_TOKEN_INVALID` | 401 | Token format is invalid | Check token format and encoding |
| `AUTH_TOKEN_EXPIRED` | 401 | Token has expired | Refresh token or re-authenticate |
| `AUTH_TOKEN_REVOKED` | 401 | Token has been revoked | Re-authenticate with valid credentials |
| `AUTH_CREDENTIALS_INVALID` | 401 | Invalid username/password | Verify credentials |
| `AUTH_MFA_REQUIRED` | 202 | Multi-factor authentication required | Complete MFA challenge |
| `AUTH_MFA_INVALID` | 401 | Invalid MFA code | Verify MFA code and try again |
| `AUTH_ACCOUNT_LOCKED` | 423 | Account temporarily locked | Wait for unlock or contact support |
| `AUTH_ACCOUNT_DISABLED` | 403 | Account has been disabled | Contact administrator |

### Authorization Errors (AUTHZ_*)

| Code | HTTP Status | Description | Resolution |
|------|-------------|-------------|------------|
| `AUTHZ_PERMISSION_DENIED` | 403 | Insufficient permissions | Request appropriate permissions |
| `AUTHZ_RESOURCE_FORBIDDEN` | 403 | Access to resource denied | Verify resource access rights |
| `AUTHZ_POLICY_VIOLATION` | 403 | Request violates security policy | Review and comply with policies |
| `AUTHZ_CONTEXT_REQUIRED` | 422 | Missing required context attributes | Provide required context data |
| `AUTHZ_EVALUATION_FAILED` | 500 | Policy evaluation failed | Check policy configuration |

### Validation Errors (VALIDATION_*)

| Code | HTTP Status | Description | Resolution |
|------|-------------|-------------|------------|
| `VALIDATION_FAILED` | 422 | Request validation failed | Check field_errors for details |
| `VALIDATION_EMAIL_INVALID` | 422 | Invalid email format | Provide valid email address |
| `VALIDATION_PASSWORD_WEAK` | 422 | Password doesn't meet requirements | Use stronger password |
| `VALIDATION_REQUIRED_FIELD` | 422 | Required field missing | Provide all required fields |
| `VALIDATION_FIELD_TOO_LONG` | 422 | Field exceeds maximum length | Shorten field value |

### Rate Limiting Errors (RATE_LIMIT_*)

| Code | HTTP Status | Description | Resolution |
|------|-------------|-------------|------------|
| `RATE_LIMIT_EXCEEDED` | 429 | API rate limit exceeded | Wait before making more requests |
| `RATE_LIMIT_LOGIN_ATTEMPTS` | 429 | Too many login attempts | Wait before attempting login again |
| `RATE_LIMIT_MFA_ATTEMPTS` | 429 | Too many MFA attempts | Wait before trying MFA again |

### System Errors (SYSTEM_*)

| Code | HTTP Status | Description | Resolution |
|------|-------------|-------------|------------|
| `SYSTEM_UNAVAILABLE` | 503 | Service temporarily unavailable | Retry later or check status page |
| `SYSTEM_MAINTENANCE` | 503 | System under maintenance | Wait for maintenance to complete |
| `SYSTEM_DATABASE_ERROR` | 500 | Database connectivity issue | Contact support if persists |
| `SYSTEM_TIMEOUT` | 504 | Request timeout | Retry with exponential backoff |

## Error Handling Best Practices

### Client-Side Error Handling

```typescript
interface APIError {
  code: string;
  message: string;
  details?: Record<string, any>;
  field_errors?: Record<string, string[]>;
  request_id?: string;
  timestamp?: string;
}

class RustSecurityClient {
  async handleRequest<T>(request: Promise<T>): Promise<T> {
    try {
      return await request;
    } catch (error) {
      const apiError = this.parseError(error);
      
      // Handle specific error types
      switch (apiError.code) {
        case 'AUTH_TOKEN_EXPIRED':
          // Attempt to refresh token
          await this.refreshToken();
          return await request; // Retry original request
          
        case 'RATE_LIMIT_EXCEEDED':
          // Implement exponential backoff
          const retryAfter = error.response?.headers['retry-after'] || 1;
          await this.delay(retryAfter * 1000);
          return await request;
          
        case 'VALIDATION_FAILED':
          // Handle validation errors specifically
          throw new ValidationError(apiError.message, apiError.field_errors);
          
        case 'SYSTEM_UNAVAILABLE':
          // Implement circuit breaker pattern
          this.circuitBreaker.recordFailure();
          throw new ServiceUnavailableError(apiError.message);
          
        default:
          throw new RustSecurityError(apiError);
      }
    }
  }
  
  private parseError(error: any): APIError {
    if (error.response?.data?.error) {
      return error.response.data.error;
    }
    
    // Fallback for network errors
    return {
      code: 'NETWORK_ERROR',
      message: 'Network request failed',
      details: { originalError: error.message }
    };
  }
}
```

### Retry Logic Implementation

```typescript
class RetryableClient {
  private async retryWithExponentialBackoff<T>(
    operation: () => Promise<T>,
    maxRetries: number = 3,
    baseDelay: number = 1000
  ): Promise<T> {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        if (attempt === maxRetries || !this.isRetryableError(error)) {
          throw error;
        }
        
        const delay = baseDelay * Math.pow(2, attempt - 1);
        const jitter = Math.random() * 1000; // Add jitter to prevent thundering herd
        
        console.log(`Attempt ${attempt} failed, retrying in ${delay + jitter}ms`);
        await this.delay(delay + jitter);
      }
    }
    
    throw new Error('Max retries exceeded');
  }
  
  private isRetryableError(error: any): boolean {
    const retryableCodes = [
      'SYSTEM_TIMEOUT',
      'SYSTEM_UNAVAILABLE',
      'SYSTEM_DATABASE_ERROR'
    ];
    
    const retryableStatuses = [500, 502, 503, 504];
    
    return (
      retryableCodes.includes(error.code) ||
      retryableStatuses.includes(error.response?.status)
    );
  }
}
```

---

# Rate Limiting & Pagination

## Rate Limiting

All API endpoints implement rate limiting to ensure fair usage and system stability.

### Rate Limit Headers

Every API response includes rate limit information in headers:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1641234567
X-RateLimit-Window: 3600
```

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed per window |
| `X-RateLimit-Remaining` | Requests remaining in current window |
| `X-RateLimit-Reset` | Unix timestamp when window resets |
| `X-RateLimit-Window` | Window duration in seconds |

### Rate Limit Tiers

| Tier | Requests/Hour | Burst Limit | Notes |
|------|---------------|-------------|--------|
| **Anonymous** | 100 | 10/min | Public endpoints only |
| **Basic** | 1,000 | 50/min | Authenticated users |
| **Premium** | 10,000 | 200/min | Premium subscription |
| **Enterprise** | 100,000 | 1,000/min | Enterprise accounts |
| **Service-to-Service** | 1,000,000 | 10,000/min | API keys with service role |

### Rate Limit Implementation

```typescript
// Client-side rate limit handling
class RateLimitedClient {
  private requestQueue: Array<() => Promise<any>> = [];
  private isProcessingQueue = false;
  
  async makeRequest<T>(requestFn: () => Promise<T>): Promise<T> {
    return new Promise((resolve, reject) => {
      this.requestQueue.push(async () => {
        try {
          const result = await requestFn();
          resolve(result);
        } catch (error) {
          if (error.status === 429) {
            // Rate limited - implement backoff
            const retryAfter = parseInt(error.headers['retry-after'] || '1');
            console.log(`Rate limited, waiting ${retryAfter} seconds`);
            
            setTimeout(async () => {
              try {
                const retryResult = await requestFn();
                resolve(retryResult);
              } catch (retryError) {
                reject(retryError);
              }
            }, retryAfter * 1000);
          } else {
            reject(error);
          }
        }
      });
      
      this.processQueue();
    });
  }
  
  private async processQueue() {
    if (this.isProcessingQueue || this.requestQueue.length === 0) {
      return;
    }
    
    this.isProcessingQueue = true;
    
    while (this.requestQueue.length > 0) {
      const request = this.requestQueue.shift()!;
      await request();
      
      // Small delay between requests to prevent burst limits
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    
    this.isProcessingQueue = false;
  }
}
```

## Pagination

List endpoints support cursor-based and offset-based pagination.

### Cursor-Based Pagination (Recommended)

Cursor-based pagination provides consistent results even when data is modified during pagination.

**Request:**
```http
GET /api/v1/incidents?limit=20&cursor=eyJjcmVhdGVkX2F0IjoiMjAyNS0wMS0yOFQxNjozMDowMFoiLCJpZCI6ImluY18yTjRkN0h4OUtOcDFtUThMUiJ9
```

**Response:**
```json
{
  "data": [
    {
      "incident_id": "inc_8Kx2Nv5mP9qR4tY7",
      "title": "Suspicious Activity Detected",
      "created_at": "2025-01-28T16:30:00Z"
    }
  ],
  "pagination": {
    "limit": 20,
    "has_next": true,
    "has_previous": true,
    "next_cursor": "eyJjcmVhdGVkX2F0IjoiMjAyNS0wMS0yOFQxNjo0NTowMFoiLCJpZCI6ImluY184S3gyTnY1bVA5cVI0dFk3In0",
    "previous_cursor": "eyJjcmVhdGVkX2F0IjoiMjAyNS0wMS0yOFQxNjoxNTowMFoiLCJpZCI6ImluY18zWXQ5Qng2bk0ycFE1c0Y4In0"
  },
  "meta": {
    "total_count": 1250,
    "request_id": "req_2N4d7Hx9Kp1mQ8fR"
  }
}
```

### Offset-Based Pagination

Traditional page-based pagination for simpler use cases.

**Request:**
```http
GET /api/v1/users?page=2&limit=50&sort=created_at:desc
```

**Response:**
```json
{
  "data": [
    {
      "user_id": "usr_2N4d7Hx9Kp1mQ8fR",
      "email": "user@example.com",
      "created_at": "2025-01-28T10:30:00Z"
    }
  ],
  "pagination": {
    "page": 2,
    "per_page": 50,
    "total": 1250,
    "total_pages": 25,
    "has_next": true,
    "has_previous": true
  }
}
```

### Pagination Parameters

| Parameter | Type | Description | Default | Max |
|-----------|------|-------------|---------|-----|
| `limit` | integer | Items per page | 20 | 100 |
| `page` | integer | Page number (1-based) | 1 | - |
| `cursor` | string | Cursor for cursor-based pagination | - | - |
| `sort` | string | Sort field and direction | `created_at:desc` | - |

### Efficient Pagination Client Implementation

```typescript
class PaginatedClient {
  async *getAllItems<T>(endpoint: string, params: Record<string, any> = {}): AsyncGenerator<T, void, unknown> {
    let cursor = null;
    let hasNext = true;
    
    while (hasNext) {
      const queryParams = {
        ...params,
        limit: 100, // Use maximum page size for efficiency
        ...(cursor && { cursor })
      };
      
      const response = await this.makeRequest(`${endpoint}?${new URLSearchParams(queryParams)}`);
      
      // Yield individual items
      for (const item of response.data) {
        yield item;
      }
      
      // Update pagination state
      hasNext = response.pagination.has_next;
      cursor = response.pagination.next_cursor;
    }
  }
  
  // Usage example
  async processAllIncidents() {
    for await (const incident of this.getAllItems('/api/v1/incidents', { severity: 'high' })) {
      await this.processIncident(incident);
    }
  }
  
  // Batch processing with parallel execution
  async processIncidentsBatch(batchSize: number = 10) {
    const incidents = this.getAllItems('/api/v1/incidents', { status: 'open' });
    const batch: any[] = [];
    
    for await (const incident of incidents) {
      batch.push(incident);
      
      if (batch.length >= batchSize) {
        // Process batch in parallel
        await Promise.all(batch.map(inc => this.processIncident(inc)));
        batch.length = 0; // Clear batch
      }
    }
    
    // Process remaining items
    if (batch.length > 0) {
      await Promise.all(batch.map(inc => this.processIncident(inc)));
    }
  }
}
```

---

# Troubleshooting Guide

## Common Integration Issues

### Authentication Problems

**Issue: "Invalid or expired access token"**

*Symptoms:*
- HTTP 401 responses from API calls
- Error code: `AUTH_TOKEN_EXPIRED` or `AUTH_TOKEN_INVALID`

*Solutions:*
1. **Check token format:**
   ```javascript
   // Correct format
   headers: {
     'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'
   }
   
   // Incorrect - missing 'Bearer ' prefix
   headers: {
     'Authorization': 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'
   }
   ```

2. **Implement token refresh:**
   ```javascript
   class TokenManager {
     async getValidToken() {
       if (this.isTokenExpired(this.accessToken)) {
         await this.refreshToken();
       }
       return this.accessToken;
     }
     
     isTokenExpired(token) {
       if (!token) return true;
       
       try {
         const payload = JSON.parse(atob(token.split('.')[1]));
         const now = Math.floor(Date.now() / 1000);
         return payload.exp < now + 60; // Refresh 1 minute before expiry
       } catch {
         return true;
       }
     }
   }
   ```

**Issue: "MFA required but not implemented"**

*Symptoms:*
- HTTP 202 response with `requires_mfa: true`
- Login flow stops unexpectedly

*Solution:*
```javascript
async function handleLogin(credentials) {
  try {
    const result = await auth.login(credentials);
    
    if (result.requires_mfa) {
      // Show MFA input form
      const mfaCode = await promptUserForMFA(result.mfa_methods);
      
      // Complete MFA challenge
      const finalResult = await auth.completeMfaChallenge({
        challenge_token: result.challenge_token,
        mfa_code: mfaCode,
        mfa_method: 'totp' // or user's choice
      });
      
      return finalResult;
    }
    
    return result;
  } catch (error) {
    console.error('Login failed:', error.message);
    throw error;
  }
}
```

### Policy Evaluation Issues

**Issue: "Policy evaluation returns unexpected results"**

*Symptoms:*
- Expected "Allow" but got "Deny"
- Inconsistent authorization decisions

*Debugging Steps:*

1. **Enable detailed evaluation:**
   ```json
   {
     "principal": {"type": "User", "id": "user_alice"},
     "action": {"type": "Action", "id": "Document::Read"},
     "resource": {"type": "Document", "id": "doc_123"},
     "context": {
       "debug": true,
       "include_policy_trace": true,
       "timestamp": "2025-01-28T16:45:00Z"
     }
   }
   ```

2. **Review policy trace:**
   ```json
   {
     "decision": "Deny",
     "policy_trace": [
       {
         "policy_id": "policy_time_based",
         "rule_id": "rule_business_hours",
         "matched": false,
         "reason": "Current time 18:45 outside business hours (09:00-17:00)"
       }
     ]
   }
   ```

3. **Common context issues:**
   ```javascript
   // Missing required context
   const context = {
     'timestamp': new Date().toISOString(),
     'ip_address': req.ip,
     'user_agent': req.headers['user-agent'],
     'mfa_verified': req.user.mfa_verified,
     'security_clearance': req.user.clearance_level
   };
   ```

**Issue: "Slow policy evaluation performance"**

*Solutions:*

1. **Use batch evaluation:**
   ```javascript
   // Instead of multiple individual calls
   const requests = documents.map(doc => ({
     id: doc.id,
     principal: {type: 'User', id: userId},
     action: {type: 'Action', id: 'Document::Read'},
     resource: {type: 'Document', id: doc.id},
     context: sharedContext
   }));
   
   const results = await policy.batchAuthorize({requests});
   ```

2. **Cache evaluation results:**
   ```javascript
   class PolicyCache {
     constructor(ttl = 300) { // 5 minute TTL
       this.cache = new Map();
       this.ttl = ttl * 1000;
     }
     
     getCacheKey(principal, action, resource, context) {
       return JSON.stringify({principal, action, resource, context});
     }
     
     async evaluate(request) {
       const key = this.getCacheKey(request);
       const cached = this.cache.get(key);
       
       if (cached && Date.now() - cached.timestamp < this.ttl) {
         return cached.result;
       }
       
       const result = await policy.authorize(request);
       this.cache.set(key, {result, timestamp: Date.now()});
       
       return result;
     }
   }
   ```

### SOAR Integration Issues

**Issue: "Playbook execution fails or hangs"**

*Debugging Steps:*

1. **Check playbook parameters:**
   ```javascript
   // Ensure all required parameters are provided
   const execution = await soar.playbooks.execute('pb_incident_response', {
     incident_id: 'inc_123',
     parameters: {
       affected_user: 'user@example.com',  // Required
       severity_level: 'high',             // Required
       notify_admin: true                  // Optional
     }
   });
   ```

2. **Monitor execution status:**
   ```javascript
   async function waitForPlaybookCompletion(playbookId, executionId) {
     const maxWaitTime = 10 * 60 * 1000; // 10 minutes
     const pollInterval = 5000; // 5 seconds
     const startTime = Date.now();
     
     while (Date.now() - startTime < maxWaitTime) {
       const status = await soar.playbooks.getExecutionStatus(playbookId, executionId);
       
       if (['completed', 'failed', 'cancelled'].includes(status.status)) {
         return status;
       }
       
       if (status.status === 'pending_approval') {
         console.log('Playbook waiting for manual approval');
         // Handle approval flow
         break;
       }
       
       await new Promise(resolve => setTimeout(resolve, pollInterval));
     }
     
     throw new Error('Playbook execution timeout');
   }
   ```

### Rate Limiting Issues

**Issue: "Frequent rate limit errors"**

*Solutions:*

1. **Implement exponential backoff:**
   ```javascript
   class ResilientClient {
     async makeRequestWithRetry(requestFn, maxRetries = 3) {
       for (let attempt = 1; attempt <= maxRetries; attempt++) {
         try {
           return await requestFn();
         } catch (error) {
           if (error.status === 429 && attempt < maxRetries) {
             const retryAfter = parseInt(error.headers['retry-after'] || '1');
             const backoffDelay = Math.pow(2, attempt) * 1000; // Exponential backoff
             const delay = Math.max(retryAfter * 1000, backoffDelay);
             
             console.log(`Rate limited. Retrying in ${delay}ms (attempt ${attempt})`);
             await new Promise(resolve => setTimeout(resolve, delay));
             continue;
           }
           throw error;
         }
       }
     }
   }
   ```

2. **Implement request queuing:**
   ```javascript
   class QueuedClient {
     constructor(requestsPerSecond = 10) {
       this.requestQueue = [];
       this.isProcessing = false;
       this.requestInterval = 1000 / requestsPerSecond;
     }
     
     async queueRequest(requestFn) {
       return new Promise((resolve, reject) => {
         this.requestQueue.push({ requestFn, resolve, reject });
         this.processQueue();
       });
     }
     
     async processQueue() {
       if (this.isProcessing || this.requestQueue.length === 0) {
         return;
       }
       
       this.isProcessing = true;
       
       while (this.requestQueue.length > 0) {
         const { requestFn, resolve, reject } = this.requestQueue.shift();
         
         try {
           const result = await requestFn();
           resolve(result);
         } catch (error) {
           reject(error);
         }
         
         // Wait before next request
         await new Promise(resolve => setTimeout(resolve, this.requestInterval));
       }
       
       this.isProcessing = false;
     }
   }
   ```

### Network and Connectivity Issues

**Issue: "Connection timeouts or network errors"**

*Solutions:*

1. **Configure appropriate timeouts:**
   ```javascript
   const client = new RustSecuritySDK({
     baseUrl: 'https://api.rust-security.com',
     timeout: 30000,        // 30 second timeout
     retries: 3,            // Retry failed requests
     retryDelay: 1000,      // Initial retry delay
     retryDelayMultiplier: 2 // Exponential backoff multiplier
   });
   ```

2. **Implement circuit breaker pattern:**
   ```javascript
   class CircuitBreaker {
     constructor(failureThreshold = 5, recoveryTimeout = 60000) {
       this.failureCount = 0;
       this.failureThreshold = failureThreshold;
       this.recoveryTimeout = recoveryTimeout;
       this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
       this.nextAttempt = Date.now();
     }
     
     async execute(operation) {
       if (this.state === 'OPEN') {
         if (Date.now() < this.nextAttempt) {
           throw new Error('Circuit breaker is OPEN');
         }
         this.state = 'HALF_OPEN';
       }
       
       try {
         const result = await operation();
         this.onSuccess();
         return result;
       } catch (error) {
         this.onFailure();
         throw error;
       }
     }
     
     onSuccess() {
       this.failureCount = 0;
       this.state = 'CLOSED';
     }
     
     onFailure() {
       this.failureCount++;
       if (this.failureCount >= this.failureThreshold) {
         this.state = 'OPEN';
         this.nextAttempt = Date.now() + this.recoveryTimeout;
       }
     }
   }
   ```

## Performance Optimization

### API Call Optimization

1. **Use appropriate page sizes:**
   ```javascript
   // Too small - many API calls
   const users = await getAllUsers({ limit: 10 });
   
   // Optimal - fewer API calls
   const users = await getAllUsers({ limit: 100 });
   ```

2. **Implement efficient caching:**
   ```javascript
   class CachedApiClient {
     constructor(ttl = 300000) { // 5 minutes
       this.cache = new Map();
       this.ttl = ttl;
     }
     
     async getCachedData(key, fetchFn) {
       const cached = this.cache.get(key);
       const now = Date.now();
       
       if (cached && now - cached.timestamp < this.ttl) {
         return cached.data;
       }
       
       const data = await fetchFn();
       this.cache.set(key, { data, timestamp: now });
       
       return data;
     }
   }
   ```

3. **Use parallel requests where possible:**
   ```javascript
   // Sequential - slower
   const user = await auth.getUser(userId);
   const permissions = await auth.getUserPermissions(userId);
   const sessions = await auth.getUserSessions(userId);
   
   // Parallel - faster
   const [user, permissions, sessions] = await Promise.all([
     auth.getUser(userId),
     auth.getUserPermissions(userId),
     auth.getUserSessions(userId)
   ]);
   ```

### Memory Management

1. **Handle large result sets efficiently:**
   ```javascript
   // Memory efficient streaming
   async function* streamIncidents(filters) {
     let cursor = null;
     
     do {
       const response = await soar.incidents.list({
         ...filters,
         cursor,
         limit: 100
       });
       
       for (const incident of response.data) {
         yield incident;
       }
       
       cursor = response.pagination.next_cursor;
     } while (cursor);
   }
   
   // Usage
   for await (const incident of streamIncidents({ severity: 'high' })) {
     await processIncident(incident);
     // Incident is garbage collected after processing
   }
   ```

## Monitoring and Debugging

### Enable Debug Logging

```javascript
// Enable SDK debug logging
const sdk = new RustSecuritySDK({
  baseUrl: 'https://api.rust-security.com',
  apiKey: process.env.API_KEY,
  debug: true,
  logLevel: 'debug'
});

// Custom request/response logging
sdk.interceptors.request.use(request => {
  console.log('API Request:', {
    method: request.method,
    url: request.url,
    headers: request.headers,
    timestamp: new Date().toISOString()
  });
  return request;
});

sdk.interceptors.response.use(
  response => {
    console.log('API Response:', {
      status: response.status,
      statusText: response.statusText,
      requestId: response.headers['x-request-id'],
      duration: response.config.metadata?.endTime - response.config.metadata?.startTime
    });
    return response;
  },
  error => {
    console.error('API Error:', {
      status: error.response?.status,
      statusText: error.response?.statusText,
      requestId: error.response?.headers['x-request-id'],
      message: error.message,
      code: error.code
    });
    throw error;
  }
);
```

### Health Check Implementation

```javascript
class HealthChecker {
  constructor(sdk) {
    this.sdk = sdk;
    this.lastCheck = null;
    this.checkInterval = 30000; // 30 seconds
  }
  
  async checkHealth() {
    const checks = {
      auth_service: this.checkAuthService(),
      policy_service: this.checkPolicyService(),
      soar_service: this.checkSoarService()
    };
    
    const results = await Promise.allSettled(Object.values(checks));
    const healthStatus = {};
    
    Object.keys(checks).forEach((service, index) => {
      const result = results[index];
      healthStatus[service] = {
        status: result.status === 'fulfilled' ? 'healthy' : 'unhealthy',
        response_time_ms: result.value?.responseTime || null,
        error: result.reason?.message || null,
        last_check: new Date().toISOString()
      };
    });
    
    this.lastCheck = healthStatus;
    return healthStatus;
  }
  
  async checkAuthService() {
    const startTime = Date.now();
    try {
      await this.sdk.auth.getHealthCheck();
      return { responseTime: Date.now() - startTime };
    } catch (error) {
      throw new Error(`Auth service health check failed: ${error.message}`);
    }
  }
}

// Usage
const healthChecker = new HealthChecker(sdk);

setInterval(async () => {
  try {
    const health = await healthChecker.checkHealth();
    console.log('Health status:', health);
    
    // Alert on service degradation
    Object.entries(health).forEach(([service, status]) => {
      if (status.status === 'unhealthy') {
        console.error(`🚨 ${service} is unhealthy:`, status.error);
        // Send alert to monitoring system
      }
    });
  } catch (error) {
    console.error('Health check failed:', error);
  }
}, 30000);
```

This comprehensive API documentation provides developers with everything they need to successfully integrate with the Rust Security Platform. The documentation covers all major services, includes working code examples, and provides detailed troubleshooting guidance for common integration scenarios.
