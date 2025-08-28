# API Reference - Complete Integration Guide

## Overview

The Rust Security Platform provides comprehensive REST APIs for authentication, authorization, and security management. All APIs follow OpenAPI 3.0 specification with complete type safety and documentation.

## Base URLs

| Environment | Auth Service | Policy Service | Red Team |
|-------------|--------------|----------------|----------|
| Development | `http://localhost:8080` | `http://localhost:8081` | `http://localhost:8082` |
| Staging | `https://auth-staging.company.com` | `https://policy-staging.company.com` | `https://redteam-staging.company.com` |
| Production | `https://auth.company.com` | `https://policy.company.com` | `https://redteam.company.com` |

## Authentication Methods

### Bearer Token Authentication
```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Client Credentials (OAuth)
```http
Authorization: Basic base64(client_id:client_secret)
```

### API Key Authentication  
```http
X-API-Key: your-api-key-here
```

---

# Auth Service API

## OAuth 2.0 / OIDC Endpoints

### Authorization Endpoint

**GET** `/oauth/authorize`

Initiates OAuth 2.0 authorization code flow with PKCE support.

**Query Parameters:**
```typescript
interface AuthorizationRequest {
  response_type: 'code' | 'token' | 'id_token' | 'code id_token' | 'code token' | 'id_token token' | 'code id_token token';
  client_id: string;
  redirect_uri: string;
  scope?: string;
  state?: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: 'S256' | 'plain';
  prompt?: 'none' | 'login' | 'consent' | 'select_account';
  max_age?: number;
  ui_locales?: string;
  id_token_hint?: string;
  login_hint?: string;
  acr_values?: string;
}
```

**Example Request:**
```http
GET /oauth/authorize?response_type=code&client_id=web-app&redirect_uri=https%3A%2F%2Fapp.company.com%2Fcallback&scope=openid%20profile%20email&state=xyz123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256 HTTP/1.1
Host: auth.company.com
```

**Success Response (302 Redirect):**
```http
HTTP/1.1 302 Found
Location: https://app.company.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz123
```

**Error Response (400 Bad Request):**
```json
{
  "error": "invalid_request",
  "error_description": "Missing required parameter: client_id",
  "error_uri": "https://docs.company.com/errors/invalid_request"
}
```

### Token Endpoint

**POST** `/oauth/token`

Exchanges authorization code, refresh token, or client credentials for access tokens.

**Headers:**
```http
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)  # For confidential clients
```

**Request Body (Authorization Code Grant):**
```typescript
interface TokenRequest {
  grant_type: 'authorization_code';
  code: string;
  redirect_uri: string;
  client_id?: string;          // For public clients
  code_verifier?: string;      // PKCE code verifier
}
```

**Request Body (Client Credentials Grant):**
```typescript
interface ClientCredentialsRequest {
  grant_type: 'client_credentials';
  scope?: string;
  client_id?: string;
  client_secret?: string;
}
```

**Request Body (Refresh Token Grant):**
```typescript
interface RefreshTokenRequest {
  grant_type: 'refresh_token';
  refresh_token: string;
  scope?: string;
  client_id?: string;
  client_secret?: string;
}
```

**Example Request:**
```http
POST /oauth/token HTTP/1.1
Host: auth.company.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic d2ViLWFwcDpzZWNyZXQ=

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fapp.company.com%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**Success Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "8xLOxBtZp8",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error Response:**
```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code is invalid or expired",
  "error_uri": "https://docs.company.com/errors/invalid_grant"
}
```

### Token Introspection

**POST** `/oauth/introspect`

Validates and returns metadata about access tokens.

**Headers:**
```http
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer {access_token}
```

**Request Body:**
```typescript
interface IntrospectionRequest {
  token: string;
  token_type_hint?: 'access_token' | 'refresh_token';
}
```

**Example Request:**
```http
POST /oauth/introspect HTTP/1.1
Host: auth.company.com
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Success Response (Active Token):**
```json
{
  "active": true,
  "scope": "openid profile email read write",
  "client_id": "web-app",
  "username": "john.doe@company.com",
  "exp": 1643723400,
  "iat": 1643719800,
  "nbf": 1643719800,
  "sub": "user123",
  "aud": ["web-app", "api-gateway"],
  "iss": "https://auth.company.com",
  "jti": "token-id-123",
  "token_type": "Bearer"
}
```

**Success Response (Inactive Token):**
```json
{
  "active": false
}
```

### Token Revocation

**POST** `/oauth/revoke`

Revokes access or refresh tokens.

**Headers:**
```http
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)
```

**Request Body:**
```typescript
interface RevocationRequest {
  token: string;
  token_type_hint?: 'access_token' | 'refresh_token';
}
```

**Example Request:**
```http
POST /oauth/revoke HTTP/1.1
Host: auth.company.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic d2ViLWFwcDpzZWNyZXQ=

token=8xLOxBtZp8&token_type_hint=refresh_token
```

**Success Response:**
```http
HTTP/1.1 200 OK
```

### UserInfo Endpoint (OIDC)

**GET** `/oauth/userinfo`

Returns user profile information for the authenticated user.

**Headers:**
```http
Authorization: Bearer {access_token}
```

**Example Request:**
```http
GET /oauth/userinfo HTTP/1.1
Host: auth.company.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Success Response:**
```json
{
  "sub": "user123",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john.doe@company.com",
  "email_verified": true,
  "picture": "https://avatars.company.com/user123",
  "locale": "en-US",
  "updated_at": 1643719800,
  "preferred_username": "johndoe",
  "profile": "https://profile.company.com/johndoe",
  "website": "https://johndoe.com",
  "gender": "male",
  "birthdate": "1990-01-01",
  "zoneinfo": "America/New_York",
  "phone_number": "+1-555-123-4567",
  "phone_number_verified": true,
  "address": {
    "formatted": "123 Main St\nAnytown, ST 12345",
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "ST", 
    "postal_code": "12345",
    "country": "US"
  }
}
```

## Authentication Endpoints

### User Registration

**POST** `/api/v1/auth/register`

Creates a new user account with optional email verification.

**Headers:**
```http
Content-Type: application/json
```

**Request Body:**
```typescript
interface RegistrationRequest {
  email: string;
  password: string;
  name: string;
  given_name?: string;
  family_name?: string;
  phone_number?: string;
  locale?: string;
  metadata?: Record<string, any>;
  verify_email?: boolean;
}
```

**Validation Rules:**
- `email`: Valid email format, unique across system
- `password`: Minimum 8 characters, complexity requirements
- `name`: 2-100 characters, no special characters
- `phone_number`: E.164 format (optional)

**Example Request:**
```http
POST /api/v1/auth/register HTTP/1.1
Host: auth.company.com
Content-Type: application/json

{
  "email": "jane.smith@company.com",
  "password": "SecurePassword123!",
  "name": "Jane Smith",
  "given_name": "Jane",
  "family_name": "Smith",
  "phone_number": "+1-555-987-6543",
  "locale": "en-US",
  "verify_email": true,
  "metadata": {
    "department": "Engineering",
    "hire_date": "2025-01-28",
    "employee_id": "EMP001"
  }
}
```

**Success Response:**
```json
{
  "user_id": "user456",
  "email": "jane.smith@company.com", 
  "name": "Jane Smith",
  "created_at": "2025-01-28T10:30:00Z",
  "email_verified": false,
  "verification_required": true,
  "verification_token_sent": true
}
```

**Error Response (Validation):**
```json
{
  "error": "validation_error",
  "message": "Request validation failed",
  "details": {
    "email": ["Email address already exists"],
    "password": ["Password must contain at least one uppercase letter"]
  }
}
```

### User Login

**POST** `/api/v1/auth/login`

Authenticates user credentials and returns access tokens.

**Headers:**
```http
Content-Type: application/json
```

**Request Body:**
```typescript
interface LoginRequest {
  email: string;
  password: string;
  remember_me?: boolean;
  mfa_token?: string;        // Second factor if MFA enabled
  device_name?: string;      // For device tracking
  client_info?: ClientInfo;
}

interface ClientInfo {
  ip_address?: string;
  user_agent?: string;
  device_fingerprint?: string;
}
```

**Example Request:**
```http
POST /api/v1/auth/login HTTP/1.1
Host: auth.company.com
Content-Type: application/json

{
  "email": "jane.smith@company.com",
  "password": "SecurePassword123!",
  "remember_me": true,
  "device_name": "Jane's MacBook",
  "client_info": {
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "device_fingerprint": "fp_abc123def456"
  }
}
```

**Success Response (No MFA Required):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "rt_8xLOxBtZp8",
  "scope": "profile email",
  "user_id": "user456",
  "session_id": "session_789"
}
```

**Success Response (MFA Required):**
```json
{
  "mfa_required": true,
  "mfa_methods": ["totp", "sms"],
  "mfa_token": "mfa_temp_token_123",
  "expires_in": 300
}
```

**Error Response (Invalid Credentials):**
```json
{
  "error": "invalid_credentials",
  "message": "Invalid email or password",
  "retry_after": 5
}
```

**Error Response (Account Locked):**
```json
{
  "error": "account_locked",
  "message": "Account temporarily locked due to too many failed attempts",
  "locked_until": "2025-01-28T11:00:00Z",
  "contact_support": "security@company.com"
}
```

### Get Current User

**GET** `/api/v1/auth/me`

Returns the current authenticated user's profile information.

**Headers:**
```http
Authorization: Bearer {access_token}
```

**Example Request:**
```http
GET /api/v1/auth/me HTTP/1.1
Host: auth.company.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Success Response:**
```json
{
  "user_id": "user456",
  "email": "jane.smith@company.com",
  "name": "Jane Smith",
  "given_name": "Jane",
  "family_name": "Smith",
  "email_verified": true,
  "phone_number": "+1-555-987-6543",
  "phone_number_verified": false,
  "picture": "https://avatars.company.com/user456",
  "locale": "en-US",
  "created_at": "2025-01-28T10:30:00Z",
  "updated_at": "2025-01-28T10:35:00Z",
  "last_login": "2025-01-28T15:30:00Z",
  "groups": ["Users", "Engineering"],
  "roles": ["employee", "developer"],
  "permissions": ["read:profile", "write:profile"],
  "mfa_enabled": true,
  "mfa_methods": ["totp"],
  "session_info": {
    "session_id": "session_789",
    "created_at": "2025-01-28T15:30:00Z",
    "expires_at": "2025-01-28T23:30:00Z",
    "device_name": "Jane's MacBook",
    "ip_address": "192.168.1.100"
  }
}
```

### Update User Profile

**PUT** `/api/v1/auth/me`

Updates the current user's profile information.

**Headers:**
```http
Content-Type: application/json
Authorization: Bearer {access_token}
```

**Request Body:**
```typescript
interface ProfileUpdateRequest {
  name?: string;
  given_name?: string;
  family_name?: string;
  phone_number?: string;
  picture?: string;
  locale?: string;
  website?: string;
  bio?: string;
  metadata?: Record<string, any>;
}
```

**Example Request:**
```http
PUT /api/v1/auth/me HTTP/1.1
Host: auth.company.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "name": "Jane Smith-Johnson",
  "phone_number": "+1-555-999-8888",
  "website": "https://janesmith.dev",
  "bio": "Senior Software Engineer specializing in security and authentication systems."
}
```

**Success Response:**
```json
{
  "user_id": "user456",
  "email": "jane.smith@company.com",
  "name": "Jane Smith-Johnson",
  "phone_number": "+1-555-999-8888",
  "website": "https://janesmith.dev",
  "bio": "Senior Software Engineer specializing in security and authentication systems.",
  "updated_at": "2025-01-28T16:45:00Z"
}
```

### Logout

**POST** `/api/v1/auth/logout`

Terminates the current user session and optionally revokes tokens.

**Headers:**
```http
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request Body:**
```typescript
interface LogoutRequest {
  revoke_tokens?: boolean;      // Revoke access/refresh tokens
  logout_all_sessions?: boolean; // Terminate all user sessions
}
```

**Example Request:**
```http
POST /api/v1/auth/logout HTTP/1.1
Host: auth.company.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "revoke_tokens": true,
  "logout_all_sessions": false
}
```

**Success Response:**
```json
{
  "message": "Successfully logged out",
  "session_terminated": true,
  "tokens_revoked": true
}
```

## Multi-Factor Authentication

### Setup TOTP

**POST** `/mfa/totp/setup`

Generates TOTP secret and QR code for authenticator app setup.

**Headers:**
```http
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request Body:**
```typescript
interface TOTPSetupRequest {
  account_name?: string;  // Defaults to user email
  issuer?: string;        // Defaults to service name
}
```

**Example Request:**
```http
POST /mfa/totp/setup HTTP/1.1
Host: auth.company.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "account_name": "jane.smith@company.com",
  "issuer": "Rust Security Platform"
}
```

**Success Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAEA...",
  "qr_code_uri": "otpauth://totp/Rust%20Security%20Platform:jane.smith@company.com?secret=JBSWY3DPEHPK3PXP&issuer=Rust%20Security%20Platform",
  "backup_codes": [
    "12345678",
    "87654321",
    "11111111",
    "22222222",
    "33333333"
  ],
  "setup_token": "totp_setup_token_123"
}
```

### Verify TOTP Setup

**POST** `/mfa/totp/verify`

Verifies TOTP code to complete setup process.

**Headers:**
```http
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request Body:**
```typescript
interface TOTPVerifyRequest {
  code: string;              // 6-digit TOTP code
  setup_token: string;       // From setup response
  name?: string;             // Friendly name for the authenticator
}
```

**Example Request:**
```http
POST /mfa/totp/verify HTTP/1.1
Host: auth.company.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "code": "123456",
  "setup_token": "totp_setup_token_123",
  "name": "Google Authenticator"
}
```

**Success Response:**
```json
{
  "verified": true,
  "mfa_enabled": true,
  "recovery_codes": [
    "12345678",
    "87654321", 
    "11111111",
    "22222222",
    "33333333"
  ],
  "message": "TOTP authentication successfully enabled"
}
```

### WebAuthn Registration

**POST** `/mfa/webauthn/register/begin`

Initiates WebAuthn credential registration process.

**Headers:**
```http
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request Body:**
```typescript
interface WebAuthnRegisterRequest {
  credential_name: string;
  user_verification?: 'required' | 'preferred' | 'discouraged';
  authenticator_attachment?: 'platform' | 'cross-platform';
}
```

**Example Request:**
```http
POST /mfa/webauthn/register/begin HTTP/1.1
Host: auth.company.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "credential_name": "YubiKey 5 NFC",
  "user_verification": "required",
  "authenticator_attachment": "cross-platform"
}
```

**Success Response:**
```json
{
  "publicKey": {
    "challenge": "c2lnbmluZ19jaGFsbGVuZ2Vfc3RyaW5n",
    "rp": {
      "name": "Rust Security Platform",
      "id": "auth.company.com"
    },
    "user": {
      "id": "dXNlcjQ1Ng",
      "name": "jane.smith@company.com",
      "displayName": "Jane Smith"
    },
    "pubKeyCredParams": [
      {"alg": -7, "type": "public-key"},
      {"alg": -257, "type": "public-key"}
    ],
    "authenticatorSelection": {
      "authenticatorAttachment": "cross-platform",
      "userVerification": "required"
    },
    "timeout": 60000,
    "attestation": "direct"
  }
}
```

**POST** `/mfa/webauthn/register/finish`

Completes WebAuthn credential registration.

**Headers:**
```http
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request Body:**
```typescript
interface WebAuthnRegisterFinishRequest {
  credential_name: string;
  credential: PublicKeyCredential; // From navigator.credentials.create()
}
```

**Success Response:**
```json
{
  "credential_id": "cred_abc123def456",
  "credential_name": "YubiKey 5 NFC",
  "created_at": "2025-01-28T16:30:00Z",
  "backup_eligible": true,
  "aaguid": "2fc0579f-8113-47ea-b116-bb5a8db9202a"
}
```

## SCIM 2.0 User Management

### List Users

**GET** `/scim/v2/Users`

Retrieves paginated list of users with filtering and sorting.

**Headers:**
```http
Authorization: Bearer {admin_access_token}
Content-Type: application/scim+json
```

**Query Parameters:**
```typescript
interface UsersListQuery {
  startIndex?: number;      // 1-based pagination start
  count?: number;          // Number of results per page (max 100)
  filter?: string;         // SCIM filter expression
  sortBy?: string;         // Attribute to sort by
  sortOrder?: 'ascending' | 'descending';
  attributes?: string;     // Comma-separated attributes to return
  excludedAttributes?: string;
}
```

**Example Request:**
```http
GET /scim/v2/Users?startIndex=1&count=10&filter=emails.value+sw+"@company.com"&sortBy=meta.created&sortOrder=descending HTTP/1.1
Host: auth.company.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/scim+json
```

**Success Response:**
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 157,
  "startIndex": 1,
  "itemsPerPage": 10,
  "Resources": [
    {
      "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
      "id": "user456",
      "externalId": "EMP001",
      "userName": "jane.smith@company.com",
      "name": {
        "formatted": "Jane Smith",
        "familyName": "Smith", 
        "givenName": "Jane"
      },
      "displayName": "Jane Smith",
      "emails": [
        {
          "value": "jane.smith@company.com",
          "type": "work",
          "primary": true
        }
      ],
      "phoneNumbers": [
        {
          "value": "+1-555-999-8888",
          "type": "work"
        }
      ],
      "active": true,
      "groups": [
        {
          "value": "group123",
          "display": "Engineering"
        }
      ],
      "meta": {
        "resourceType": "User",
        "created": "2025-01-28T10:30:00Z",
        "lastModified": "2025-01-28T16:45:00Z",
        "version": "2",
        "location": "https://auth.company.com/scim/v2/Users/user456"
      }
    }
  ]
}
```

### Create User

**POST** `/scim/v2/Users`

Creates a new user account through SCIM interface.

**Headers:**
```http
Authorization: Bearer {admin_access_token}
Content-Type: application/scim+json
```

**Request Body:**
```typescript
interface SCIMUser {
  schemas: string[];
  externalId?: string;
  userName: string;
  name?: {
    formatted?: string;
    familyName?: string;
    givenName?: string;
    middleName?: string;
    honorificPrefix?: string;
    honorificSuffix?: string;
  };
  displayName?: string;
  emails?: Array<{
    value: string;
    type?: string;
    primary?: boolean;
  }>;
  phoneNumbers?: Array<{
    value: string;
    type?: string;
    primary?: boolean;
  }>;
  active?: boolean;
  password?: string;
  groups?: Array<{
    value: string;
    display?: string;
  }>;
  roles?: Array<{
    value: string;
    display?: string;
    type?: string;
    primary?: boolean;
  }>;
}
```

**Example Request:**
```http
POST /scim/v2/Users HTTP/1.1
Host: auth.company.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "externalId": "EMP002", 
  "userName": "bob.johnson@company.com",
  "name": {
    "formatted": "Bob Johnson",
    "familyName": "Johnson",
    "givenName": "Bob"
  },
  "displayName": "Bob Johnson",
  "emails": [
    {
      "value": "bob.johnson@company.com",
      "type": "work",
      "primary": true
    }
  ],
  "phoneNumbers": [
    {
      "value": "+1-555-123-4567",
      "type": "work"
    }
  ],
  "active": true,
  "password": "TempPassword123!",
  "groups": [
    {
      "value": "group456",
      "display": "Sales"
    }
  ]
}
```

**Success Response (201 Created):**
```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "user789",
  "externalId": "EMP002",
  "userName": "bob.johnson@company.com",
  "name": {
    "formatted": "Bob Johnson",
    "familyName": "Johnson",
    "givenName": "Bob"
  },
  "displayName": "Bob Johnson",
  "emails": [
    {
      "value": "bob.johnson@company.com", 
      "type": "work",
      "primary": true
    }
  ],
  "phoneNumbers": [
    {
      "value": "+1-555-123-4567",
      "type": "work"
    }
  ],
  "active": true,
  "groups": [
    {
      "value": "group456",
      "display": "Sales"
    }
  ],
  "meta": {
    "resourceType": "User",
    "created": "2025-01-28T17:00:00Z",
    "lastModified": "2025-01-28T17:00:00Z",
    "version": "1",
    "location": "https://auth.company.com/scim/v2/Users/user789"
  }
}
```

---

# Policy Service API

## Policy Evaluation

### Evaluate Authorization Request

**POST** `/api/v1/policies/evaluate`

Evaluates authorization request against all applicable policies.

**Headers:**
```http
Content-Type: application/json
Authorization: Bearer {access_token}
```

**Request Body:**
```typescript
interface PolicyEvaluationRequest {
  principal: EntityUid;
  action: EntityUid;
  resource: EntityUid;
  context?: Context;
}

interface EntityUid {
  type: string;
  id: string;
}

interface Context {
  [key: string]: any;
}
```

**Example Request:**
```http
POST /api/v1/policies/evaluate HTTP/1.1
Host: policy.company.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "principal": {
    "type": "User",
    "id": "jane.smith@company.com"
  },
  "action": {
    "type": "Action", 
    "id": "ReadDocument"
  },
  "resource": {
    "type": "Document",
    "id": "doc_123"
  },
  "context": {
    "ip_address": "192.168.1.100",
    "time": "2025-01-28T15:30:00Z",
    "department": "Engineering",
    "classification_level": "Internal"
  }
}
```

**Success Response:**
```json
{
  "decision": "Allow",
  "diagnostics": {
    "reason": [
      "Policy 'allow-engineers-read-docs' permits this request",
      "Principal is member of Engineering group",
      "Document classification allows Engineering access"
    ],
    "policies": [
      {
        "policy_id": "policy_001", 
        "effect": "Permit",
        "conditions_met": true
      }
    ]
  },
  "evaluation_time_ms": 2,
  "cache_hit": false,
  "policy_version": "v1.2.3"
}
```

**Deny Response:**
```json
{
  "decision": "Deny",
  "diagnostics": {
    "reason": [
      "No policy explicitly permits this request",
      "Default deny policy applied"
    ],
    "policies": []
  },
  "evaluation_time_ms": 1,
  "cache_hit": true,
  "policy_version": "v1.2.3"
}
```

### Batch Policy Evaluation

**POST** `/api/v1/policies/batch`

Evaluates multiple authorization requests in a single call.

**Headers:**
```http
Content-Type: application/json
Authorization: Bearer {access_token}
```

**Request Body:**
```typescript
interface BatchEvaluationRequest {
  requests: PolicyEvaluationRequest[];
  fail_fast?: boolean;  // Stop on first denial
}
```

**Example Request:**
```http
POST /api/v1/policies/batch HTTP/1.1
Host: policy.company.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "requests": [
    {
      "principal": {"type": "User", "id": "jane.smith@company.com"},
      "action": {"type": "Action", "id": "ReadDocument"},
      "resource": {"type": "Document", "id": "doc_123"}
    },
    {
      "principal": {"type": "User", "id": "jane.smith@company.com"}, 
      "action": {"type": "Action", "id": "WriteDocument"},
      "resource": {"type": "Document", "id": "doc_123"}
    }
  ],
  "fail_fast": false
}
```

**Success Response:**
```json
{
  "results": [
    {
      "request_index": 0,
      "decision": "Allow",
      "evaluation_time_ms": 2
    },
    {
      "request_index": 1,
      "decision": "Deny", 
      "evaluation_time_ms": 1,
      "reason": "User lacks write permission for document"
    }
  ],
  "total_evaluation_time_ms": 3,
  "cache_hits": 1,
  "cache_misses": 1
}
```

## Policy Management

### List Policies

**GET** `/api/v1/policies`

Retrieves all policies with pagination and filtering.

**Headers:**
```http
Authorization: Bearer {admin_access_token}
```

**Query Parameters:**
```typescript
interface PoliciesListQuery {
  page?: number;
  per_page?: number;
  filter?: string;      // Filter by policy content
  tag?: string;         // Filter by policy tags
  active_only?: boolean;
}
```

**Example Request:**
```http
GET /api/v1/policies?page=1&per_page=10&active_only=true HTTP/1.1
Host: policy.company.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Success Response:**
```json
{
  "policies": [
    {
      "id": "policy_001",
      "name": "Engineering Document Access",
      "description": "Allows engineering team to read internal documents",
      "policy": "permit (principal in Group::\"Engineering\", action == Action::\"ReadDocument\", resource) when { resource.classification == \"Internal\" };",
      "active": true,
      "version": "1.2",
      "created_at": "2025-01-28T10:00:00Z",
      "updated_at": "2025-01-28T12:00:00Z",
      "tags": ["engineering", "documents", "read-access"]
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 15,
    "total_pages": 2
  }
}
```

### Create Policy

**POST** `/api/v1/policies`

Creates a new authorization policy.

**Headers:**
```http
Content-Type: application/json
Authorization: Bearer {admin_access_token}
```

**Request Body:**
```typescript
interface PolicyCreateRequest {
  name: string;
  description?: string;
  policy: string;          // Cedar policy language
  active?: boolean;
  tags?: string[];
  priority?: number;
}
```

**Example Request:**
```http
POST /api/v1/policies HTTP/1.1
Host: policy.company.com
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

{
  "name": "Sales Team CRM Access",
  "description": "Allows sales team members to access CRM system during business hours",
  "policy": "permit (principal in Group::\"Sales\", action == Action::\"AccessCRM\", resource == Resource::\"CRM\") when { context.time >= time(\"09:00:00\") && context.time <= time(\"17:00:00\") && context.day_of_week in [\"Monday\", \"Tuesday\", \"Wednesday\", \"Thursday\", \"Friday\"] };",
  "active": true,
  "tags": ["sales", "crm", "business-hours"],
  "priority": 100
}
```

**Success Response (201 Created):**
```json
{
  "id": "policy_002",
  "name": "Sales Team CRM Access",
  "description": "Allows sales team members to access CRM system during business hours", 
  "policy": "permit (principal in Group::\"Sales\", action == Action::\"AccessCRM\", resource == Resource::\"CRM\") when { context.time >= time(\"09:00:00\") && context.time <= time(\"17:00:00\") && context.day_of_week in [\"Monday\", \"Tuesday\", \"Wednesday\", \"Thursday\", \"Friday\"] };",
  "active": true,
  "version": "1.0",
  "created_at": "2025-01-28T17:30:00Z",
  "updated_at": "2025-01-28T17:30:00Z",
  "tags": ["sales", "crm", "business-hours"],
  "priority": 100
}
```

## Error Responses

### Standard Error Format

All APIs return errors in a consistent format:

```typescript
interface ErrorResponse {
  error: string;              // Error code
  message: string;           // Human-readable message
  details?: any;             // Additional error details
  request_id?: string;       // Unique request identifier
  timestamp: string;         // ISO 8601 timestamp
}
```

### Common HTTP Status Codes

| Status Code | Description | Common Scenarios |
|-------------|-------------|------------------|
| `400 Bad Request` | Invalid request format or parameters | Missing required fields, invalid JSON |
| `401 Unauthorized` | Authentication required or failed | Missing/invalid access token |
| `403 Forbidden` | Insufficient permissions | User lacks required scope/role |
| `404 Not Found` | Resource not found | Invalid user ID, policy ID |
| `409 Conflict` | Resource conflict | Duplicate email, concurrent updates |
| `422 Unprocessable Entity` | Validation errors | Invalid email format, weak password |
| `429 Too Many Requests` | Rate limit exceeded | Too many API calls |
| `500 Internal Server Error` | Server error | Database connection, unexpected errors |

### Error Examples

**400 Bad Request:**
```json
{
  "error": "invalid_request",
  "message": "Required field missing: email",
  "details": {
    "field": "email",
    "code": "REQUIRED"
  },
  "request_id": "req_abc123",
  "timestamp": "2025-01-28T17:45:00Z"
}
```

**401 Unauthorized:**
```json
{
  "error": "invalid_token",
  "message": "The access token is expired",
  "details": {
    "expired_at": "2025-01-28T16:30:00Z"
  },
  "request_id": "req_def456", 
  "timestamp": "2025-01-28T17:45:00Z"
}
```

**403 Forbidden:**
```json
{
  "error": "insufficient_scope",
  "message": "Token lacks required scope: admin:users:write",
  "details": {
    "required_scope": "admin:users:write",
    "token_scopes": ["read:profile", "write:profile"]
  },
  "request_id": "req_ghi789",
  "timestamp": "2025-01-28T17:45:00Z"
}
```

## SDKs and Code Examples

### JavaScript/TypeScript SDK

```typescript
import { RustSecurityClient } from '@company/rust-security-sdk';

const client = new RustSecurityClient({
  baseUrl: 'https://auth.company.com',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
});

// Authenticate user
const authResult = await client.auth.login({
  email: 'user@company.com',
  password: 'password123'
});

// Get user profile
const user = await client.auth.getCurrentUser(authResult.accessToken);

// Evaluate policy
const decision = await client.policy.evaluate({
  principal: { type: 'User', id: user.userId },
  action: { type: 'Action', id: 'ReadDocument' },
  resource: { type: 'Document', id: 'doc-123' }
});
```

### Python SDK

```python
from rust_security_sdk import RustSecurityClient

client = RustSecurityClient(
    base_url='https://auth.company.com',
    client_id='your-client-id',
    client_secret='your-client-secret'
)

# Authenticate user
auth_result = client.auth.login(
    email='user@company.com',
    password='password123'
)

# Get user profile
user = client.auth.get_current_user(auth_result.access_token)

# Evaluate policy
decision = client.policy.evaluate(
    principal={'type': 'User', 'id': user.user_id},
    action={'type': 'Action', 'id': 'ReadDocument'},
    resource={'type': 'Document', 'id': 'doc-123'}
)
```

### Go SDK

```go
package main

import (
    "context"
    rustsecurity "github.com/company/rust-security-go"
)

func main() {
    client := rustsecurity.NewClient(&rustsecurity.Config{
        BaseURL:      "https://auth.company.com",
        ClientID:     "your-client-id", 
        ClientSecret: "your-client-secret",
    })

    // Authenticate user
    authResult, err := client.Auth.Login(context.Background(), &rustsecurity.LoginRequest{
        Email:    "user@company.com",
        Password: "password123",
    })
    if err != nil {
        panic(err)
    }

    // Get user profile
    user, err := client.Auth.GetCurrentUser(context.Background(), authResult.AccessToken)
    if err != nil {
        panic(err)
    }

    // Evaluate policy
    decision, err := client.Policy.Evaluate(context.Background(), &rustsecurity.PolicyRequest{
        Principal: &rustsecurity.EntityUid{Type: "User", ID: user.UserID},
        Action:    &rustsecurity.EntityUid{Type: "Action", ID: "ReadDocument"},
        Resource:  &rustsecurity.EntityUid{Type: "Document", ID: "doc-123"},
    })
    if err != nil {
        panic(err)
    }
}
```

This comprehensive API reference provides everything needed to integrate with the Rust Security Platform's authentication, authorization, and security management capabilities.