# API Documentation

## Overview

The Rust Security Platform provides a comprehensive REST API for authentication, authorization, and user management. All endpoints support JSON request/response format and follow RESTful conventions.

### API Architecture Overview

```mermaid
graph TB
    Client[Client Application] --> Gateway[API Gateway]
    Gateway --> Auth[Auth Service :8080]
    Gateway --> Policy[Policy Service :8081]
    Gateway --> Threat[Threat Detection :8082]
    
    Auth --> AuthDB[(Auth Database)]
    Auth --> Redis[(Redis Cache)]
    Auth --> JWKS[JWKS Endpoint]
    
    Policy --> PolicyDB[(Policy Database)]
    Policy --> Cedar[Cedar Engine]
    
    Threat --> ThreatDB[(Threat Intelligence)]
    Threat --> SOAR[SOAR Engine]
    
    Auth -.->|validates tokens| Policy
    Auth -.->|security events| Threat
    Policy -.->|audit logs| Threat
    
    style Auth fill:#e1f5fe
    style Policy fill:#f3e5f5  
    style Threat fill:#fff3e0
```

### Authentication Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Auth Service
    participant P as Policy Service
    participant R as Redis
    participant D as Database
    
    Note over C,D: Standard Login Flow
    C->>A: POST /auth/login
    A->>D: Validate credentials
    D-->>A: User data
    A->>R: Store session
    A-->>C: JWT + Refresh Token
    
    Note over C,D: Authenticated Request
    C->>P: GET /protected (with JWT)
    P->>A: Validate token
    A->>R: Check session
    R-->>A: Session valid
    A-->>P: Token valid
    P->>D: Check permissions
    D-->>P: User permissions
    P-->>C: Protected resource
    
    Note over C,D: Token Refresh
    C->>A: POST /auth/refresh
    A->>R: Validate refresh token
    R-->>A: Token valid
    A-->>C: New JWT + Refresh Token
```

## Base URL

```
Production: https://api.yourdomain.com
Staging: https://staging-api.yourdomain.com
Development: http://localhost:8080
```

## Authentication

All API requests require authentication via JWT tokens in the Authorization header:

```http
Authorization: Bearer <jwt_token>
```

## Rate Limiting

API requests are rate-limited to prevent abuse:
- **Standard endpoints**: 100 requests per minute
- **Authentication endpoints**: 10 requests per minute
- **Bulk operations**: 5 requests per minute

Rate limit headers are included in responses:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## Error Handling

The API uses standard HTTP status codes and returns detailed error information:

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "The provided credentials are invalid",
    "details": {
      "field": "password",
      "reason": "Password does not meet complexity requirements"
    },
    "request_id": "req_123456789"
  }
}
```

### Common Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request body or parameters |
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

## Endpoints

### Authentication

#### POST /auth/login
Authenticate user with email/password.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "secure_password",
  "remember_me": false
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "rt_abc123...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "user": {
    "id": "user_123",
    "email": "user@example.com",
    "roles": ["user"],
    "permissions": ["read:profile"]
  }
}
```

#### POST /auth/refresh
Refresh access token using refresh token.

**Request:**
```json
{
  "refresh_token": "rt_abc123..."
}
```

#### POST /auth/logout
Invalidate current session.

**Request:**
```json
{
  "refresh_token": "rt_abc123..."
}
```

#### GET /auth/me
Get current user information.

**Response:**
```json
{
  "user": {
    "id": "user_123",
    "email": "user@example.com",
    "name": "John Doe",
    "roles": ["user", "admin"],
    "permissions": ["read:profile", "write:profile"],
    "last_login": "2023-12-01T10:30:00Z",
    "created_at": "2023-01-15T09:00:00Z"
  }
}
```

### OAuth 2.0

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client App
    participant A as Auth Service
    participant P as Provider (Google/GitHub)
    
    Note over U,P: OAuth 2.0 Authorization Code Flow with PKCE
    
    U->>C: Click "Login with Google"
    C->>C: Generate code_verifier & code_challenge
    C->>A: GET /auth/oauth/google?redirect_uri=...&code_challenge=...
    A-->>C: Redirect to Google with state
    
    C->>P: Redirect user to Google OAuth
    U->>P: Authenticate with Google
    P-->>C: Redirect with authorization code
    
    C->>A: POST /auth/oauth/google/callback
    Note right of A: {code, state, code_verifier}
    A->>P: Exchange code for tokens
    P-->>A: Access token + ID token
    A->>A: Validate ID token & create user
    A-->>C: JWT + Refresh token
```

#### GET /auth/oauth/{provider}
Initiate OAuth flow with external provider.

**Parameters:**
- `provider`: google, github, microsoft, etc.
- `redirect_uri`: Callback URL after authentication
- `state`: CSRF protection token
- `code_challenge`: PKCE code challenge (recommended)
- `code_challenge_method`: S256 (recommended)

**Response:**
```json
{
  "authorization_url": "https://accounts.google.com/oauth/authorize?...",
  "state": "csrf_token_123"
}
```

#### POST /auth/oauth/{provider}/callback
Handle OAuth callback.

**Request:**
```json
{
  "code": "oauth_code_123",
  "state": "csrf_token_123",
  "code_verifier": "pkce_verifier_123"
}
```

### User Management

#### POST /users
Create new user account.

**Request:**
```json
{
  "email": "newuser@example.com",
  "password": "secure_password",
  "name": "Jane Doe",
  "roles": ["user"]
}
```

#### GET /users/{user_id}
Get user by ID.

#### PUT /users/{user_id}
Update user information.

#### DELETE /users/{user_id}
Delete user account.

#### GET /users
List users with pagination.

**Parameters:**
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20, max: 100)
- `search`: Search query
- `role`: Filter by role

### Roles and Permissions

#### GET /roles
List available roles.

#### POST /roles
Create new role.

#### GET /permissions
List available permissions.

#### POST /users/{user_id}/roles
Assign role to user.

#### DELETE /users/{user_id}/roles/{role_id}
Remove role from user.

### Multi-Factor Authentication

```mermaid
sequenceDiagram
    participant U as User
    participant C as Client
    participant A as Auth Service
    participant T as TOTP App
    participant S as SMS Service
    
    Note over U,S: MFA Setup Flow
    
    U->>C: Enable MFA
    C->>A: POST /auth/mfa/setup
    A->>A: Generate TOTP secret
    A-->>C: QR code + backup codes
    C-->>U: Display QR code
    U->>T: Scan QR code
    T-->>U: Generate TOTP token
    U->>C: Enter TOTP token
    C->>A: POST /auth/mfa/verify
    A->>A: Validate TOTP token
    A-->>C: MFA enabled successfully
    
    Note over U,S: Login with MFA
    
    U->>C: Login with username/password  
    C->>A: POST /auth/login
    A->>A: Validate credentials
    A-->>C: MFA challenge required
    C-->>U: Prompt for MFA token
    U->>T: Get current TOTP
    T-->>U: 6-digit code
    U->>C: Enter TOTP code
    C->>A: POST /auth/mfa/verify
    A->>A: Validate TOTP + time window
    A-->>C: JWT + Refresh tokens
```

#### POST /auth/mfa/setup
Setup MFA for current user.

**Request:**
```json
{
  "method": "totp",
  "phone": "+1234567890"
}
```

**Response:**
```json
{
  "qr_code": "data:image/png;base64,iVBOR...",
  "secret": "JBSWY3DPEHPK3PXP",
  "backup_codes": ["abc123", "def456", "ghi789"],
  "setup_uri": "otpauth://totp/YourApp:user@example.com?secret=JBSWY3DPEHPK3PXP"
}
```

#### POST /auth/mfa/verify
Verify MFA token.

**Request:**
```json
{
  "token": "123456",
  "method": "totp"
}
```

**Response:**
```json
{
  "verified": true,
  "remaining_backup_codes": 5
}
```

#### DELETE /auth/mfa
Disable MFA for current user.

### Sessions

#### GET /sessions
List active sessions for current user.

#### DELETE /sessions/{session_id}
Terminate specific session.

#### DELETE /sessions
Terminate all sessions except current.

### Audit Logs

#### GET /audit
Get audit logs (admin only).

**Parameters:**
- `user_id`: Filter by user
- `action`: Filter by action type
- `from`: Start date (ISO 8601)
- `to`: End date (ISO 8601)

## SDKs and Libraries

### JavaScript/TypeScript
```bash
npm install @yourorg/rust-security-client
```

```javascript
import { RustSecurityClient } from '@yourorg/rust-security-client';

const client = new RustSecurityClient({
  baseUrl: 'https://api.yourdomain.com',
  apiKey: 'your-api-key'
});

const user = await client.auth.login({
  email: 'user@example.com',
  password: 'password'
});
```

### Python
```bash
pip install rust-security-python
```

```python
from rust_security import Client

client = Client(
    base_url='https://api.yourdomain.com',
    api_key='your-api-key'
)

user = client.auth.login(
    email='user@example.com',
    password='password'
)
```

### Go
```bash
go get github.com/yourorg/rust-security-go
```

```go
import "github.com/yourorg/rust-security-go"

client := rustsecurity.NewClient("https://api.yourdomain.com", "your-api-key")
user, err := client.Auth.Login("user@example.com", "password")
```

## Webhooks

The platform supports webhooks for real-time event notifications:

```mermaid
sequenceDiagram
    participant A as Auth Service
    participant W as Webhook Queue
    participant Y as Your App
    participant D as Database
    
    Note over A,D: Event-Driven Webhook System
    
    A->>A: User login event occurs
    A->>W: Queue webhook event
    A->>D: Log event to audit trail
    
    W->>W: Process webhook queue
    W->>Y: POST /webhook/auth
    Note right of W: Signed payload with event data
    
    alt Webhook Success
        Y-->>W: 200 OK
        W->>D: Mark delivery successful
    else Webhook Failure  
        Y-->>W: 4xx/5xx Error
        W->>W: Retry with backoff
        W->>Y: Retry delivery (up to 3 times)
        
        alt Still Failing
            W->>D: Mark delivery failed
            W->>A: Alert admin of webhook failure
        end
    end
    
    Note over A,D: Webhook Security Verification
    Y->>Y: Verify webhook signature
    Y->>Y: Validate timestamp (prevent replay)
    Y->>Y: Process event data
```

### Supported Events
- `user.created` - New user registration
- `user.updated` - User profile changes
- `user.deleted` - User account deletion
- `auth.login` - Successful authentication
- `auth.logout` - User logout
- `auth.failed` - Failed authentication attempt
- `role.assigned` - Role granted to user
- `role.removed` - Role revoked from user
- `mfa.enabled` - Multi-factor authentication enabled
- `mfa.disabled` - Multi-factor authentication disabled
- `session.expired` - Session timeout or invalidation

### Webhook Configuration
```json
{
  "url": "https://your-app.com/webhooks/auth",
  "events": ["user.created", "auth.login", "auth.failed"],
  "secret": "webhook_secret_key_minimum_32_chars",
  "retry_policy": {
    "max_attempts": 3,
    "initial_delay": 1,
    "backoff_multiplier": 2
  }
}
```

### Webhook Payload
```json
{
  "id": "webhook_evt_123456789",
  "event": "user.created",
  "timestamp": "2023-12-01T10:30:00Z",
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "name": "John Doe",
      "roles": ["user"]
    },
    "metadata": {
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0...",
      "source": "web_registration"
    }
  },
  "signature": "sha256=a8b7c6d5e4f3..."
}
```

### Webhook Security
All webhook payloads are signed using HMAC-SHA256. Verify the signature:

```javascript
const crypto = require('crypto');

function verifyWebhook(payload, signature, secret) {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
    
  return signature === `sha256=${expectedSignature}`;
}
```

## Testing

### Postman Collection
Import our Postman collection for easy API testing:
[Download Collection](./postman/rust-security-platform.json)

### OpenAPI Specification
View the complete API specification:
[OpenAPI Spec](./openapi.yaml)

## Support

- **Documentation**: [https://docs.yourdomain.com](https://docs.yourdomain.com)
- **Support Email**: [support@yourdomain.com](mailto:support@yourdomain.com)
- **GitHub Issues**: [https://github.com/yourorg/rust-security-platform/issues](https://github.com/yourorg/rust-security-platform/issues)
- **Discord Community**: [https://discord.gg/yourinvite](https://discord.gg/yourinvite)
