# API Documentation

## Overview

The Rust Security Platform provides a comprehensive REST API for authentication, authorization, and user management. All endpoints support JSON request/response format and follow RESTful conventions.

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

#### GET /auth/oauth/{provider}
Initiate OAuth flow with external provider.

**Parameters:**
- `provider`: google, github, microsoft, etc.
- `redirect_uri`: Callback URL after authentication
- `state`: CSRF protection token

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
  "state": "csrf_token_123"
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

#### POST /auth/mfa/setup
Setup MFA for current user.

**Request:**
```json
{
  "method": "totp",
  "phone": "+1234567890"
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

### Supported Events
- `user.created`
- `user.updated`
- `user.deleted`
- `auth.login`
- `auth.logout`
- `auth.failed`
- `role.assigned`
- `role.removed`

### Webhook Configuration
```json
{
  "url": "https://your-app.com/webhooks/auth",
  "events": ["user.created", "auth.login"],
  "secret": "webhook_secret_key"
}
```

### Webhook Payload
```json
{
  "event": "user.created",
  "timestamp": "2023-12-01T10:30:00Z",
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com"
    }
  },
  "signature": "sha256=..."
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
