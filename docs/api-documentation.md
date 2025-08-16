# API Documentation - Rust Authentication Service

## Base URL
```
Production: https://auth.yourcompany.com
Development: http://localhost:3001
```

## OAuth2/OIDC Endpoints

### OIDC Discovery
**GET** `/.well-known/openid_configuration`

Returns the OpenID Connect configuration.

### Authorization
**GET** `/oauth/authorize`

Initiates OAuth2 authorization code flow.

**Parameters:**
- `client_id` (required): Client identifier
- `response_type` (required): Must be "code"
- `redirect_uri` (required): Client redirect URI
- `scope` (optional): Requested scopes
- `state` (recommended): CSRF protection
- `code_challenge` (PKCE): Code challenge
- `code_challenge_method` (PKCE): Must be "S256"

### Token Exchange
**POST** `/oauth/token`

Exchanges authorization code for access tokens.

**Parameters:**
- `grant_type` (required): "authorization_code" or "client_credentials"
- `code` (required for auth code): Authorization code
- `redirect_uri` (required for auth code): Must match authorize request
- `client_id` (required): Client identifier
- `client_secret` (required): Client secret
- `code_verifier` (PKCE): Code verifier

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def50200...",
  "scope": "openid profile"
}
```

### Token Introspection
**POST** `/oauth/introspect`

Validates and returns information about a token.

**Authentication:** Client credentials (Basic Auth)

### Token Revocation
**POST** `/oauth/revoke`

Revokes an access or refresh token.

**Authentication:** Client credentials (Basic Auth)

### JSON Web Key Set
**GET** `/jwks.json`

Returns public keys for JWT signature verification.

## SCIM 2.0 Endpoints

### List Users
**GET** `/scim/v2/Users`

Returns a list of users with pagination.

**Authentication:** Bearer token required

**Parameters:**
- `startIndex` (optional): Start index (default: 1)
- `count` (optional): Results per page (default: 20)
- `filter` (optional): SCIM filter expression

### Get User
**GET** `/scim/v2/Users/{id}`

Retrieves a specific user by ID.

**Authentication:** Bearer token required

### Create User
**POST** `/scim/v2/Users`

Creates a new user.

**Authentication:** Bearer token required
**Content-Type:** `application/scim+json`

### Update User
**PUT** `/scim/v2/Users/{id}`

Updates an existing user.

**Authentication:** Bearer token required
**Content-Type:** `application/scim+json`

### Delete User
**DELETE** `/scim/v2/Users/{id}`

Deletes a user.

**Authentication:** Bearer token required

## Multi-Factor Authentication

### Generate TOTP Secret
**POST** `/mfa/totp/generate`

Generates a TOTP secret for a user.

**Authentication:** Bearer token required

### Verify TOTP Code
**POST** `/mfa/totp/verify`

Verifies a TOTP code.

**Authentication:** Bearer token required

## Administrative Endpoints

### Health Check
**GET** `/health`

Returns service health status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2023-12-01T12:00:00Z",
  "version": "1.0.0"
}
```

### Metrics
**GET** `/metrics`

Returns Prometheus metrics for monitoring.

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": "invalid_request",
  "error_description": "The request is missing a required parameter"
}
```

### Common Error Codes
- `invalid_request`: Malformed request
- `invalid_client`: Invalid client credentials
- `invalid_grant`: Invalid authorization grant
- `unauthorized_client`: Client not authorized
- `access_denied`: Access denied
- `server_error`: Internal server error

### HTTP Status Codes
- **200 OK**: Request successful
- **201 Created**: Resource created
- **400 Bad Request**: Invalid request
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Access denied
- **404 Not Found**: Resource not found
- **429 Too Many Requests**: Rate limit exceeded
- **500 Internal Server Error**: Server error

## Rate Limiting

All endpoints are subject to rate limiting:
- **Default limit**: 60 requests per minute per IP
- **Burst limit**: 120 requests

## Security Considerations

1. Always use HTTPS in production
2. Validate redirect URIs against registered values
3. Use PKCE for public clients
4. Implement proper CSRF protection using state parameter
5. Monitor for suspicious activity using security logs

For detailed integration examples and SDKs, see the full API documentation.
