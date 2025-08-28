# 📡 API Guide - Rust Security Platform

Complete guide to integrating with the Rust Security Platform APIs. This guide covers all endpoints, authentication methods, error handling, and best practices.

## 📋 Table of Contents

- [🔗 API Overview](#-api-overview)
- [🔐 Authentication](#-authentication)
- [👤 User Management](#-user-management)
- [🎫 Token Management](#-token-management)
- [🔒 Authorization & Policies](#-authorization--policies)
- [🛡️ Security Features](#️-security-features)
- [📊 Monitoring & Analytics](#-monitoring--analytics)
- [🚨 Error Handling](#-error-handling)
- [💡 Best Practices](#-best-practices)
- [🔧 SDKs & Examples](#-sdks--examples)

## 🔗 API Overview

### Base URLs

```
Production:  https://auth.yourdomain.com
Staging:     https://auth-staging.yourdomain.com
Development: http://localhost:8080
```

### API Versioning

```
Current Version: v1
Base Path: /api/v1
Auth Endpoints: /auth/*
Policy Endpoints: /policies/*
Admin Endpoints: /admin/*
```

### Content Types

```
Request:  application/json
Response: application/json
Errors:   application/problem+json (RFC 7807)
```

### Rate Limiting

```
Default Limits:
- Authentication: 100 requests/minute/IP
- API calls: 1000 requests/minute/user
- Admin operations: 10 requests/minute/user

Headers:
- X-RateLimit-Limit: Request limit
- X-RateLimit-Remaining: Remaining requests
- X-RateLimit-Reset: Reset timestamp
```

## 🔐 Authentication

### Registration

**Endpoint:** `POST /auth/register`

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@company.com", 
    "password": "SecurePassword123!",
    "profile": {
      "first_name": "John",
      "last_name": "Doe",
      "phone": "+1-555-0123"
    },
    "terms_accepted": true
  }'
```

**Response:**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "john_doe",
  "email": "john@company.com",
  "email_verified": false,
  "profile": {
    "first_name": "John",
    "last_name": "Doe",
    "phone": "+1-555-0123"
  },
  "created_at": "2024-01-15T10:30:00Z",
  "status": "active"
}
```

### Login

**Endpoint:** `POST /auth/login`

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "SecurePassword123!",
    "remember_me": true,
    "device_info": {
      "device_type": "web",
      "user_agent": "Mozilla/5.0...",
      "ip_address": "192.168.1.100"
    }
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read write",
  "user": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "john_doe",
    "email": "john@company.com",
    "roles": ["user"],
    "permissions": ["read:profile", "write:profile"]
  },
  "session": {
    "session_id": "sess_abc123",
    "device_id": "dev_xyz789",
    "last_activity": "2024-01-15T10:30:00Z"
  }
}
```

### Multi-Factor Authentication

**Endpoint:** `POST /auth/mfa/verify`

```bash
# After initial login, if MFA is enabled
curl -X POST http://localhost:8080/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{
    "mfa_token": "temp_token_from_login",
    "code": "123456",
    "method": "totp"
  }'
```

### Token Refresh

**Endpoint:** `POST /auth/refresh`

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read write"
}
```

### Logout

**Endpoint:** `POST /auth/logout`

```bash
curl -X POST http://localhost:8080/auth/logout \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "invalidate_all_sessions": false
  }'
```

## 👤 User Management

### Get User Profile

**Endpoint:** `GET /auth/profile`

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/auth/profile
```

**Response:**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "john_doe",
  "email": "john@company.com",
  "email_verified": true,
  "profile": {
    "first_name": "John",
    "last_name": "Doe",
    "phone": "+1-555-0123",
    "avatar_url": "https://cdn.company.com/avatars/john_doe.jpg",
    "timezone": "America/New_York",
    "locale": "en-US"
  },
  "roles": ["user"],
  "permissions": [
    "read:profile",
    "write:profile"
  ],
  "account_status": "active",
  "last_login": "2024-01-15T10:30:00Z",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Update User Profile

**Endpoint:** `PUT /auth/profile`

```bash
curl -X PUT http://localhost:8080/auth/profile \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": {
      "first_name": "John",
      "last_name": "Smith", 
      "phone": "+1-555-0124",
      "timezone": "America/Los_Angeles"
    }
  }'
```

### Change Password

**Endpoint:** `PUT /auth/password`

```bash
curl -X PUT http://localhost:8080/auth/password \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "SecurePassword123!",
    "new_password": "NewSecurePassword456!",
    "revoke_other_sessions": true
  }'
```

### Email Verification

**Endpoint:** `POST /auth/verify-email`

```bash
# Send verification email
curl -X POST http://localhost:8080/auth/verify-email \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Verify with token
curl -X PUT http://localhost:8080/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "verification_token": "email_verification_token_here"
  }'
```

### Password Reset

**Endpoint:** `POST /auth/password-reset`

```bash
# Request password reset
curl -X POST http://localhost:8080/auth/password-reset \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@company.com"
  }'

# Reset with token
curl -X PUT http://localhost:8080/auth/password-reset \
  -H "Content-Type: application/json" \
  -d '{
    "reset_token": "password_reset_token_here",
    "new_password": "NewSecurePassword789!"
  }'
```

## 🎫 Token Management

### List Active Sessions

**Endpoint:** `GET /auth/sessions`

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/auth/sessions
```

**Response:**
```json
{
  "sessions": [
    {
      "session_id": "sess_abc123",
      "device_info": {
        "device_type": "web",
        "user_agent": "Mozilla/5.0...",
        "ip_address": "192.168.1.100",
        "location": "New York, NY"
      },
      "created_at": "2024-01-15T10:30:00Z",
      "last_activity": "2024-01-15T11:00:00Z",
      "is_current": true
    }
  ],
  "total_count": 1
}
```

### Revoke Session

**Endpoint:** `DELETE /auth/sessions/{session_id}`

```bash
curl -X DELETE http://localhost:8080/auth/sessions/sess_abc123 \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### Generate API Key

**Endpoint:** `POST /auth/api-keys`

```bash
curl -X POST http://localhost:8080/auth/api-keys \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Mobile App Integration",
    "scopes": ["read:profile", "write:profile"],
    "expires_in_days": 90
  }'
```

**Response:**
```json
{
  "api_key_id": "ak_550e8400e29b41d4a716446655440000",
  "api_key": "sk_live_abc123xyz789...",
  "name": "Mobile App Integration",
  "scopes": ["read:profile", "write:profile"],
  "created_at": "2024-01-15T10:30:00Z",
  "expires_at": "2024-04-15T10:30:00Z"
}
```

### API Key Authentication

```bash
# Use API key in header
curl -H "Authorization: Bearer sk_live_abc123xyz789..." \
  http://localhost:8080/auth/profile

# Or use X-API-Key header
curl -H "X-API-Key: sk_live_abc123xyz789..." \
  http://localhost:8080/auth/profile
```

## 🔒 Authorization & Policies

### Check Permissions

**Endpoint:** `POST /policies/check`

```bash
curl -X POST http://localhost:8080/policies/check \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": "document:123",
    "action": "read",
    "context": {
      "department": "engineering",
      "project": "alpha"
    }
  }'
```

**Response:**
```json
{
  "allowed": true,
  "reason": "User has read permission for documents in engineering department",
  "policy_id": "policy_abc123",
  "decision_time": "2024-01-15T10:30:00Z"
}
```

### Batch Permission Check

**Endpoint:** `POST /policies/batch-check`

```bash
curl -X POST http://localhost:8080/policies/batch-check \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "resource": "document:123",
        "action": "read"
      },
      {
        "resource": "document:123", 
        "action": "write"
      },
      {
        "resource": "project:alpha",
        "action": "admin"
      }
    ]
  }'
```

**Response:**
```json
{
  "results": [
    {
      "resource": "document:123",
      "action": "read",
      "allowed": true,
      "reason": "User has read access"
    },
    {
      "resource": "document:123",
      "action": "write", 
      "allowed": false,
      "reason": "Write access denied"
    },
    {
      "resource": "project:alpha",
      "action": "admin",
      "allowed": false,
      "reason": "Admin role required"
    }
  ]
}
```

### List User Policies

**Endpoint:** `GET /policies/user/{user_id}`

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/policies/user/550e8400-e29b-41d4-a716-446655440000
```

## 🛡️ Security Features

### Enable MFA

**Endpoint:** `POST /auth/mfa/enable`

```bash
# Enable TOTP MFA
curl -X POST http://localhost:8080/auth/mfa/enable \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "totp"
  }'
```

**Response:**
```json
{
  "method": "totp",
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "https://api.qrserver.com/v1/create-qr-code/?data=otpauth://totp/...",
  "backup_codes": [
    "12345678",
    "87654321",
    "11111111",
    "22222222",
    "33333333"
  ],
  "enabled": false
}
```

### Verify MFA Setup

**Endpoint:** `PUT /auth/mfa/enable`

```bash
curl -X PUT http://localhost:8080/auth/mfa/enable \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "totp",
    "code": "123456"
  }'
```

### Security Events

**Endpoint:** `GET /auth/security-events`

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "http://localhost:8080/auth/security-events?limit=10&offset=0"
```

**Response:**
```json
{
  "events": [
    {
      "event_id": "evt_abc123",
      "event_type": "failed_login",
      "severity": "medium",
      "timestamp": "2024-01-15T10:25:00Z",
      "details": {
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "reason": "invalid_password"
      }
    },
    {
      "event_id": "evt_def456",
      "event_type": "password_changed",
      "severity": "low",
      "timestamp": "2024-01-15T10:30:00Z",
      "details": {
        "ip_address": "192.168.1.100"
      }
    }
  ],
  "total_count": 25,
  "has_more": true
}
```

### Device Management

**Endpoint:** `GET /auth/devices`

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/auth/devices
```

**Response:**
```json
{
  "devices": [
    {
      "device_id": "dev_abc123",
      "device_name": "MacBook Pro",
      "device_type": "web", 
      "user_agent": "Mozilla/5.0...",
      "ip_address": "192.168.1.100",
      "location": "New York, NY",
      "trusted": true,
      "last_seen": "2024-01-15T10:30:00Z",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total_count": 1
}
```

## 📊 Monitoring & Analytics

### User Analytics

**Endpoint:** `GET /auth/analytics`

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "http://localhost:8080/auth/analytics?period=7d&metrics=logins,registrations"
```

**Response:**
```json
{
  "period": "7d",
  "metrics": {
    "logins": {
      "total": 156,
      "daily_breakdown": [
        {"date": "2024-01-09", "count": 23},
        {"date": "2024-01-10", "count": 19},
        {"date": "2024-01-11", "count": 25},
        {"date": "2024-01-12", "count": 22},
        {"date": "2024-01-13", "count": 21},
        {"date": "2024-01-14", "count": 24},
        {"date": "2024-01-15", "count": 22}
      ]
    },
    "registrations": {
      "total": 12,
      "daily_breakdown": [
        {"date": "2024-01-09", "count": 2},
        {"date": "2024-01-10", "count": 1},
        {"date": "2024-01-11", "count": 3},
        {"date": "2024-01-12", "count": 1},
        {"date": "2024-01-13", "count": 2},
        {"date": "2024-01-14", "count": 2},
        {"date": "2024-01-15", "count": 1}
      ]
    }
  }
}
```

### Health Check

**Endpoint:** `GET /health`

```bash
curl http://localhost:8080/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.2.0",
  "uptime": 345600,
  "checks": {
    "database": "healthy",
    "redis": "healthy", 
    "external_services": "healthy"
  }
}
```

### Metrics (Prometheus)

**Endpoint:** `GET /metrics`

```bash
curl http://localhost:8080/metrics
```

**Response:**
```
# HELP auth_requests_total Total number of authentication requests
# TYPE auth_requests_total counter
auth_requests_total{method="login",status="success"} 1234
auth_requests_total{method="login",status="failure"} 56

# HELP auth_request_duration_seconds Authentication request duration
# TYPE auth_request_duration_seconds histogram
auth_request_duration_seconds_bucket{method="login",le="0.1"} 892
auth_request_duration_seconds_bucket{method="login",le="0.5"} 1180
auth_request_duration_seconds_bucket{method="login",le="1.0"} 1250
```

## 🚨 Error Handling

### Error Response Format

All errors follow RFC 7807 (Problem Details for HTTP APIs):

```json
{
  "type": "https://auth.yourdomain.com/errors/invalid-credentials",
  "title": "Invalid Credentials",
  "status": 401,
  "detail": "The provided username or password is incorrect",
  "instance": "/auth/login",
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_abc123",
  "errors": [
    {
      "field": "password",
      "code": "invalid",
      "message": "Password does not match our records"
    }
  ]
}
```

### Common Error Codes

#### Authentication Errors (4xx)

```json
// 400 Bad Request
{
  "type": "https://auth.yourdomain.com/errors/validation-failed",
  "title": "Validation Failed",
  "status": 400,
  "detail": "One or more fields contain invalid data",
  "errors": [
    {
      "field": "email",
      "code": "invalid_format",
      "message": "Email address format is invalid"
    }
  ]
}

// 401 Unauthorized
{
  "type": "https://auth.yourdomain.com/errors/invalid-credentials", 
  "title": "Invalid Credentials",
  "status": 401,
  "detail": "The provided credentials are incorrect"
}

// 403 Forbidden
{
  "type": "https://auth.yourdomain.com/errors/insufficient-permissions",
  "title": "Insufficient Permissions", 
  "status": 403,
  "detail": "You don't have permission to access this resource"
}

// 404 Not Found
{
  "type": "https://auth.yourdomain.com/errors/resource-not-found",
  "title": "Resource Not Found",
  "status": 404,
  "detail": "The requested resource could not be found"
}

// 409 Conflict
{
  "type": "https://auth.yourdomain.com/errors/conflict",
  "title": "Conflict",
  "status": 409, 
  "detail": "A user with this email address already exists"
}

// 429 Too Many Requests
{
  "type": "https://auth.yourdomain.com/errors/rate-limit-exceeded",
  "title": "Rate Limit Exceeded",
  "status": 429,
  "detail": "Too many requests. Try again later",
  "retry_after": 60
}
```

#### Server Errors (5xx)

```json
// 500 Internal Server Error
{
  "type": "https://auth.yourdomain.com/errors/internal-error",
  "title": "Internal Server Error", 
  "status": 500,
  "detail": "An unexpected error occurred"
}

// 502 Bad Gateway
{
  "type": "https://auth.yourdomain.com/errors/service-unavailable",
  "title": "Service Unavailable",
  "status": 502,
  "detail": "A required service is currently unavailable"
}

// 503 Service Unavailable
{
  "type": "https://auth.yourdomain.com/errors/maintenance",
  "title": "Service Under Maintenance",
  "status": 503,
  "detail": "The service is temporarily unavailable due to maintenance"
}
```

### Error Handling Best Practices

```javascript
// Example error handling in JavaScript
async function loginUser(credentials) {
  try {
    const response = await fetch('/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(credentials)
    });
    
    if (!response.ok) {
      const error = await response.json();
      
      // Handle specific error types
      switch (error.status) {
        case 401:
          throw new Error('Invalid username or password');
        case 429:
          throw new Error(`Too many attempts. Try again in ${error.retry_after} seconds`);
        case 500:
          throw new Error('Server error. Please try again later');
        default:
          throw new Error(error.detail || 'An unexpected error occurred');
      }
    }
    
    return await response.json();
  } catch (error) {
    console.error('Login failed:', error);
    throw error;
  }
}
```

## 💡 Best Practices

### Security Best Practices

```javascript
// 1. Always use HTTPS in production
const apiBaseUrl = process.env.NODE_ENV === 'production' 
  ? 'https://auth.yourdomain.com'
  : 'http://localhost:8080';

// 2. Store tokens securely
// ❌ Don't store in localStorage
localStorage.setItem('access_token', token);

// ✅ Use httpOnly cookies or secure storage
// Set tokens as httpOnly cookies on server
// Or use browser's Credential Management API

// 3. Handle token expiration gracefully
async function apiCall(url, options = {}) {
  let token = getAccessToken();
  
  const response = await fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${token}`
    }
  });
  
  // Token expired, try to refresh
  if (response.status === 401) {
    token = await refreshAccessToken();
    
    // Retry with new token
    return fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`
      }
    });
  }
  
  return response;
}

// 4. Validate input on client side
function validateRegistration(data) {
  const errors = [];
  
  if (!data.email || !isValidEmail(data.email)) {
    errors.push('Valid email address is required');
  }
  
  if (!data.password || data.password.length < 12) {
    errors.push('Password must be at least 12 characters');
  }
  
  return errors;
}
```

### Performance Best Practices

```javascript
// 1. Cache user data appropriately
const userCache = new Map();

async function getUserProfile(userId) {
  if (userCache.has(userId)) {
    return userCache.get(userId);
  }
  
  const user = await fetchUserProfile(userId);
  userCache.set(userId, user);
  
  // Cache for 5 minutes
  setTimeout(() => userCache.delete(userId), 5 * 60 * 1000);
  
  return user;
}

// 2. Batch permission checks
async function checkMultiplePermissions(requests) {
  // ✅ Batch requests
  const response = await fetch('/policies/batch-check', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ requests })
  });
  
  return response.json();
}

// ❌ Don't make individual requests
// const permissions = await Promise.all(
//   requests.map(req => checkPermission(req))
// );

// 3. Use appropriate timeout values
const fetchWithTimeout = (url, options, timeout = 5000) => {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Request timeout')), timeout)
    )
  ]);
};
```

### Integration Patterns

```javascript
// 1. Middleware pattern for authentication
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Token required' });
  }
  
  // Verify token with auth service
  verifyToken(token)
    .then(user => {
      req.user = user;
      next();
    })
    .catch(error => {
      res.status(401).json({ error: 'Invalid token' });
    });
}

// 2. Retry with exponential backoff
async function apiCallWithRetry(url, options, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url, options);
      
      if (response.ok || response.status < 500) {
        return response;
      }
      
      throw new Error(`HTTP ${response.status}`);
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      
      // Exponential backoff: 1s, 2s, 4s
      const delay = Math.pow(2, i) * 1000;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// 3. Circuit breaker pattern
class CircuitBreaker {
  constructor(threshold = 5, timeout = 60000) {
    this.threshold = threshold;
    this.timeout = timeout;
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
  }
  
  async call(fn) {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime > this.timeout) {
        this.state = 'HALF_OPEN';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }
    
    try {
      const result = await fn();
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
    this.lastFailureTime = Date.now();
    
    if (this.failureCount >= this.threshold) {
      this.state = 'OPEN';
    }
  }
}
```

## 🔧 SDKs & Examples

### JavaScript/Node.js SDK

```bash
npm install rust-security-sdk
```

```javascript
import { RustSecurityClient } from 'rust-security-sdk';

const client = new RustSecurityClient({
  baseUrl: 'https://auth.yourdomain.com',
  apiKey: 'your-api-key'
});

// Register user
const user = await client.auth.register({
  username: 'john_doe',
  email: 'john@company.com',
  password: 'SecurePassword123!'
});

// Login
const session = await client.auth.login({
  username: 'john_doe',
  password: 'SecurePassword123!'
});

// Check permission
const allowed = await client.policies.check({
  resource: 'document:123',
  action: 'read'
});
```

### Python SDK

```bash
pip install rust-security-sdk
```

```python
from rust_security_sdk import RustSecurityClient

client = RustSecurityClient(
    base_url='https://auth.yourdomain.com',
    api_key='your-api-key'
)

# Register user
user = client.auth.register(
    username='john_doe',
    email='john@company.com', 
    password='SecurePassword123!'
)

# Login
session = client.auth.login(
    username='john_doe',
    password='SecurePassword123!'
)

# Check permission
allowed = client.policies.check(
    resource='document:123',
    action='read'
)
```

### cURL Examples

```bash
# Complete authentication flow
#!/bin/bash

BASE_URL="http://localhost:8080"

# 1. Register user
echo "=== Registering User ==="
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "demo_user",
    "email": "demo@example.com",
    "password": "SecurePassword123!"
  }')

echo $REGISTER_RESPONSE | jq .

# 2. Login
echo -e "\n=== Logging In ==="
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "demo_user",
    "password": "SecurePassword123!"
  }')

echo $LOGIN_RESPONSE | jq .

# Extract access token
ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.access_token')

# 3. Get profile
echo -e "\n=== Getting Profile ==="
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$BASE_URL/auth/profile" | jq .

# 4. Update profile
echo -e "\n=== Updating Profile ==="
curl -s -X PUT "$BASE_URL/auth/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": {
      "first_name": "Demo",
      "last_name": "User"
    }
  }' | jq .

# 5. Check permissions
echo -e "\n=== Checking Permissions ==="
curl -s -X POST "$BASE_URL/policies/check" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": "document:123",
    "action": "read"
  }' | jq .

# 6. Logout
echo -e "\n=== Logging Out ==="
curl -s -X POST "$BASE_URL/auth/logout" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .

echo -e "\n=== Authentication Flow Complete ==="
```

## 🔗 Interactive API Documentation

### Swagger UI

Visit the interactive API documentation when the service is running:

```
http://localhost:8080/docs
```

### ReDoc

Alternative documentation interface:

```
http://localhost:8080/redoc
```

### OpenAPI Specification

Download the OpenAPI spec:

```bash
curl http://localhost:8080/openapi.json > api-spec.json
```

---

## 📞 Support

- 📧 **API Support**: api-support@company.com
- 💬 **Developer Community**: [Join our Discord](https://discord.gg/rust-security)
- 🐛 **Report Issues**: [GitHub Issues](https://github.com/your-org/rust-security-platform/issues)
- 📚 **Documentation**: [Full API Reference](../api/README.md)

---

**Happy integrating! 🚀💻**