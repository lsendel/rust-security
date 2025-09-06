# API Reference Overview

## Introduction

The Rust Security Platform provides a comprehensive set of APIs for authentication, authorization, user management, and security monitoring. These APIs are designed to be RESTful, secure, and highly performant, leveraging Rust's memory safety and performance characteristics.

## Overview

This document provides an overview of the API reference documentation for the Rust Security Platform. The APIs implement industry-standard protocols and security practices to ensure secure and reliable integration with external applications and services. These APIs are designed to be RESTful, secure, and highly performant, leveraging Rust's memory safety and performance characteristics.

## Core Components

The platform consists of several core services, each with its own API:

1. **Auth Service** (`http://localhost:8080`) - Handles authentication, OAuth 2.0 flows, user management, and token operations
2. **Policy Service** (`http://localhost:8081`) - Manages authorization policies and makes access control decisions
3. **Monitoring Service** (`http://localhost:8082`) - Provides security monitoring, threat detection, and audit capabilities

## API Design Principles

### RESTful Design
- Resource-oriented URLs
- Standard HTTP methods (GET, POST, PUT, DELETE)
- Proper HTTP status codes
- JSON request/response bodies

### Security First
- All APIs use HTTPS in production
- OAuth 2.0 and OpenID Connect compliant
- Token-based authentication
- Rate limiting and threat detection
- Input validation and sanitization

### Performance Optimized
- Sub-50ms response times for most operations
- Efficient caching strategies
- Connection pooling support
- Streaming for large data transfers

## Authentication

All protected endpoints require authentication. The platform supports multiple authentication methods:

### OAuth 2.0 Flows
- **Client Credentials** - Service-to-service authentication
- **Password Grant** - User authentication with username/password
- **Authorization Code** - Web application authentication
- **Refresh Token** - Token renewal

### Token Types
- **Access Tokens** - Short-lived tokens for API access
- **Refresh Tokens** - Long-lived tokens for token renewal
- **ID Tokens** - User identity information (OpenID Connect)

## Rate Limiting

The platform implements rate limiting to prevent abuse and ensure fair usage:

- **Per IP**: 100 requests/minute
- **Per Client**: 1000 requests/minute
- **Per User**: 500 requests/minute
- **Adaptive**: Dynamic rate limiting based on threat detection

Rate limit headers are included in all responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Error Handling

All APIs return consistent error responses with appropriate HTTP status codes:

```json
{
  "error": "invalid_request",
  "error_description": "Missing required parameter: grant_type",
  "error_uri": "https://docs.rust-security.dev/errors/invalid_request"
}
```

Common HTTP status codes:
- **200** - Success
- **201** - Created
- **400** - Bad Request
- **401** - Unauthorized
- **403** - Forbidden
- **404** - Not Found
- **429** - Too Many Requests
- **500** - Internal Server Error

## Versioning

APIs are versioned using semantic versioning. Breaking changes increment the major version number. Version can be specified in headers:

```
Accept: application/json; version=1
API-Version: 1.0
```

## Environments

The platform supports multiple environments:

| Environment | Base URL | Purpose |
|-------------|----------|---------|
| Development | `http://localhost:8080` | Local development |
| Staging | `https://auth-staging.example.com` | Integration testing |
| Production | `https://auth.example.com` | Live service |

## SDK Support

Official SDKs are available for multiple languages:
- **Rust** - Native Rust client
- **JavaScript/TypeScript** - Node.js and browser support
- **Python** - Python client library
- **Java** - Java client library
- **Go** - Go client library

## Getting Started

To get started with the APIs:

1. Register an OAuth client in the admin console
2. Obtain an access token using one of the OAuth flows
3. Use the access token to make authenticated requests
4. Handle rate limiting and error responses appropriately

For detailed endpoint documentation, see the specific API sections:
- [Authentication API](authentication.md)
- [Authorization API](authorization.md)
- [User Management API](user-management.md)
- [Token Management API](token-management.md)