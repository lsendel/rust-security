# MVP OAuth 2.0 Service

A production-ready OAuth 2.0 service with enterprise-grade security validation built on mvp-tools.

## Features

- **OAuth 2.0 Client Credentials Flow**: Standard-compliant token issuance
- **Enhanced Security Validation**: Input sanitization and threat detection
- **Token Introspection**: RFC 7662 compliant token validation
- **JWKS Endpoint**: Public key distribution for JWT verification
- **Health & Metrics**: Monitoring endpoints for operational visibility
- **Policy Engine**: Configurable authorization policies
- **Production Ready**: Docker, security hardening, and observability

## Quick Start

### Development

```bash
# Run the service
cargo run

# Run tests
cargo test

# Service will be available at http://localhost:3000
```

### Production Deployment with Docker

```bash
# Build and start the service
docker-compose up -d

# With reverse proxy and TLS
docker-compose --profile with-proxy up -d
```

## API Endpoints

### OAuth 2.0 Token Endpoint
```bash
POST /oauth/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": "mvp-client", 
  "client_secret": "mvp-secret"
}
```

### Token Introspection
```bash
POST /oauth/introspect
Content-Type: application/json

{
  "token": "your-jwt-token-here"
}
```

### JWKS Public Keys
```bash
GET /.well-known/jwks.json
```

### Service Health
```bash
GET /health
```

### Metrics
```bash
GET /metrics
```

## Security Features

- **Input Validation**: Control character filtering, size limits, injection prevention
- **Threat Detection**: SQL injection, XSS, and DoS protection
- **Security Context**: Request correlation and security incident logging
- **Rate Limiting**: Protection against abuse (when using nginx proxy)
- **Secure Defaults**: Non-root user, read-only filesystem, minimal capabilities

## Configuration

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

Key configuration:
- `JWT_SECRET`: Strong secret for JWT signing (generate with `openssl rand -base64 32`)
- `PORT`: Service port (default: 3000)
- `RUST_LOG`: Logging level (info, debug, warn, error)

## Client Configuration

Default client for testing:
- Client ID: `mvp-client`
- Client Secret: `mvp-secret`

For production, modify the client configuration in `AppState::new()`.

## Architecture

- **mvp-tools**: Core security validation and policy engine
- **common**: Shared utilities across the workspace
- **Axum**: Modern async web framework
- **JWT**: JSON Web Tokens with HS256 signing
- **Enhanced Validation**: Enterprise-grade input sanitization

## Monitoring

The service exposes:
- `/health`: Service status and feature flags
- `/metrics`: Prometheus-compatible metrics
- Structured logging with trace correlation

## Security Considerations

1. **JWT Secret**: Use a strong, randomly generated secret
2. **TLS**: Always use HTTPS in production
3. **CORS**: Restrict origins in production environments
4. **Rate Limiting**: Configure appropriate limits for your use case
5. **Monitoring**: Set up alerts for security incidents
6. **Updates**: Keep dependencies updated for security patches

## License

This is a demonstration MVP implementation. Review and audit before production use.