# Auth Service

The Auth Service is the core authentication component of the Rust Security Platform, providing OAuth 2.0, OpenID Connect, and user management functionality.

## Overview

The Auth Service implements industry-standard authentication protocols with enterprise-grade security features. It provides a complete authentication solution with support for multiple authentication factors, comprehensive session management, and advanced threat detection.

## Features

### Authentication Protocols
- **OAuth 2.0**: Full RFC 6749 implementation
- **OpenID Connect**: OIDC Core 1.0 compliant
- **SCIM 2.0**: User and group provisioning
- **SAML 2.0**: (Implementation in progress)

### Security Features
- **Multi-Factor Authentication**: TOTP, WebAuthn, SMS
- **Token Management**: JWT with RS256 signing
- **Session Management**: Secure session handling with Redis
- **Rate Limiting**: Adaptive rate limiting and DDoS protection
- **Threat Detection**: Real-time security monitoring

### Performance
- **Sub-50ms authentication latency**
- **10,000+ requests per second throughput**
- **Horizontal scaling support**
- **Intelligent caching strategies**

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AUTH SERVICE                             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   API       │  │  Business   │  │   Data      │         │
│  │  Layer      │  │   Logic     │  │  Access     │         │
│  │             │  │             │  │             │         │
│  │ • HTTP      │  │ • OAuth     │  │ • Redis     │         │
│  │ • Middleware│  │ • Token     │  │ • Database  │         │
│  │ • Validation│  │ • User      │  │ • Cache     │         │
│  └─────────────┘  │ • MFA       │  └─────────────┘         │
│                   │ • Session   │                          │
│                   └─────────────┘                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Security   │  │ Monitoring  │  │   Infra     │         │
│  │             │  │             │  │             │         │
│  │ • JWT       │  │ • Metrics   │  │ • Config    │         │
│  │ • Crypto    │  │ • Logging   │  │ • Health    │         │
│  │ • TLS       │  │ • Tracing   │  │ • Shutdown  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## Key Components

### OAuth 2.0 Provider
- Authorization Code Flow with PKCE
- Client Credentials Flow
- Refresh Token Flow
- Resource Owner Password Credentials Flow

### OpenID Connect Provider
- ID Token generation and validation
- UserInfo endpoint
- Discovery endpoint
- Dynamic client registration

### Multi-Factor Authentication
- **TOTP**: Time-based one-time passwords
- **WebAuthn**: FIDO2/WebAuthn support
- **SMS**: SMS-based one-time passwords
- **Backup Codes**: Recovery codes

### Session Management
- Secure session handling
- Session timeout and cleanup
- Concurrent session control
- Session revocation

### Token Management
- JWT token generation and validation
- Token binding and replay attack prevention
- Refresh token rotation
- Token revocation

## API Endpoints

### OAuth 2.0 Endpoints
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `POST /oauth/introspect` - Token introspection
- `POST /oauth/revoke` - Token revocation

### OIDC Endpoints
- `GET /oauth/userinfo` - User information
- `GET /.well-known/openid-configuration` - Discovery
- `GET /.well-known/jwks.json` - JSON Web Key Set

### User Management
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout
- `GET /api/v1/auth/me` - User profile

### MFA Endpoints
- `POST /mfa/totp/setup` - TOTP setup
- `POST /mfa/totp/verify` - TOTP verification
- `POST /mfa/webauthn/register` - WebAuthn registration
- `POST /mfa/webauthn/verify` - WebAuthn verification

### SCIM 2.0 Endpoints
- `GET /scim/v2/Users` - List users
- `POST /scim/v2/Users` - Create user
- `GET /scim/v2/Users/{id}` - Get user
- `PUT /scim/v2/Users/{id}` - Update user
- `DELETE /scim/v2/Users/{id}` - Delete user

### Administration
- `GET /admin/health` - Health check
- `GET /admin/metrics` - Prometheus metrics
- `GET /admin/status` - Service status

## Configuration

### Environment Variables

```bash
# Server Configuration
PORT=8080
BIND_ADDRESS=0.0.0.0
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com

# Database Configuration
DATABASE_URL=postgresql://user:pass@localhost:5432/auth_service
DATABASE_POOL_SIZE=10

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_POOL_SIZE=10

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-key-32-chars-min
JWT_EXPIRATION=3600

# Security Configuration
MFA_REQUIRED=false
PKCE_REQUIRED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=100
```

### Configuration File

```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 8080
  allowed_origins:
    - "https://app.example.com"
    - "https://admin.example.com"

database:
  url: "postgresql://user:pass@localhost:5432/auth_service"
  pool_size: 10

redis:
  url: "redis://localhost:6379"
  pool_size: 10

jwt:
  secret: "your-super-secure-jwt-secret-key-32-chars-min"
  expiration: 3600

security:
  mfa_required: false
  pkce_required: true
  rate_limit:
    requests_per_minute: 100
    burst_size: 10
```

## Running the Service

### Development

```bash
# Run with default configuration
cargo run -p auth-service

# Run with custom environment
PORT=8080 cargo run -p auth-service

# Run with configuration file
CONFIG_FILE=config.yaml cargo run -p auth-service
```

### Production

```bash
# Build optimized binary
cargo build --release -p auth-service

# Run optimized binary
./target/release/auth-service
```

### Docker

```bash
# Build Docker image
docker build -t auth-service -f Dockerfile.prod .

# Run Docker container
docker run -p 8080:8080 auth-service
```

## Testing

### Unit Tests

```bash
# Run unit tests
cargo test -p auth-service --lib

# Run specific test
cargo test -p auth-service test_oauth_flow
```

### Integration Tests

```bash
# Run integration tests
cargo test -p auth-service --test '*'
```

### Security Tests

```bash
# Run security tests
cargo test -p auth-service --features security-tests
```

## Monitoring

### Metrics

The service exposes Prometheus metrics at `/admin/metrics`:

- `auth_requests_total` - Total authentication requests
- `auth_request_duration_seconds` - Request duration
- `auth_tokens_active_total` - Active tokens
- `auth_sessions_active_total` - Active sessions
- `auth_mfa_verifications_total` - MFA verifications

### Health Checks

- `GET /admin/health` - Basic health check
- `GET /admin/status` - Detailed status information

### Distributed Tracing

OpenTelemetry tracing is available for request tracking and performance monitoring.

## Security

### Cryptographic Security

- **JWT Signing**: RS256 with 2048-bit keys
- **Password Hashing**: Argon2 with secure parameters
- **MFA Secrets**: Secure random generation
- **TLS**: TLS 1.3 support

### Threat Protection

- **Rate Limiting**: Adaptive rate limiting
- **MFA Enforcement**: Multi-factor authentication
- **Session Security**: Secure session management
- **Token Security**: Token binding and validation

## Performance

### Benchmarks

- **Authentication**: <50ms P95 latency
- **Token Validation**: <10ms P95 latency
- **Throughput**: >10,000 requests/second
- **Concurrency**: Horizontal scaling support

### Optimization Strategies

- **Caching**: Multi-level caching strategy
- **Connection Pooling**: Efficient resource utilization
- **Async Processing**: Non-blocking operations
- **Memory Management**: Efficient memory usage

## Contributing

### Development Setup

```bash
# Install dependencies
cargo build -p auth-service

# Run tests
cargo test -p auth-service

# Run linter
cargo clippy -p auth-service

# Format code
cargo fmt -p auth-service
```

### Code Standards

- Follow Rust naming conventions
- Write comprehensive documentation
- Include tests for new functionality
- Maintain 80%+ test coverage
- Use error handling appropriately
- Follow security best practices

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check port availability
netstat -tlnp | grep :8080

# Verify configuration
cargo run --bin auth-service -- --validate-config

# Check dependencies
redis-cli ping
pg_isready -h localhost -p 5432
```

#### Authentication Failures
```bash
# Check JWT configuration
curl http://localhost:8080/.well-known/jwks.json

# Validate token
curl -X POST http://localhost:8080/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_TOKEN"
```

#### Performance Issues
```bash
# Check metrics
curl http://localhost:8080/metrics | grep -E "(request_duration|error_rate)"

# Monitor resource usage
docker stats
```

## Documentation

For comprehensive documentation, see:
- [API Reference](../../docs/03-api-reference/authentication.md)
- [Security Documentation](../../docs/04-security/authentication-security.md)
- [Architecture Documentation](../../docs/02-core-concepts/components.md)

## License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.