## Feature Flags and Test Modes

The `auth-service` crate exposes several optional features and a test mode environment flag to control behavior:

- Feature `optimizations`: Enables optional, heavier optimized modules (e.g., advanced async, crypto, and database pooling). This feature is off by default to keep the default build/test surface smaller. Enable via:
  - `cargo build -p auth-service --features optimizations`
  - `cargo test -p auth-service --features optimizations`

- Feature `threat-hunting`: Enables ML/threat-hunting related dependencies and tests. Off by default. Enable via:
  - `cargo test -p auth-service --features threat-hunting`

- Env `TEST_MODE`: Controls certain middleware behaviors for tests.
  - `TEST_MODE=1` bypasses request-signature validation middleware for convenience in broad integration tests.
  - `TEST_MODE=0` keeps signature validation enabled. When testing admin routes, you can sign requests by computing an `x-signature` over `method\npath\nbody\ntimestamp` using HMAC-SHA256 with `REQUEST_SIGNING_SECRET` and including `x-timestamp` (unix seconds).

Policy service behavior for authorization tests:
- If `POLICY_SERVICE_URL` is unreachable and not in strict mode, the service returns `Allow` (permissive fallback).
- Strict mode can be enabled via request header `x-policy-enforcement: strict` or env `POLICY_ENFORCEMENT=strict` and will return 500 when the policy service is unavailable or invalid.

# Rust Security Workspace

Production-ready, enterprise-grade authentication and authorization workspace built with Rust.

## Project Overview

This is a comprehensive Rust-based monorepo for security-focused applications. It consists of three main services and compliance tools: an `auth-service`, a `policy-service`, an `axum-integration-example`, and `compliance-tools`. The services are built using the Axum web framework and the Tokio runtime with extensive security features and production-ready capabilities.

- **`auth-service`**: OAuth2/OIDC-compatible authentication service with advanced security features
- **`policy-service`**: Authorization service using Cedar policy engine for fine-grained access control
- **`axum-integration-example`**: Demonstration application showing integration patterns
- **`compliance-tools`**: Pure Rust compliance reporting and validation tools (replaces previous Python scripts)

## 🚀 Key Features

### Security Features
- ✅ **Multi-Factor Authentication (MFA)**: TOTP support with backup codes
- ✅ **Token Binding**: Prevents token theft by binding tokens to client characteristics
- ✅ **PKCE Support**: Proof Key for Code Exchange for enhanced OAuth2 security
- ✅ **Request Signing**: HMAC-SHA256 request signing for critical operations
- ✅ **Rate Limiting**: Configurable per-client rate limiting with sliding windows
- ✅ **Security Headers**: Comprehensive security headers (CSP, HSTS, etc.)
- ✅ **Input Validation**: Protection against injection attacks and malicious input
- ✅ **Audit Logging**: Structured audit logs for security events
- ✅ **Circuit Breaker**: Fault tolerance for external dependencies

### Authentication & Authorization
- ✅ **OAuth2 Flows**: Client credentials and refresh token flows
- ✅ **OpenID Connect**: Full OIDC support with ID tokens and discovery
- ✅ **JWT Tokens**: Secure JWT token generation and validation
- ✅ **Cedar Policies**: AWS Cedar for attribute-based access control (ABAC)
- ✅ **SCIM Integration**: System for Cross-domain Identity Management
- ✅ **Google OAuth**: OAuth2 integration with Google Identity Platform

### Production Features
- ✅ **Pluggable Storage**: Choose between the default in-memory/Redis hybrid store or a persistent SQL backend.
- ✅ **High Availability**: Redis clustering support with in-memory fallback
- ✅ **Kubernetes Ready**: Complete K8s manifests with security policies
- ✅ **Monitoring**: Prometheus metrics and health checks
- ✅ **Distributed Tracing**: OpenTelemetry support for observability
- ✅ **Graceful Shutdown**: Proper shutdown handling for zero-downtime deployments
- ✅ **Configuration Validation**: Comprehensive startup configuration validation
- ✅ **Docker Support**: Multi-stage builds with security hardening

## Service Architecture

### Auth Service (port 8080)
- `/health` - Health check endpoint
- `/oauth/token` - Issue new access tokens (supports client_credentials and refresh_token)
- `/oauth/introspect` - Validate and check token status
- `/oauth/revoke` - Revoke existing tokens
- `/oauth/authorize` - OAuth2 authorization endpoint
- `/oauth/userinfo` - OIDC UserInfo endpoint
- `/.well-known/openid-configuration` - OIDC discovery document
- `/.well-known/oauth-authorization-server` - OAuth 2.0 authorization server metadata
- `/jwks.json` - JSON Web Key Set for token verification
- `/mfa/totp/register` - TOTP MFA registration
- `/mfa/totp/verify` - TOTP MFA verification
- `/mfa/totp/backup-codes/generate` - Generate backup codes
- `/scim/v2/Users` - SCIM user management
- `/scim/v2/Groups` - SCIM group management
- `/oauth/google/login` - Google OAuth login initiation
- `/oauth/google/callback` - Google OAuth callback
- `/metrics` - Prometheus metrics endpoint
- `/openapi.json` - OpenAPI specification

**Enhanced Token Features:**
- Opaque access tokens with configurable expiration
- Refresh tokens with extended lifetime
- Token binding to prevent theft
- Comprehensive token introspection
- Secure token revocation

**Security Enhancements:**
- Strong JWT secret validation in production
- Client credential strength requirements
- Request signing for critical operations
- Rate limiting with IP-based tracking
- Comprehensive input validation

### Policy Service (port 8081)
- `/health` - Health check endpoint
- `/v1/authorize` - Cedar-based authorization decisions with detailed logging
- `/openapi.json` - OpenAPI specification
- `/metrics` - Prometheus metrics endpoint

**Cedar Policy Features:**
- Multi-tenant ABAC policies
- Attribute-based access control
- Policy evaluation with detailed context
- Audit logging for authorization decisions

### Axum Integration Example (port 3000)
- Complete user management API with authentication
- Database integration (SQLite/PostgreSQL)
- JWT-based authentication middleware
- Role-based authorization
- Password hashing with bcrypt
- Comprehensive validation and error handling

## 🛠 Building and Running

### Prerequisites
- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Docker (for containerized deployment)
- Redis (for production token storage)

### Local Development

```bash
# Build the entire project
cargo build

# Run with all features
cargo build --all-features

# Run the auth-service
cargo run -p auth-service

# Run the policy-service
cargo run -p policy-service

# Run the integration example
cargo run -p axum-integration-example

# Run comprehensive tests
cargo test --all --all-features --verbose
```

### Docker Deployment

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Kubernetes Deployment

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n rust-security

# Port forward for testing
kubectl port-forward svc/auth-service 8080:8080 -n rust-security
```

See [DEPLOYMENT.md](docs/deployment/README.md) for comprehensive deployment instructions.

## 🔧 Configuration

### Environment Variables

#### Auth Service
```bash
# Server Configuration
BIND_ADDR=0.0.0.0:8080
RUST_LOG=info,auth_service=debug
ENVIRONMENT=production  # Enforces strong security in production

# Security Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
CLIENT_CREDENTIALS=client1:secret1;client2:secret2
ALLOWED_SCOPES=read,write,admin
REQUEST_SIGNING_SECRET=your-request-signing-secret

# Token Configuration
TOKEN_EXPIRY_SECONDS=3600
EXTERNAL_BASE_URL=https://auth.example.com

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=120

# Storage Configuration
# STORE_BACKEND=hybrid # Use 'hybrid' (default) or 'sql'
# DATABASE_URL=postgres://user:password@host/database # Required if STORE_BACKEND=sql

# Redis Configuration (used by hybrid store)
REDIS_URL=redis://redis:6379

# CORS Configuration
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com

# Google OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://auth.example.com/oauth/google/callback
```

#### Policy Service
```bash
BIND_ADDR=0.0.0.0:8080
RUST_LOG=info,policy_service=debug
ALLOWED_ORIGINS=*
```

### Security Configuration

#### Production Security Requirements
- JWT secrets must be at least 32 characters
- Client secrets must be at least 8 characters
- Default secrets are rejected in production
- Strong configuration validation at startup

#### Token Binding
Tokens are automatically bound to client IP and User-Agent to prevent token theft.

#### Request Signing
Critical operations require HMAC-SHA256 request signatures:
```bash
# Example signed request
curl -X POST https://auth.example.com/oauth/revoke \
  -H "X-Signature: <hmac-sha256-signature>" \
  -H "X-Timestamp: <unix-timestamp>" \
  -d "token=<token-to-revoke>"
```

## 🧪 Testing

### Unit and Integration Tests
```bash
# Run all tests
cargo test --all --all-features --verbose

# Run specific test suite
cargo test -p auth-service --test comprehensive_integration_test

# Run with coverage
cargo tarpaulin --all --all-features
```

### Load Testing
```bash
# Run load test script
./scripts/load_test.sh http://localhost:8080 10 100

# Custom load test
./scripts/load_test.sh <base-url> <concurrent-users> <requests-per-user>
```

### Security Testing
```bash
# Security audit
cargo audit --deny warnings

# Dependency policy check
cargo deny check --all-features

# Format check
cargo fmt --all -- --check

# Lint check
cargo clippy --all-targets --all-features -- -D warnings
```

## 📊 Monitoring and Observability

### Metrics
- Prometheus metrics at `/metrics` endpoints
- Custom metrics for tokens issued, refreshed, and revoked
- HTTP request metrics with status codes and latencies
- Circuit breaker state metrics

### Health Checks
- Kubernetes-ready health endpoints
- Dependency health checking
- Graceful degradation support

### Distributed Tracing
```bash
# Enable tracing feature
cargo build --features tracing

# Configure Jaeger endpoint
export JAEGER_ENDPOINT=http://jaeger:14268/api/traces
```

### Audit Logging
Structured audit logs for security events:
- Token issuance and revocation
- Authentication attempts
- Authorization decisions
- MFA operations
- Administrative actions

## 🔒 Security Best Practices

### Implemented Security Measures
1. **Defense in Depth**: Multiple security layers
2. **Principle of Least Privilege**: Minimal required permissions
3. **Secure by Default**: Safe default configurations
4. **Input Validation**: Comprehensive input sanitization
5. **Output Encoding**: Proper response encoding
6. **Error Handling**: Secure error messages
7. **Logging**: Security event logging without sensitive data
8. **Monitoring**: Real-time security monitoring

### Security Headers
All responses include comprehensive security headers:
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `X-XSS-Protection`
- `Referrer-Policy`
- `Permissions-Policy`

## 🚀 Production Deployment

### High Availability Setup
- Multiple service replicas
- Redis clustering for token storage
- Load balancing with health checks
- Graceful shutdown handling
- Circuit breaker for fault tolerance

### Kubernetes Features
- Pod Security Standards compliance
- Network policies for traffic isolation
- Resource limits and requests
- Horizontal Pod Autoscaling
- Persistent volume claims for data
- Service mesh ready

### Monitoring Stack
- Prometheus for metrics collection
- Grafana for visualization
- AlertManager for notifications
- Jaeger for distributed tracing
- ELK stack for log aggregation

## 📚 API Documentation

### OpenAPI/Swagger
- Interactive API documentation at `/docs` (when docs feature is enabled)
- OpenAPI specifications at `/openapi.json`
- Comprehensive request/response schemas

### Authentication Flow Examples

#### Client Credentials Flow
```bash
# Request token
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=read write"

# Response
{
  "access_token": "tk_...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "rt_...",
  "scope": "read write",
  "exp": 1234567890,
  "iat": 1234564290
}
```

#### Token Introspection
```bash
curl -X POST http://localhost:8080/oauth/introspect \
  -H "Content-Type: application/json" \
  -d '{"token": "tk_..."}'
```

#### Authorization Decision
```bash
curl -X POST http://localhost:8081/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "req_123",
    "principal": {"type": "User", "id": "user1"},
    "action": "orders:read",
    "resource": {"type": "Order", "id": "order1"},
    "context": {}
  }'
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Run security checks
7. Submit a pull request

### Development Guidelines
- Follow Rust best practices
- Add comprehensive tests
- Update documentation
- Follow security guidelines
- Use conventional commits

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Projects

- [AWS Cedar](https://github.com/cedar-policy/cedar) - Policy language and engine
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [Tokio](https://github.com/tokio-rs/tokio) - Async runtime
- [OpenTelemetry](https://opentelemetry.io/) - Observability framework

## 📞 Support

For questions, issues, or contributions:
- Open an issue on GitHub
- Check the [DEPLOYMENT.md](docs/deployment/README.md) for deployment help
- Review the [SECURITY.md](SECURITY.md) for security considerations

---

**Built with ❤️ and 🦀 Rust for production security workloads.**
