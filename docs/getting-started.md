# Getting Started Guide

This guide will help you get the Rust Authentication Service up and running quickly for development and testing.

## Prerequisites

### System Requirements
- **Rust**: 1.70+ (latest stable recommended)
- **Redis**: 6.0+ (for session storage and rate limiting)
- **PostgreSQL**: 12+ (optional, for production persistence)
- **Docker**: 20.10+ (optional, for containerized deployment)

### Development Tools
- **Git**: For version control
- **Cargo**: Rust package manager (included with Rust)
- **OpenSSL**: For TLS support

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/rust-security.git
cd rust-security/auth-service
```

### 2. Install Rust

If you don't have Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 3. Install Dependencies

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install pkg-config libssl-dev

# Install system dependencies (macOS)
brew install pkg-config openssl

# Install Rust dependencies
cargo build
```

### 4. Set Up Redis

#### Using Docker
```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

#### Using Package Manager
```bash
# Ubuntu/Debian
sudo apt install redis-server

# macOS
brew install redis
brew services start redis
```

### 5. Configuration

Create your environment configuration:

```bash
cp .env.example .env
```

Edit `.env` with your settings:

```env
# Server Configuration
BIND_ADDR=127.0.0.1:8080
EXTERNAL_BASE_URL=http://localhost:8080

# Redis Configuration
REDIS_URL=redis://127.0.0.1:6379

# Security Configuration
CLIENT_CREDENTIALS=client1:secret1,client2:secret2
ALLOWED_SCOPES=openid,profile,email,admin
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080

# Token Configuration
TOKEN_EXPIRY_SECONDS=3600
REFRESH_TOKEN_EXPIRY_SECONDS=1209600

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=100

# Feature Flags
TEST_MODE=1
```

## Running the Service

### Development Mode

```bash
# Run with debug logging
RUST_LOG=debug cargo run --bin auth-service

# Run with specific features
cargo run --bin auth-service --features docs,benchmarks
```

The service will start on `http://localhost:8080` by default.

### Docker Mode

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f auth-service
```

## Verification

### 1. Health Check

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
  "status": "ok"
}
```

### 2. OIDC Discovery

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

This should return the OpenID Connect configuration.

### 3. API Documentation

If you enabled the `docs` feature, visit:
- Swagger UI: `http://localhost:8080/docs`
- OpenAPI JSON: `http://localhost:8080/openapi.json`

## Basic Authentication Flow

### 1. Client Credentials Flow

```bash
# Request a token using client credentials
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=client1&client_secret=secret1&scope=openid"
```

### 2. Authorization Code Flow

```bash
# Step 1: Get authorization code
curl "http://localhost:8080/oauth/authorize?response_type=code&client_id=client1&redirect_uri=http://localhost:3000/callback&scope=openid&state=xyz123"

# Step 2: Exchange code for token (use the code from step 1)
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:3000/callback&client_id=client1&client_secret=secret1"
```

### 3. Token Introspection

```bash
# Introspect a token
curl -X POST http://localhost:8080/oauth/introspect \
  -H "Authorization: Basic $(echo -n 'client1:secret1' | base64)" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_ACCESS_TOKEN"
```

## Multi-Factor Authentication

### 1. TOTP Registration

```bash
# Register TOTP for a user
curl -X POST http://localhost:8080/mfa/totp/register \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user123"}'
```

### 2. TOTP Verification

```bash
# Verify TOTP code
curl -X POST http://localhost:8080/mfa/totp/verify \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user123", "code": "123456"}'
```

## Session Management

### 1. Create Session

```bash
curl -X POST http://localhost:8080/session/create \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user123", "duration": 3600}'
```

### 2. Get Session

```bash
curl http://localhost:8080/session/SESSION_ID \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## SCIM User Management

### 1. List Users

```bash
curl http://localhost:8080/scim/v2/Users \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 2. Create User

```bash
curl -X POST http://localhost:8080/scim/v2/Users \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "testuser",
    "name": {
      "familyName": "User",
      "givenName": "Test"
    },
    "emails": [{
      "value": "test@example.com",
      "primary": true
    }]
  }'
```

## Development Tools

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test integration_tests

# Run with specific features
cargo test --features threat-hunting,soar
```

### Benchmarking

```bash
# Run performance benchmarks
cargo bench --features benchmarks

# Generate performance reports
cargo bench --features benchmarks -- --output-format html
```

### Security Testing

```bash
# Run security tests
cargo test security

# Run threat hunting tests
cargo test threat_hunting --features threat-hunting

# Run SOAR tests
cargo test soar --features soar
```

## Monitoring and Observability

### Metrics

The service exposes Prometheus metrics at `/metrics`:

```bash
curl http://localhost:8080/metrics
```

### Security Monitoring

Enable security monitoring for threat detection:

```bash
# Check security alerts
curl http://localhost:8080/admin/security/alerts \
  -H "Authorization: Bearer ADMIN_TOKEN"

# Check security configuration
curl http://localhost:8080/admin/security/config \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

### Rate Limiting Stats

```bash
# Get rate limiting statistics
curl http://localhost:8080/admin/rate-limit/stats \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

## Common Configuration Patterns

### Production-Ready Configuration

```env
# Production settings
BIND_ADDR=0.0.0.0:8080
EXTERNAL_BASE_URL=https://auth.yourcompany.com
REDIS_URL=redis://redis.yourcompany.com:6379
TOKEN_EXPIRY_SECONDS=900
RATE_LIMIT_REQUESTS_PER_MINUTE=60
LOG_LEVEL=info
```

### High-Security Configuration

```env
# High-security settings
TOKEN_EXPIRY_SECONDS=300
REFRESH_TOKEN_EXPIRY_SECONDS=86400
RATE_LIMIT_REQUESTS_PER_MINUTE=30
POLICY_ENFORCEMENT=strict
MFA_REQUIRED=true
```

### Development Configuration

```env
# Development settings
RUST_LOG=debug
TEST_MODE=1
RATE_LIMIT_REQUESTS_PER_MINUTE=1000
TOKEN_EXPIRY_SECONDS=3600
```

## Next Steps

1. **Security Setup**: Configure MFA and security policies - see [Security Guide](./security/README.md)
2. **Integration**: Integrate with your applications - see [Integration Guide](./integration/README.md)
3. **Production**: Deploy to production - see [Deployment Guide](./deployment/README.md)
4. **Monitoring**: Set up comprehensive monitoring - see [Operations Guide](./operations/README.md)

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   ```bash
   # Check Redis is running
   redis-cli ping
   
   # Check Redis connectivity
   telnet localhost 6379
   ```

2. **Port Already in Use**
   ```bash
   # Find process using port 8080
   lsof -i :8080
   
   # Kill the process
   kill -9 PID
   ```

3. **SSL/TLS Issues**
   ```bash
   # Install OpenSSL development headers
   sudo apt install libssl-dev pkg-config
   ```

For more detailed troubleshooting, see the [Troubleshooting Guide](./troubleshooting/README.md).

## Support

- **Documentation**: This documentation site
- **Issues**: [GitHub Issues](https://github.com/your-org/rust-security/issues)
- **Security**: [Security Policy](../SECURITY.md)
- **Community**: [GitHub Discussions](https://github.com/your-org/rust-security/discussions)