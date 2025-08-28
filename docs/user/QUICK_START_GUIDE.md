# 🚀 Quick Start Guide - Rust Security Platform

Get up and running with the Rust Security Platform in under 10 minutes! This guide will walk you through installation, basic configuration, and your first authentication flow.

## 📋 Table of Contents

- [⚡ 5-Minute Demo](#-5-minute-demo)
- [🔧 Development Setup](#-development-setup)
- [🏗️ Production Deployment](#️-production-deployment)
- [🔐 Basic Authentication Flow](#-basic-authentication-flow)
- [📊 Monitoring Dashboard](#-monitoring-dashboard)
- [🎯 Next Steps](#-next-steps)

## ⚡ 5-Minute Demo

### Prerequisites

```bash
# Required tools
- Docker & Docker Compose
- Git
- curl (for testing)

# Optional but recommended
- Kubernetes CLI (kubectl)
- Rust toolchain (for development)
```

### One-Command Demo

```bash
# Clone and start the demo
git clone https://github.com/your-org/rust-security-platform.git
cd rust-security-platform
./scripts/setup/quick-start.sh

# Select option 4: "Demo Mode"
# This will start:
# ✅ Auth Service (http://localhost:8080)
# ✅ Policy Service (http://localhost:8081)  
# ✅ Redis Cache
# ✅ PostgreSQL Database
# ✅ Grafana Dashboard (http://localhost:3000)
```

### Verify Demo is Running

```bash
# Test auth service health
curl http://localhost:8080/health
# Expected: {"status":"healthy","timestamp":"2024-..."}

# Test policy service health  
curl http://localhost:8081/health
# Expected: {"status":"healthy","timestamp":"2024-..."}

# View metrics
curl http://localhost:8080/metrics
# Expected: Prometheus metrics output
```

### Quick Authentication Test

```bash
# Register a new user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "demo-user",
    "email": "demo@example.com",
    "password": "SecurePassword123!"
  }'

# Login and get access token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "demo-user", 
    "password": "SecurePassword123!"
  }'

# Use the returned access_token for authenticated requests
TOKEN="your-access-token-here"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/auth/profile
```

## 🔧 Development Setup

### Full Development Environment

```bash
# Clone the repository
git clone https://github.com/your-org/rust-security-platform.git
cd rust-security-platform

# Run the interactive setup
./scripts/setup/quick-start.sh

# Select option 1: "Developer Mode"
# This installs all development dependencies and tools
```

### Manual Development Setup

```bash
# 1. Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 2. Install required Rust components
rustup component add rustfmt clippy

# 3. Install development tools
cargo install cargo-watch cargo-audit cargo-deny

# 4. Start development services
docker-compose -f docker-compose.dev.yml up -d

# 5. Run database migrations
cd auth-service
sqlx database create
sqlx migrate run

# 6. Start services in development mode
cargo run --bin auth-service &
cargo run --bin policy-service &
```

### Development Workflow

```bash
# Watch and rebuild on changes
cargo watch -x "run --bin auth-service"

# Run tests
cargo test --workspace --all-features

# Format code
cargo fmt --all

# Lint code
cargo clippy --workspace --all-features -- -D warnings

# Security audit
cargo audit
```

## 🏗️ Production Deployment

### Kubernetes Deployment (Recommended)

```bash
# 1. Prepare Kubernetes cluster
kubectl create namespace rust-security

# 2. Deploy the platform
kubectl apply -f deployment/kubernetes.yaml

# 3. Verify deployment
kubectl get pods -n rust-security
kubectl get services -n rust-security

# 4. Port forward for local access (optional)
kubectl port-forward -n rust-security svc/auth-service-lb 8080:80
```

### Docker Deployment

```bash
# 1. Build production images
docker build -f deployment/Dockerfile -t rust-security:latest .

# 2. Deploy with Docker Compose
docker-compose -f deployment/docker-compose.yml up -d

# 3. Verify deployment
docker ps
curl http://localhost:8080/health
```

### Configuration

#### Environment Variables

```bash
# Required environment variables for production
export DATABASE_URL="postgresql://user:password@localhost:5432/auth_db"
export REDIS_URL="redis://localhost:6379"
export JWT_SECRET="your-super-secure-jwt-secret-key"
export ENCRYPTION_KEY="your-32-character-encryption-key"

# Optional security enhancements
export SECURITY_MONITORING_ENABLED="true"
export JIT_TOKENS_ENABLED="true"
export RATE_LIMITING_ENABLED="true"
```

#### Configuration File

```toml
# config/production.toml
[server]
host = "0.0.0.0"
port = 8080
metrics_port = 9090

[database]
url = "${DATABASE_URL}"
max_connections = 100
connection_timeout = 30

[redis]
url = "${REDIS_URL}"
pool_size = 50
connection_timeout = 5

[security]
jwt_access_token_ttl_seconds = 900      # 15 minutes
jwt_refresh_token_ttl_seconds = 86400   # 24 hours
password_min_length = 12
require_mfa = false

[monitoring]
enable_metrics = true
enable_tracing = true
log_level = "info"
```

## 🔐 Basic Authentication Flow

### User Registration

```bash
# Register a new user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@company.com",
    "password": "MySecurePassword123!",
    "profile": {
      "first_name": "John",
      "last_name": "Doe"
    }
  }'

# Response:
{
  "user_id": "uuid-here",
  "username": "john_doe",
  "email": "john@company.com",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### User Authentication

```bash
# Login with username/password
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "MySecurePassword123!"
  }'

# Response:
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "user_id": "uuid-here",
    "username": "john_doe",
    "email": "john@company.com"
  }
}
```

### Using Access Tokens

```bash
# Make authenticated requests
ACCESS_TOKEN="your-access-token-here"

# Get user profile
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/auth/profile

# Update profile
curl -X PUT http://localhost:8080/auth/profile \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": {
      "first_name": "John",
      "last_name": "Smith",
      "phone": "+1-555-0123"
    }
  }'

# Change password
curl -X PUT http://localhost:8080/auth/password \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "MySecurePassword123!",
    "new_password": "NewSecurePassword456!"
  }'
```

### Token Refresh

```bash
# Refresh expired access token
REFRESH_TOKEN="your-refresh-token-here"

curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "'$REFRESH_TOKEN'"
  }'

# Response:
{
  "access_token": "new-access-token-here",
  "token_type": "Bearer", 
  "expires_in": 900
}
```

## 📊 Monitoring Dashboard

### Access Grafana Dashboard

```bash
# Default credentials (change in production!)
Username: admin
Password: admin

# Dashboard URL
http://localhost:3000

# Pre-built dashboards:
# 1. Authentication Metrics
# 2. Security Events
# 3. Performance Metrics
# 4. System Health
```

### Key Metrics to Monitor

```bash
# Authentication Metrics
- Login success/failure rates
- Token issuance rates
- Password reset requests
- Account lockout events

# Security Metrics
- Failed authentication attempts
- Suspicious user behavior
- Rate limiting violations
- Security rule triggers

# Performance Metrics
- Request latency (p50, p95, p99)
- Throughput (requests per second)
- Error rates
- Database connection pool usage

# System Health
- Service uptime
- Memory usage
- CPU utilization
- Database performance
```

### Alerting Setup

```bash
# Configure alerts in Grafana
1. Go to Alerting > Alert Rules
2. Create alert for high error rate (>5%)
3. Create alert for service down
4. Set notification channels (email, Slack, etc.)

# Test alerts
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"invalid","password":"invalid"}' \
  --max-redirs 0 --retry 10
```

## 🎯 Next Steps

### Integration Examples

```bash
# Explore integration examples
cd examples/
ls -la

# Try the Axum integration example
cd axum-integration-example
cargo run

# Visit http://localhost:3000 for interactive demo
```

### API Documentation

```bash
# Generate API documentation
cargo doc --no-deps --all-features --workspace --open

# Interactive API docs (when service is running)
open http://localhost:8080/docs     # Swagger UI
open http://localhost:8080/redoc    # ReDoc
```

### Advanced Configuration

```bash
# Enable multi-factor authentication
export MFA_ENABLED="true"

# Enable advanced security monitoring
export BEHAVIORAL_ANALYSIS_ENABLED="true"
export GEO_ANOMALY_DETECTION_ENABLED="true"

# Configure external secrets management
export SECRETS_PROVIDER="vault"  # or "aws", "gcp"
export VAULT_ADDRESS="https://vault.company.com"
```

### Production Checklist

```bash
# Before going to production:
- [ ] Change default passwords and secrets
- [ ] Configure HTTPS/TLS certificates
- [ ] Set up backup and disaster recovery
- [ ] Configure monitoring and alerting
- [ ] Implement log aggregation
- [ ] Set up security scanning
- [ ] Configure auto-scaling
- [ ] Test failover scenarios
- [ ] Document operational procedures
- [ ] Train support team
```

### Getting Help

```bash
# Documentation
docs/                    # Comprehensive documentation
docs/api/               # API reference
docs/troubleshooting/   # Common issues and solutions

# Community
- GitHub Issues: Report bugs and request features
- Discussions: Ask questions and share experiences
- Security: security@company.com for security issues

# Development
- CONTRIBUTING.md: Contributing guidelines
- CODE_OF_CONDUCT.md: Community standards
- SECURITY.md: Security policy
```

### Sample Applications

```bash
# Explore sample applications in examples/
examples/
├── axum-integration-example/     # Web application example
├── cli-client/                   # Command-line client
├── mobile-app-integration/       # Mobile app integration
└── microservice-integration/     # Microservice example
```

## 🎉 Congratulations!

You now have the Rust Security Platform running! Here's what you've accomplished:

✅ **Deployed** a production-ready authentication service  
✅ **Configured** secure user registration and login  
✅ **Set up** monitoring and observability  
✅ **Tested** the complete authentication flow  
✅ **Explored** the API documentation  

### What's Next?

1. **Customize** the configuration for your specific needs
2. **Integrate** with your existing applications
3. **Scale** the deployment based on your requirements
4. **Secure** the platform with your security policies
5. **Monitor** and optimize performance

---

## 🔗 Quick Reference

### Useful Commands

```bash
# Service management
docker-compose up -d          # Start all services
docker-compose down           # Stop all services
docker-compose logs -f        # View logs

# Health checks
curl http://localhost:8080/health     # Auth service
curl http://localhost:8081/health     # Policy service

# Monitoring
http://localhost:3000         # Grafana dashboard
http://localhost:8080/metrics # Prometheus metrics
```

### Default Endpoints

| Service | URL | Purpose |
|---------|-----|---------|
| Auth Service | http://localhost:8080 | Authentication API |
| Policy Service | http://localhost:8081 | Authorization policies |
| Grafana | http://localhost:3000 | Monitoring dashboard |
| API Docs | http://localhost:8080/docs | Interactive API documentation |

### Support

- 📧 **Email**: support@company.com
- 💬 **Chat**: [Join our Discord](https://discord.gg/rust-security)
- 🐛 **Issues**: [GitHub Issues](https://github.com/your-org/rust-security-platform/issues)
- 📚 **Docs**: [Full Documentation](./README.md)

---

**Happy authenticating! 🔐✨**