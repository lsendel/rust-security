# Rust Security Platform - Quick Start Guide

Get the Rust Security Platform up and running in just a few minutes!

## 🚀 30-Second Demo

The fastest way to see the platform in action:

```bash
# Clone the repository
git clone https://github.com/your-org/rust-security-platform.git
cd rust-security-platform

# Run the quick start script
./scripts/setup/quick-start.sh

# Select option 4 for demo mode
# Visit http://localhost:8080 when ready
```

## 📋 Prerequisites

Before you begin, ensure you have:

- **Rust 1.75+** - Install via [rustup.rs](https://rustup.rs/)
- **Docker & Docker Compose** - For containerized services
- **Git** - For version control
- **curl or wget** - For testing APIs

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 4GB | 8GB+ |
| **CPU** | 2 cores | 4+ cores |
| **Storage** | 10GB | 20GB+ |
| **OS** | Linux, macOS, Windows WSL2 | Any modern OS |

## 🏃‍♂️ Quick Start Options

Choose your preferred setup method:

### Option 1: Development Mode (Full Features)
```bash
./scripts/setup/quick-start.sh
# Select option 1: Developer mode

# Services will be available at:
# • Auth Service: http://localhost:8080
# • Policy Service: http://localhost:8081
# • Grafana Dashboard: http://localhost:3000
# • Prometheus Metrics: http://localhost:9090
```

### Option 2: Docker Compose (Recommended for Testing)
```bash
# Start all services with Docker
docker-compose up -d

# Check service health
docker-compose ps

# View logs
docker-compose logs -f auth-service
```

### Option 3: Manual Setup (Advanced Users)
```bash
# Install dependencies
cargo build --release

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Start Redis
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Run the auth service
cargo run --bin auth-service

# Run the policy service
cargo run --bin policy-service
```

## 🧪 Verify Your Installation

### Health Check
```bash
# Check auth service
curl http://localhost:8080/health

# Expected response:
# {"status":"healthy","service":"auth-service","version":"1.0.0"}

# Check policy service
curl http://localhost:8081/health
```

### OAuth Token Test
```bash
# Get an access token
curl -X POST "http://localhost:8080/oauth/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=demo_client" \
  -d "client_secret=demo_secret"

# Expected response:
# {
#   "access_token": "your_access_token",
#   "token_type": "Bearer",
#   "expires_in": 3600
# }
```

### JWT Introspection Test
```bash
# Introspect the token
curl -X POST "http://localhost:8080/oauth/introspect" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d "token=YOUR_ACCESS_TOKEN"
```

## 🎛️ Configuration

### Basic Configuration
Edit your `.env` file:

```bash
# Client credentials (format: client_id:client_secret)
CLIENT_CREDENTIALS=demo_client:demo_secret;admin_client:admin_secret

# JWT settings
JWT_SECRET=your_super_secret_jwt_key_change_this_in_production

# Redis connection
REDIS_URL=redis://localhost:6379

# Rate limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=60

# Logging
RUST_LOG=info,auth_service=debug
```

### Advanced Configuration
For production settings, see:
- [Configuration Guide](./docs/configuration/README.md)
- [Security Configuration](./docs/security/SECURITY_CONFIGURATION.md)
- [Production Deployment](./docs/deployment/PRODUCTION_DEPLOYMENT.md)

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │    │   Web Frontend  │    │   Mobile Apps   │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │      Auth Service         │
                    │   (OAuth 2.0, OIDC)      │
                    └─────────────┬─────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │    Policy Service         │
                    │   (Cedar Policies)        │
                    └─────────────┬─────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │     Redis Store           │
                    │  (Sessions, Cache)        │
                    └───────────────────────────┘
```

## 🔧 Common Issues & Solutions

### Issue: Redis Connection Failed
```bash
# Solution: Start Redis
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Or check if Redis is running
redis-cli ping
```

### Issue: Port Already in Use
```bash
# Find what's using the port
lsof -i :8080

# Kill the process
kill -9 <PID>

# Or use different ports in .env
PORT=8090
```

### Issue: Compilation Errors
```bash
# Update Rust toolchain
rustup update

# Clean build cache
cargo clean
cargo build
```

### Issue: Permission Denied
```bash
# Make scripts executable
chmod +x scripts/setup/quick-start.sh

# Or run with bash
bash scripts/setup/quick-start.sh
```

## 📊 Monitoring & Observability

Access the built-in monitoring:

- **Grafana Dashboards**: http://localhost:3000
  - Username: `admin`
  - Password: `admin`
- **Prometheus Metrics**: http://localhost:9090
- **Application Logs**: `docker-compose logs -f`

### Key Metrics to Watch
- Authentication latency (P95 < 50ms)
- Token validation rate
- Error rates
- Redis connection health

## 🧪 Testing the Platform

### Unit Tests
```bash
# Run all tests
cargo test

# Run with coverage
cargo test --all-features

# Run specific service tests
cargo test -p auth-service
```

### Integration Tests
```bash
# End-to-end tests
./scripts/test/run-e2e-tests.sh

# Security tests
./scripts/test/run-security-tests.sh

# Performance tests
./scripts/test/run-load-tests.sh
```

## 🚀 Next Steps

1. **Explore the API**: Check out the [API Documentation](./docs/api/README.md)
2. **Security Setup**: Review [Security Guidelines](./SECURITY.md)
3. **Production Deployment**: See [Deployment Guide](./docs/deployment/README.md)
4. **Integration**: Learn about [Integrations](./docs/integrations/README.md)
5. **Contributing**: Read [Contributing Guidelines](./CONTRIBUTING.md)

## 📚 Additional Resources

- **Architecture Deep Dive**: [docs/architecture/README.md](./docs/architecture/README.md)
- **Security Features**: [docs/security/README.md](./docs/security/README.md)
- **Performance Tuning**: [docs/performance/README.md](./docs/performance/README.md)
- **Troubleshooting**: [docs/troubleshooting/README.md](./docs/troubleshooting/README.md)

## 💬 Getting Help

- **Documentation**: Complete guides in the `docs/` directory
- **Issues**: Report bugs on [GitHub Issues](https://github.com/your-org/rust-security-platform/issues)
- **Discussions**: Community support on [GitHub Discussions](https://github.com/your-org/rust-security-platform/discussions)
- **Security**: Email security@rust-security-platform.com for security issues

---

**🎉 Congratulations!** You now have the Rust Security Platform running locally. Start building secure authentication into your applications!
