# Developer Onboarding Guide

## Overview

Welcome to the Rust Security Platform - an enterprise-grade authentication and authorization platform built with security-first principles. This guide will get you from zero to productive developer in under 30 minutes.

## Prerequisites

### Required Software
- **Rust** 1.80+ ([Install via rustup](https://rustup.rs/))
- **Docker** & **Docker Compose** ([Docker Desktop](https://www.docker.com/products/docker-desktop))
- **Git** ([Download](https://git-scm.com/downloads))
- **PostgreSQL** 15+ (local or Docker)
- **Redis** 7+ (local or Docker)

### Recommended Tools
- **VS Code** with Rust Analyzer extension
- **Postman** or **curl** for API testing
- **pgAdmin** or **DBeaver** for database management

## Quick Setup (Docker - Recommended)

### 1. Clone and Setup
```bash
# Clone repository
git clone <repository-url>
cd rust-security

# Generate production secrets
./scripts/generate-production-secrets.sh

# Start all services
./deploy-docker-production.sh
```

### 2. Verify Installation
```bash
# Check service health
./validate-services.sh

# Expected output:
# ✅ Auth Service: http://localhost:8080/health
# ✅ Policy Service: http://localhost:8081/health  
# ✅ Dashboard: http://localhost:3000
# ✅ PostgreSQL: Connected
# ✅ Redis: Connected
```

### 3. Access Services
| Service | URL | Purpose |
|---------|-----|---------|
| Auth Service | http://localhost:8080 | Authentication API |
| Policy Service | http://localhost:8081 | Authorization API |
| Dashboard | http://localhost:3000 | Security monitoring |
| API Docs | http://localhost:8080/swagger-ui/ | Interactive API docs |

## Manual Development Setup

### 1. Database Setup
```bash
# Install PostgreSQL (macOS)
brew install postgresql@15
brew services start postgresql@15

# Create development database
createdb rust_security_dev
createdb rust_security_test

# Run migrations
cd auth-service
./scripts/run-migrations.sh
```

### 2. Redis Setup
```bash
# Install Redis (macOS)  
brew install redis
brew services start redis

# Verify Redis
redis-cli ping  # Should return PONG
```

### 3. Environment Configuration
```bash
# Copy environment template
cp .env.example .env

# Edit configuration
vim .env
```

**Required Environment Variables:**
```bash
# .env
DATABASE_URL=postgresql://postgres:password@localhost:5432/rust_security_dev
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-super-secure-secret-min-32-chars
RUST_LOG=debug
ENVIRONMENT=development
```

### 4. Build and Run Services
```bash
# Install dependencies and build
cargo build --workspace

# Run auth service
cargo run --bin auth-service

# Run policy service (in another terminal)
cargo run --bin policy-service
```

## Development Workflow

### Project Structure
```
rust-security/
├── auth-service/          # Authentication service
│   ├── src/
│   │   ├── main.rs       # Service entry point
│   │   ├── lib.rs        # Core library
│   │   └── ...
│   ├── tests/            # Integration tests
│   └── Cargo.toml
├── policy-service/       # Authorization service
├── common/              # Shared utilities
├── docs/               # Documentation
├── monitoring/         # Monitoring configs
└── scripts/           # Deployment scripts
```

### Building and Testing
```bash
# Quick compilation check (fastest)
cargo check --workspace

# Full build
cargo build --workspace

# Run all tests (after compilation check)
cargo test --no-run --workspace  # Compile tests
cargo test --workspace          # Run tests

# Run specific service tests
cargo test --package auth-service
```

### Code Quality
```bash
# Format code
cargo fmt --all

# Run clippy (linting)
cargo clippy --workspace -- -D warnings

# Security audit
cargo audit
```

### Feature Development
```bash
# Create feature branch
git checkout -b feature/new-authentication

# Work on changes...

# Test your changes
cargo test --workspace
./validate-services.sh

# Submit PR
git push origin feature/new-authentication
```

## API Development

### Authentication Service APIs
```bash
# Health check
curl http://localhost:8080/health

# Get OpenID configuration
curl http://localhost:8080/.well-known/openid-configuration

# Client credentials flow
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=read"
```

### Policy Service APIs
```bash
# Health check
curl http://localhost:8081/health

# Evaluate policy
curl -X POST http://localhost:8081/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "principal": {"type": "User", "id": "alice"},
    "action": {"type": "Action", "id": "read"},  
    "resource": {"type": "Document", "id": "doc123"}
  }'
```

## Testing Strategy

### Test Categories
1. **Unit Tests** - Individual component testing
2. **Integration Tests** - Service interaction testing  
3. **Security Tests** - Authentication/authorization testing
4. **Performance Tests** - Load and benchmark testing

### Running Tests
```bash
# All tests
cargo test --workspace

# Specific test categories
cargo test --workspace security
cargo test --workspace integration

# With output
cargo test --workspace -- --nocapture

# Performance benchmarks
cargo bench --workspace
```

### Test Examples
```rust
// Unit test example
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jwt_validation() {
        let token = generate_test_jwt();
        let result = validate_jwt(&token).await;
        assert!(result.is_ok());
    }
}

// Integration test example  
#[tokio::test]
async fn test_auth_flow() {
    let app = create_test_app().await;
    let response = app
        .oneshot(Request::builder()
            .method(http::Method::POST)
            .uri("/oauth2/token")
            .body(Body::empty())
            .unwrap())
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
}
```

## Database Development

### Migration Management
```bash
# Create new migration
sqlx migrate add create_users_table

# Run migrations
sqlx migrate run

# Revert migration
sqlx migrate revert
```

### Database Queries
```rust
// Query example
#[derive(sqlx::FromRow)]
struct User {
    id: uuid::Uuid,
    email: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn get_user(pool: &PgPool, user_id: uuid::Uuid) -> Result<User> {
    let user = sqlx::query_as!(
        User,
        "SELECT id, email, created_at FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(pool)
    .await?;
    
    Ok(user)
}
```

## Configuration Management

### Development Configuration
```rust
// config.rs
#[derive(Deserialize, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub environment: Environment,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        envy::from_env::<Config>()
            .map_err(|e| anyhow!("Failed to load config: {}", e))
    }
}
```

### Environment-Specific Settings
```bash
# Development
RUST_LOG=debug
ENVIRONMENT=development
JWT_SECRET=dev-secret-dont-use-in-production

# Production  
RUST_LOG=info
ENVIRONMENT=production
JWT_SECRET_FILE=/run/secrets/jwt_secret
```

## Monitoring and Observability

### Logging
```rust
use tracing::{info, warn, error, debug, span, Level};

// Structured logging
#[tracing::instrument]
async fn authenticate_user(user_id: &str) -> Result<User> {
    let span = span!(Level::INFO, "authenticate_user", user_id);
    let _enter = span.enter();
    
    info!("Starting authentication for user: {}", user_id);
    
    match get_user_from_db(user_id).await {
        Ok(user) => {
            info!("User authenticated successfully");
            Ok(user)
        }
        Err(e) => {
            error!("Authentication failed: {}", e);
            Err(e)
        }
    }
}
```

### Metrics
```rust
use prometheus::{Counter, Histogram, register_counter, register_histogram};

// Define metrics
lazy_static! {
    static ref AUTH_REQUESTS: Counter = register_counter!(
        "auth_requests_total",
        "Total number of authentication requests"
    ).unwrap();
    
    static ref AUTH_DURATION: Histogram = register_histogram!(
        "auth_request_duration_seconds",
        "Duration of authentication requests"
    ).unwrap();
}

// Use in code
async fn handle_auth_request() {
    let timer = AUTH_DURATION.start_timer();
    AUTH_REQUESTS.inc();
    
    // Handle request...
    
    timer.observe_duration();
}
```

## Security Best Practices

### Input Validation
```rust
use validator::{Validate, ValidationError};

#[derive(Deserialize, Validate)]
struct LoginRequest {
    #[validate(email)]
    email: String,
    
    #[validate(length(min = 8, max = 100))]
    password: String,
}

async fn login(req: Json<LoginRequest>) -> Result<Json<LoginResponse>> {
    req.validate()
        .map_err(|e| AppError::ValidationError(e))?;
    
    // Process login...
}
```

### Error Handling
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Validation error: {0}")]  
    ValidationError(#[from] validator::ValidationErrors),
}

// Convert to HTTP response
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::AuthenticationFailed => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            AppError::ValidationError(_) => (StatusCode::BAD_REQUEST, "Invalid input"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };
        
        (status, Json(json!({"error": message}))).into_response()
    }
}
```

## Common Issues and Solutions

### Build Issues
```bash
# Clear cache and rebuild
cargo clean
cargo build --workspace

# Update dependencies
cargo update

# Check for compilation errors
cargo check --workspace
```

### Database Connection Issues
```bash
# Check PostgreSQL status
pg_isready -h localhost -p 5432

# Test connection
psql $DATABASE_URL -c "SELECT version();"

# Reset database
dropdb rust_security_dev
createdb rust_security_dev  
./scripts/run-migrations.sh
```

### Redis Connection Issues
```bash
# Check Redis status
redis-cli ping

# View Redis info
redis-cli info

# Clear Redis data
redis-cli FLUSHDB
```

### Service Port Conflicts
```bash
# Find process using port
lsof -ti :8080

# Kill process
kill -9 $(lsof -ti :8080)

# Use different port
export PORT=8081
cargo run --bin auth-service
```

## IDE Setup

### VS Code Configuration
```json
// .vscode/settings.json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.checkOnSave.extraArgs": ["--", "-D", "warnings"],
    "rust-analyzer.cargo.features": ["development"],
    "[rust]": {
        "editor.defaultFormatter": "rust-lang.rust-analyzer",
        "editor.formatOnSave": true
    }
}
```

### Recommended Extensions
- Rust Analyzer (`rust-lang.rust-analyzer`)
- CodeLLDB (`vadimcn.vscode-lldb`)
- TOML (`be5invis.toml`)
- Thunder Client (`rangav.vscode-thunder-client`)

## Next Steps

Once you have the platform running:

1. **Explore the APIs** - Use the interactive documentation at http://localhost:8080/swagger-ui/
2. **Read the Architecture** - See [Architecture Overview](/Users/lsendel/IdeaProjects/rust-security/docs/architecture/README.md)
3. **Deploy to Staging** - Follow the [Deployment Guide](/Users/lsendel/IdeaProjects/rust-security/docs/PRODUCTION_DEPLOYMENT.md)
4. **Integrate Applications** - See [Integration Guide](/Users/lsendel/IdeaProjects/rust-security/docs/INTEGRATION_GUIDE.md)

## Getting Help

- **Documentation**: Check `/docs` directory for specific guides
- **Issues**: Review GitHub issues for known problems
- **Logs**: Check service logs for debugging information
- **Community**: Join our developer Slack channel

Remember: The platform is designed with security-first principles. Always validate inputs, handle errors gracefully, and follow secure coding practices.
