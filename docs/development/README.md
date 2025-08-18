# Development Guide

This guide provides comprehensive information for developers working on the Rust Authentication Service.

## Development Environment Setup

### Prerequisites

#### Required Tools
- **Rust**: 1.70+ (stable toolchain)
- **Git**: For version control
- **Redis**: 6.0+ for caching and session storage
- **Docker**: 20.10+ (optional, for containerized development)
- **PostgreSQL**: 12+ (optional, for production-like testing)

#### Development Tools
```bash
# Install Rust toolchain
rustup toolchain install stable
rustup default stable

# Install additional components
rustup component add rustfmt
rustup component add clippy
rustup component add rust-src

# Install cargo tools
cargo install cargo-watch      # Auto-rebuild on changes
cargo install cargo-audit      # Security vulnerability scanning
cargo install cargo-deny       # License and dependency checking
cargo install cargo-edit       # Cargo.toml editing helpers
cargo install cargo-machete    # Remove unused dependencies
cargo install cargo-outdated   # Check for outdated dependencies
```

### Repository Structure

```
auth-service/
├── src/                          # Source code
│   ├── lib.rs                   # Main library entry point
│   ├── main.rs                  # Binary entry point
│   ├── config.rs                # Configuration management
│   ├── security/                # Security modules
│   ├── mfa/                     # Multi-factor authentication
│   ├── soar/                    # SOAR automation modules
│   └── threat_hunting/          # Threat detection modules
├── tests/                       # Test suites
│   ├── integration/             # Integration tests
│   ├── security/                # Security tests
│   ├── performance/             # Performance tests
│   └── common/                  # Test utilities
├── benches/                     # Performance benchmarks
├── docs/                        # Documentation
├── scripts/                     # Development scripts
├── .env.example                 # Example environment configuration
├── Cargo.toml                   # Rust package configuration
├── Dockerfile                   # Container configuration
└── docker-compose.yml          # Development services
```

### Local Development Setup

#### 1. Clone and Setup

```bash
# Clone repository
git clone https://github.com/your-org/rust-security.git
cd rust-security/auth-service

# Copy environment template
cp .env.example .env

# Install dependencies
cargo build
```

#### 2. Configure Environment

Edit `.env` for development:

```env
# Development Configuration
RUST_LOG=debug,auth_service=trace
BIND_ADDR=127.0.0.1:8080
EXTERNAL_BASE_URL=http://localhost:8080

# Redis (start with docker-compose)
REDIS_URL=redis://127.0.0.1:6379

# Development credentials
CLIENT_CREDENTIALS=dev_client:dev_secret,test_client:test_secret
ALLOWED_SCOPES=openid,profile,email,admin,test
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080

# Development tokens (shorter expiry for testing)
TOKEN_EXPIRY_SECONDS=3600
REFRESH_TOKEN_EXPIRY_SECONDS=86400

# Feature flags
TEST_MODE=1
ENABLE_METRICS=true
ENABLE_SECURITY_MONITORING=true

# Development rate limiting (more permissive)
RATE_LIMIT_REQUESTS_PER_MINUTE=1000
```

#### 3. Start Development Services

```bash
# Start Redis and other services
docker-compose up -d redis

# Or start all services
docker-compose up -d
```

#### 4. Run the Service

```bash
# Development mode with auto-reload
cargo watch -x 'run --bin auth-service'

# With specific features
cargo watch -x 'run --bin auth-service --features docs,benchmarks'

# Debug mode with full logging
RUST_LOG=trace cargo run --bin auth-service
```

## Code Architecture

### Module Organization

#### Core Modules

```rust
// src/lib.rs - Main library interface
pub mod keys;              // Key management and rotation
pub mod security;          // Security utilities and middleware
pub mod store;             // Token and data storage
pub mod mfa;               // Multi-factor authentication
pub mod session_manager;   // Session management
pub mod scim;              // SCIM 2.0 user provisioning
pub mod webauthn;          // WebAuthn implementation
```

#### Security Modules

```rust
// Security-related modules
pub mod security_logging;    // Structured security event logging
pub mod security_monitoring; // Real-time threat monitoring
pub mod security_headers;    // HTTP security headers
pub mod security_metrics;    // Security metrics and instrumentation
pub mod rate_limit_optimized; // High-performance rate limiting
pub mod per_ip_rate_limit;   // Per-IP rate limiting middleware
```

#### Advanced Features (Feature-gated)

```rust
// SOAR automation
#[cfg(feature = "soar")]
pub mod soar_core;
#[cfg(feature = "soar")]
pub mod soar_workflow;
#[cfg(feature = "soar")]
pub mod soar_executors;

// Threat hunting
#[cfg(feature = "threat-hunting")]
pub mod threat_types;
#[cfg(feature = "threat-hunting")]
pub mod threat_behavioral_analyzer;
#[cfg(feature = "threat-hunting")]
pub mod threat_intelligence;

// Performance optimizations
#[cfg(feature = "optimizations")]
pub mod crypto_optimized;
#[cfg(feature = "optimizations")]
pub mod database_optimized;
```

### Design Patterns

#### Error Handling

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid client credentials")]
    InvalidClientCredentials,
    
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    
    #[error("Internal error: {0}")]
    InternalError(#[from] anyhow::Error),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
}

// Implement IntoResponse for HTTP responses
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::InvalidClientCredentials => {
                (StatusCode::UNAUTHORIZED, "invalid_client")
            }
            AuthError::InvalidToken(msg) => {
                (StatusCode::BAD_REQUEST, format!("invalid_token: {}", msg))
            }
            // ... other variants
        };
        
        (status, message).into_response()
    }
}
```

#### Async/Await Patterns

```rust
use tokio::sync::RwLock;
use std::sync::Arc;

// Shared state with async-safe locks
pub struct AppState {
    pub token_store: TokenStore,
    pub client_credentials: HashMap<String, String>,
    pub allowed_scopes: Vec<String>,
    pub authorization_codes: Arc<RwLock<HashMap<String, AuthorizationCode>>>,
}

// Async endpoint handlers
pub async fn issue_token(
    headers: HeaderMap,
    State(state): State<AppState>,
    Form(form): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, AuthError> {
    // Async operations
    let record = state.token_store.get_record(&token).await?;
    
    // Background task spawning
    tokio::spawn(async move {
        cleanup_expired_tokens().await;
    });
    
    Ok(Json(response))
}
```

#### Security Middleware

```rust
use axum::middleware::Next;
use axum::response::Response;
use axum::extract::Request;

pub async fn security_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Request validation
    validate_request_size(&request)?;
    validate_content_type(&request)?;
    
    // Security headers
    let mut response = next.run(request).await;
    add_security_headers(&mut response);
    
    // Audit logging
    log_request_response(&request, &response).await;
    
    Ok(response)
}
```

## Testing Strategy

### Test Categories

#### 1. Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;
    
    #[tokio::test]
    async fn test_token_validation() {
        let token = "valid_token";
        let result = validate_token(token).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_rate_limiting() {
        let mut limiter = RateLimiter::new(5, Duration::from_secs(60));
        
        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("127.0.0.1").await);
        }
        
        // Should block 6th request
        assert!(!limiter.check_rate_limit("127.0.0.1").await);
    }
}
```

#### 2. Integration Tests

```rust
// tests/integration/oauth_flow_tests.rs
use auth_service::{app, AppState};
use axum_test::TestServer;
use serde_json::json;

#[tokio::test]
async fn test_complete_oauth_flow() {
    let app_state = create_test_app_state().await;
    let app = app(app_state);
    let server = TestServer::new(app).unwrap();
    
    // Step 1: Authorization request
    let auth_response = server
        .get("/oauth/authorize")
        .add_query_params(&[
            ("response_type", "code"),
            ("client_id", "test_client"),
            ("redirect_uri", "http://localhost:3000/callback"),
            ("scope", "openid profile"),
            ("state", "test_state"),
        ])
        .await;
    
    assert_eq!(auth_response.status_code(), 302);
    
    // Extract authorization code from redirect
    let location = auth_response.header("location");
    let code = extract_code_from_redirect(location);
    
    // Step 2: Token exchange
    let token_response = server
        .post("/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost:3000/callback"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .await;
    
    assert_eq!(token_response.status_code(), 200);
    let token_json: serde_json::Value = token_response.json();
    assert!(token_json["access_token"].is_string());
}
```

#### 3. Security Tests

```rust
// tests/security/attack_simulation_tests.rs
#[tokio::test]
async fn test_rate_limiting_protection() {
    let server = create_test_server().await;
    
    // Simulate brute force attack
    let mut success_count = 0;
    for i in 0..200 {
        let response = server
            .post("/oauth/token")
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "test_client"),
                ("client_secret", &format!("wrong_secret_{}", i)),
            ])
            .await;
        
        if response.status_code() == 200 {
            success_count += 1;
        }
    }
    
    // Should block most requests due to rate limiting
    assert!(success_count < 10);
}

#[tokio::test]
async fn test_idor_protection() {
    let server = create_test_server().await;
    
    // Create tokens for two different users
    let user1_token = create_user_token("user1").await;
    let user2_token = create_user_token("user2").await;
    
    // User1 creates a session
    let session_response = server
        .post("/session/create")
        .bearer_token(&user1_token)
        .json(&json!({
            "user_id": "user1",
            "duration": 3600
        }))
        .await;
    
    let session_id = session_response.json()["session_id"].as_str().unwrap();
    
    // User2 attempts to access User1's session (should fail)
    let unauthorized_response = server
        .get(&format!("/session/{}", session_id))
        .bearer_token(&user2_token)
        .await;
    
    assert_eq!(unauthorized_response.status_code(), 403);
}
```

#### 4. Performance Tests

```rust
// tests/performance/load_tests.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_token_validation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = rt.block_on(create_token_store());
    let token = "sample_token";
    
    c.bench_function("token_validation", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(store.get_record(token).await.unwrap())
        })
    });
}

fn bench_rate_limiting(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let limiter = create_rate_limiter();
    
    c.bench_function("rate_limit_check", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(limiter.check_rate_limit("127.0.0.1").await)
        })
    });
}

criterion_group!(benches, bench_token_validation, bench_rate_limiting);
criterion_main!(benches);
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test categories
cargo test unit_tests
cargo test integration_tests
cargo test security_tests
cargo test performance_tests

# Run with features
cargo test --features threat-hunting,soar

# Run with coverage
cargo test --features benchmarks -- --nocapture

# Run benchmarks
cargo bench --features benchmarks

# Run security audits
cargo audit
cargo deny check
```

### Test Utilities

```rust
// tests/common/mod.rs
use auth_service::{AppState, TokenStore};
use std::collections::HashMap;

pub async fn create_test_app_state() -> AppState {
    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret".to_string());
    
    AppState {
        token_store: TokenStore::InMemory(Default::default()),
        client_credentials,
        allowed_scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "admin".to_string(),
        ],
        authorization_codes: Default::default(),
    }
}

pub async fn create_test_token(user_id: &str, scopes: &[&str]) -> String {
    // Create a test token with specified user and scopes
    format!("test_token_{}_{}", user_id, scopes.join("_"))
}
```

## Code Quality and Standards

### Formatting and Linting

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check

# Run linting
cargo clippy

# Run strict linting
cargo clippy -- -D warnings

# Check for unused dependencies
cargo machete

# Check for outdated dependencies
cargo outdated
```

### Code Style Guidelines

#### Naming Conventions

```rust
// Modules: snake_case
mod security_logging;
mod rate_limit_optimized;

// Types: PascalCase
struct TokenRequest;
enum AuthError;
trait TokenStore;

// Functions and variables: snake_case
fn validate_token() {}
let user_id = "user123";

// Constants: SCREAMING_SNAKE_CASE
const DEFAULT_TOKEN_EXPIRY_SECONDS: u64 = 3600;
const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024;
```

#### Documentation Standards

```rust
/// Validates an OAuth2 access token and returns token metadata.
/// 
/// This function performs comprehensive token validation including:
/// - Format validation (JWT or opaque token)
/// - Signature verification for JWTs
/// - Expiration checking
/// - Scope validation
/// - Token binding verification
/// 
/// # Arguments
/// 
/// * `token` - The access token to validate
/// * `required_scopes` - Optional scopes that must be present
/// 
/// # Returns
/// 
/// Returns `Ok(TokenMetadata)` if the token is valid, or `Err(AuthError)`
/// if validation fails.
/// 
/// # Examples
/// 
/// ```rust
/// let token = "eyJhbGciOiJSUzI1NiIs...";
/// let metadata = validate_token(token, Some(&["openid", "profile"])).await?;
/// println!("Token is valid for user: {}", metadata.subject);
/// ```
/// 
/// # Security Considerations
/// 
/// This function implements multiple security checks:
/// - Prevents token replay attacks through nonce tracking
/// - Validates token binding to prevent token theft
/// - Enforces scope-based authorization
/// 
/// # Errors
/// 
/// Returns `AuthError::InvalidToken` for various validation failures:
/// - Malformed token format
/// - Invalid signature
/// - Expired token
/// - Missing required scopes
/// - Token binding mismatch
pub async fn validate_token(
    token: &str,
    required_scopes: Option<&[&str]>,
) -> Result<TokenMetadata, AuthError> {
    // Implementation...
}
```

#### Error Handling Patterns

```rust
// Use Result<T, E> for recoverable errors
pub async fn get_user(id: &str) -> Result<User, DatabaseError> {
    database::query_user(id)
        .await
        .map_err(DatabaseError::from)
}

// Use Option<T> for missing values
pub fn get_optional_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// Convert errors appropriately
impl From<redis::RedisError> for AuthError {
    fn from(err: redis::RedisError) -> Self {
        AuthError::InternalError(err.into())
    }
}
```

### Security Code Review Checklist

#### Input Validation
- [ ] All inputs are validated for type, length, and format
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention (proper encoding/escaping)
- [ ] Path traversal prevention
- [ ] Integer overflow protection

#### Authentication & Authorization
- [ ] Proper authentication checks
- [ ] Authorization checks (IDOR prevention)
- [ ] Session management security
- [ ] Token validation and binding
- [ ] MFA requirements enforced

#### Cryptography
- [ ] Secure random number generation
- [ ] Proper key management
- [ ] Current cryptographic algorithms
- [ ] Secure key storage
- [ ] Proper encryption/decryption

#### Error Handling
- [ ] No sensitive information in error messages
- [ ] Proper error logging
- [ ] Graceful error recovery
- [ ] Rate limiting on error paths

#### Logging & Monitoring
- [ ] Security events are logged
- [ ] No sensitive data in logs
- [ ] Audit trail completeness
- [ ] Monitoring integration

## Debugging and Troubleshooting

### Development Debugging

#### Logging Configuration

```env
# Detailed logging for development
RUST_LOG=trace,auth_service=trace,security_audit=debug,sqlx=debug

# Component-specific logging
RUST_LOG=auth_service::security=trace,auth_service::mfa=debug

# Performance logging
RUST_LOG=auth_service::rate_limit_optimized=trace
```

#### Debug Utilities

```rust
// Debug middleware for request/response logging
pub async fn debug_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    
    tracing::debug!("Incoming request: {} {}", method, uri);
    tracing::trace!("Request headers: {:?}", headers);
    
    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed();
    
    tracing::debug!(
        "Response: {} {} - {:?} in {:?}",
        method,
        uri,
        response.status(),
        duration
    );
    
    Ok(response)
}
```

### Performance Debugging

#### Profiling

```bash
# CPU profiling
cargo run --features profiling --bin auth-service

# Memory profiling
cargo build --features profiling
valgrind --tool=massif target/debug/auth-service

# Async runtime profiling
cargo run --features tokio-console --bin auth-service
```

#### Benchmarking

```bash
# Run benchmarks
cargo bench --features benchmarks

# Generate performance reports
cargo bench --features benchmarks -- --output-format html

# Continuous benchmarking
cargo watch -x 'bench --features benchmarks'
```

### Common Issues

#### Redis Connection Issues

```rust
// Debug Redis connectivity
async fn debug_redis_connection() -> Result<(), redis::RedisError> {
    let client = redis::Client::open("redis://127.0.0.1:6379/")?;
    let mut con = client.get_async_connection().await?;
    
    // Test basic operations
    redis::cmd("PING").query_async(&mut con).await?;
    redis::cmd("SET").arg("test_key").arg("test_value").query_async(&mut con).await?;
    let value: String = redis::cmd("GET").arg("test_key").query_async(&mut con).await?;
    
    println!("Redis test successful: {}", value);
    Ok(())
}
```

#### Performance Issues

```rust
// Debug rate limiting performance
pub async fn debug_rate_limiting() {
    let start = std::time::Instant::now();
    
    for i in 0..1000 {
        let result = check_rate_limit(&format!("user_{}", i % 100)).await;
        if i % 100 == 0 {
            println!("Processed {} requests in {:?}", i, start.elapsed());
        }
    }
    
    println!("Total time for 1000 requests: {:?}", start.elapsed());
}
```

## Development Workflow

### Git Workflow

```bash
# Feature development
git checkout -b feature/mfa-enhancement
git commit -m "feat: add TOTP replay protection"
git push origin feature/mfa-enhancement

# Bug fixes
git checkout -b fix/rate-limit-bypass
git commit -m "fix: prevent rate limit bypass with invalid IPs"

# Security fixes
git checkout -b security/fix-token-validation
git commit -m "security: fix token signature validation"
```

### Continuous Integration

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        components: rustfmt, clippy
    
    - name: Cache cargo
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          target
        key: cargo-${{ hashFiles('**/Cargo.lock') }}
    
    - name: Format check
      run: cargo fmt -- --check
    
    - name: Lint
      run: cargo clippy -- -D warnings
    
    - name: Test
      run: cargo test --all-features
      env:
        REDIS_URL: redis://localhost:6379
    
    - name: Security audit
      run: cargo audit
    
    - name: Benchmark
      run: cargo bench --features benchmarks
```

### Release Process

```bash
# Version bump
cargo edit set-version 1.2.0

# Update changelog
git add CHANGELOG.md
git commit -m "docs: update changelog for v1.2.0"

# Create release tag
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0

# Build release
cargo build --release --all-features

# Security check before release
cargo audit
cargo deny check
```

## Contributing Guidelines

### Code Contributions

1. **Fork the repository**
2. **Create a feature branch**
3. **Write tests** for new functionality
4. **Ensure all tests pass**
5. **Run security audits**
6. **Submit a pull request**

### Pull Request Process

1. **Description**: Clear description of changes
2. **Testing**: Evidence of testing (unit, integration, security)
3. **Documentation**: Updated documentation if needed
4. **Breaking Changes**: Clearly marked and justified
5. **Security Review**: Security implications addressed

### Code Review Checklist

- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] Security implications reviewed
- [ ] Performance impact assessed
- [ ] Documentation updated
- [ ] Breaking changes documented

## Development Tools and IDE Setup

### VS Code Configuration

```json
// .vscode/settings.json
{
  "rust-analyzer.checkOnSave.command": "clippy",
  "rust-analyzer.rustfmt.extraArgs": ["+nightly"],
  "rust-analyzer.cargo.features": ["docs", "benchmarks"],
  "files.watcherExclude": {
    "**/target/**": true
  }
}
```

### Recommended Extensions

- rust-analyzer
- CodeLLDB (debugging)
- Error Lens
- GitLens
- Thunder Client (API testing)

### Development Scripts

```bash
# scripts/dev-setup.sh
#!/bin/bash
set -e

echo "Setting up development environment..."

# Install Rust if not present
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
fi

# Install development tools
cargo install cargo-watch cargo-audit cargo-deny

# Start development services
docker-compose up -d redis

# Create development environment file
cp .env.example .env

echo "Development environment ready!"
echo "Run 'cargo watch -x run' to start the service"
```

This comprehensive development guide provides all the necessary information for developers to contribute effectively to the Rust Authentication Service while maintaining high security and code quality standards.