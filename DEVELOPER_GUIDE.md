# 👩‍💻 Developer Guide

**Rust Authentication Service - Enterprise Security Platform**

## 📋 Table of Contents

1. [Getting Started](#getting-started)
2. [Development Environment](#development-environment)
3. [Architecture Overview](#architecture-overview)
4. [Security Implementation](#security-implementation)
5. [Testing Guide](#testing-guide)
6. [Performance Guidelines](#performance-guidelines)
7. [Contribution Guidelines](#contribution-guidelines)
8. [Debugging & Troubleshooting](#debugging--troubleshooting)

## 🚀 Getting Started

### **Prerequisites**
- **Rust**: 1.70+ (latest stable recommended)
- **Redis**: 6.0+ for session storage and rate limiting
- **PostgreSQL**: 14+ for persistent data (optional)
- **Docker**: For containerized development
- **Git**: For version control

### **Quick Setup**
```bash
# Clone the repository
git clone https://github.com/yourcompany/rust-security.git
cd rust-security

# Install dependencies
cd auth-service
cargo build

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Run tests
cargo test

# Start development server
cargo run
```

### **Environment Variables**
```bash
# Required
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-jwt-secret-key

# Optional
DATABASE_URL=postgresql://user:pass@localhost/auth_db
RUST_LOG=info
POLICY_SERVICE_URL=http://localhost:8081

# Security Features
ENABLE_RATE_LIMITING=true
ENABLE_TOTP_REPLAY_PROTECTION=true
ENABLE_IDOR_PROTECTION=true
ENABLE_PKCE_ENFORCEMENT=true
```

## 🛠️ Development Environment

### **IDE Setup**

#### **VS Code (Recommended)**
Install these extensions:
- **rust-analyzer**: Rust language support
- **CodeLLDB**: Debugging support
- **crates**: Dependency management
- **Error Lens**: Inline error display

#### **VS Code Settings** (`.vscode/settings.json`):
```json
{
    "rust-analyzer.cargo.features": ["performance", "soar"],
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.checkOnSave.extraArgs": ["--", "-W", "clippy::all"],
    "rust-analyzer.cargo.allFeatures": false,
    "editor.formatOnSave": true,
    "[rust]": {
        "editor.defaultFormatter": "rust-lang.rust-analyzer"
    }
}
```

### **Development Dependencies**
```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
tokio-test = "0.4"
mockall = "0.12"
wiremock = "0.6"
test-log = "0.2"
tempfile = "3.0"
```

### **Useful Development Commands**
```bash
# Format code
cargo fmt

# Lint code
cargo clippy -- -D warnings

# Check without building
cargo check

# Build with all features
cargo build --all-features

# Run specific tests
cargo test test_idor_protection

# Generate documentation
cargo doc --no-deps --open

# Security audit
cargo audit

# Run benchmarks
cargo bench
```

## 🏗️ Architecture Overview

### **Project Structure**
```
auth-service/
├── src/
│   ├── lib.rs              # Main library and router
│   ├── mfa.rs              # Multi-factor authentication
│   ├── security.rs         # Security utilities and PKCE
│   ├── store.rs            # Session and token storage
│   ├── keys.rs             # Cryptographic operations
│   ├── rate_limit_optimized.rs  # Rate limiting
│   ├── security_logging.rs # Security event logging
│   ├── soar_*.rs           # SOAR automation modules
│   └── threat_*.rs         # Threat hunting modules
├── tests/
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   ├── security/           # Security tests
│   └── performance/        # Performance tests
├── benches/                # Benchmark tests
└── examples/               # Usage examples
```

### **Key Components**

#### **Security Layer**
```rust
pub struct SecurityConfig {
    pub enable_idor_protection: bool,
    pub enable_totp_replay_protection: bool,
    pub enable_pkce_enforcement: bool,
    pub trusted_proxies: Vec<String>,
}
```

#### **Authentication Flow**
```rust
// OAuth2 with PKCE enforcement
pub async fn oauth_authorize(
    Query(params): Query<AuthorizeParams>,
    security_config: SecurityConfig,
) -> Result<Response, AuthError> {
    // 1. Validate PKCE challenge (S256 only)
    // 2. Validate redirect URI
    // 3. Check rate limits
    // 4. Generate authorization code
    // 5. Log security event
}
```

#### **Session Management**
```rust
// IDOR-protected session operations
pub async fn get_user_sessions(
    headers: HeaderMap,
    store: Arc<dyn TokenStore>,
) -> Result<Json<SessionsResponse>, AuthError> {
    // 1. Extract user from token
    // 2. Validate session ownership
    // 3. Return user's sessions only
}
```

## 🔒 Security Implementation

### **IDOR Protection**
Prevents unauthorized access to resources:

```rust
/// Extracts user information from Bearer token
pub async fn extract_user_from_token(
    headers: &HeaderMap,
    store: &Arc<dyn TokenStore>,
) -> Result<User, AuthError> {
    let token = extract_bearer_token(headers)?;
    let user = validate_and_decode_token(&token, store).await?;
    Ok(user)
}

/// Validates session ownership
pub async fn validate_session_ownership(
    session_id: &str,
    user_id: &str,
    store: &Arc<dyn TokenStore>,
) -> Result<bool, AuthError> {
    let session = store.get_session(session_id).await?;
    Ok(session.user_id == user_id)
}
```

### **TOTP Replay Prevention**
Prevents code reuse attacks:

```rust
/// Tracks TOTP nonce to prevent replay
pub async fn track_totp_nonce(
    redis: &Arc<Redis>,
    user_id: &str,
    code: &str,
    window_start: i64,
) -> Result<(), RedisError> {
    let nonce_key = format!("totp_nonce:{}:{}:{}", user_id, code, window_start);
    redis.set_ex(&nonce_key, "used", 300).await // 5-minute TTL
}

/// Checks if TOTP code was already used
pub async fn is_totp_code_used(
    redis: &Arc<Redis>,
    user_id: &str,
    code: &str,
    window_start: i64,
) -> Result<bool, RedisError> {
    let nonce_key = format!("totp_nonce:{}:{}:{}", user_id, code, window_start);
    Ok(redis.exists(&nonce_key).await?)
}
```

### **PKCE Enforcement**
Ensures secure OAuth2 flows:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    // Plain method removed for security
    S256,
}

/// Validates PKCE challenge
pub fn validate_pkce_challenge(
    challenge: &str,
    verifier: &str,
    method: &CodeChallengeMethod,
) -> Result<bool, PkceError> {
    match method {
        CodeChallengeMethod::S256 => {
            let hash = sha256::digest(verifier.as_bytes());
            let encoded = base64_url_encode(&hash);
            Ok(encoded == challenge)
        }
    }
}
```

### **Rate Limiting**
Protects against abuse:

```rust
/// Checks rate limit with trusted proxy support
pub async fn check_rate_limit_with_proxy(
    client_ip: &str,
    headers: &HeaderMap,
    config: &RateLimitConfig,
) -> Result<bool, RateLimitError> {
    let real_ip = extract_real_client_ip(client_ip, headers, &config.trusted_proxies)?;
    let limiter = get_rate_limiter(&config);
    limiter.check_rate_limit(&real_ip).await
}
```

## 🧪 Testing Guide

### **Test Categories**

#### **Unit Tests**
Test individual functions and modules:
```rust
#[tokio::test]
async fn test_idor_protection() {
    let store = MockTokenStore::new();
    let headers = create_test_headers("user_123");
    
    let user = extract_user_from_token(&headers, &store).await.unwrap();
    assert_eq!(user.id, "user_123");
}
```

#### **Integration Tests**
Test complete workflows:
```rust
#[tokio::test]
async fn test_oauth_flow_with_pkce() {
    let app = spawn_test_app().await;
    
    // Step 1: Authorization request
    let auth_response = app.get("/oauth/authorize")
        .query(&[("code_challenge_method", "S256")])
        .send().await;
    
    assert_eq!(auth_response.status(), 200);
    
    // Step 2: Token exchange
    let token_response = app.post("/oauth/token")
        .form(&[("code_verifier", "test_verifier")])
        .send().await;
    
    assert_eq!(token_response.status(), 200);
}
```

#### **Security Tests**
Test attack scenarios:
```rust
#[tokio::test]
async fn test_totp_replay_attack() {
    let app = spawn_test_app().await;
    let totp_code = "123456";
    
    // First request should succeed
    let response1 = app.post("/mfa/totp/verify")
        .json(&json!({"totp_code": totp_code}))
        .send().await;
    assert_eq!(response1.status(), 200);
    
    // Second request with same code should fail
    let response2 = app.post("/mfa/totp/verify")
        .json(&json!({"totp_code": totp_code}))
        .send().await;
    assert_eq!(response2.status(), 400);
}
```

#### **Performance Tests**
Test performance requirements:
```rust
#[tokio::test]
async fn test_token_validation_performance() {
    let app = spawn_test_app().await;
    let start = Instant::now();
    
    for _ in 0..1000 {
        let response = app.post("/oauth/introspect")
            .json(&json!({"token": "test_token"}))
            .send().await;
        assert_eq!(response.status(), 200);
    }
    
    let duration = start.elapsed();
    assert!(duration < Duration::from_millis(1000)); // <1ms per validation
}
```

### **Test Utilities**
```rust
pub mod test_utils {
    use super::*;
    
    pub async fn spawn_test_app() -> TestApp {
        let config = TestConfig::default();
        TestApp::new(config).await
    }
    
    pub fn create_test_headers(user_id: &str) -> HeaderMap {
        let token = create_test_jwt(user_id);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap()
        );
        headers
    }
    
    pub fn create_test_jwt(user_id: &str) -> String {
        // Create valid JWT for testing
    }
}
```

### **Running Tests**
```bash
# Run all tests
cargo test

# Run specific test category
cargo test unit::
cargo test integration::
cargo test security::
cargo test performance::

# Run tests with coverage
cargo tarpaulin --out Html

# Run property-based tests
cargo test property:: -- --ignored

# Run benchmarks
cargo bench
```

## ⚡ Performance Guidelines

### **Performance Targets**
- **Token Generation**: <100ms P95
- **Token Validation**: <10ms P95
- **Session Operations**: <50ms P95
- **Rate Limit Checks**: <1ms P95
- **Memory Usage**: <1KB per active session

### **Optimization Techniques**

#### **Async/Await Best Practices**
```rust
// ✅ Good: Use async/await for I/O operations
pub async fn validate_token(token: &str) -> Result<Claims, AuthError> {
    let redis_check = redis.get(token).await?;
    let db_check = database.verify_token(token).await?;
    Ok(combine_results(redis_check, db_check))
}

// ❌ Bad: Blocking operations in async context
pub async fn bad_validate_token(token: &str) -> Result<Claims, AuthError> {
    let result = expensive_blocking_operation(token); // Blocks the executor
    Ok(result)
}
```

#### **Caching Strategies**
```rust
// Multi-tier caching
pub struct CacheManager {
    l1_cache: Arc<MemoryCache>, // Fast in-memory
    l2_cache: Arc<RedisCache>,  // Shared cache
}

impl CacheManager {
    pub async fn get_or_set<T>(&self, key: &str, fetcher: F) -> Result<T, CacheError>
    where
        F: Future<Output = Result<T, Error>>,
    {
        // Try L1 cache first
        if let Some(value) = self.l1_cache.get(key).await? {
            return Ok(value);
        }
        
        // Try L2 cache
        if let Some(value) = self.l2_cache.get(key).await? {
            self.l1_cache.set(key, &value).await?;
            return Ok(value);
        }
        
        // Fetch from source
        let value = fetcher.await?;
        self.l2_cache.set(key, &value).await?;
        self.l1_cache.set(key, &value).await?;
        Ok(value)
    }
}
```

#### **Memory Management**
```rust
// Use Arc for shared data
pub struct AppState {
    pub redis: Arc<Redis>,
    pub token_store: Arc<dyn TokenStore>,
    pub rate_limiter: Arc<RateLimiter>,
}

// Prefer owned types for temporary data
pub fn process_request(data: Vec<u8>) -> Result<Response, Error> {
    let parsed = parse_data(data)?; // Takes ownership
    Ok(build_response(parsed))
}
```

### **Profiling and Monitoring**
```rust
// Add tracing for performance monitoring
#[tracing::instrument(skip(store))]
pub async fn validate_session(
    session_id: &str,
    store: &Arc<dyn TokenStore>,
) -> Result<Session, AuthError> {
    let start = Instant::now();
    let session = store.get_session(session_id).await?;
    
    tracing::info!(
        duration_ms = start.elapsed().as_millis(),
        session_id = session_id,
        "Session validation completed"
    );
    
    Ok(session)
}
```

## 🤝 Contribution Guidelines

### **Code Style**
- **Format**: Use `cargo fmt` before committing
- **Linting**: Address all `cargo clippy` warnings
- **Documentation**: Add rustdoc comments for public APIs
- **Testing**: Include tests for new functionality

### **Commit Messages**
Follow conventional commits:
```
feat(security): add TOTP replay protection
fix(auth): resolve IDOR vulnerability in sessions
docs(api): update authentication documentation
test(mfa): add comprehensive TOTP tests
```

### **Pull Request Process**
1. **Create Feature Branch**: `git checkout -b feature/new-security-feature`
2. **Implement Changes**: Follow coding standards
3. **Add Tests**: Ensure >90% coverage for new code
4. **Update Documentation**: Update relevant docs
5. **Run Tests**: `cargo test` and `cargo clippy`
6. **Create PR**: Use PR template and request review
7. **Address Feedback**: Respond to review comments
8. **Merge**: After approval and CI passes

### **Security Considerations**
- **Never commit secrets**: Use environment variables
- **Validate inputs**: All user inputs must be validated
- **Follow OWASP**: Apply OWASP security principles
- **Security review**: Security-related changes need security team review

## 🐛 Debugging & Troubleshooting

### **Logging Configuration**
```bash
# Debug level logging
RUST_LOG=auth_service=debug cargo run

# Specific module logging
RUST_LOG=auth_service::security=trace cargo run

# JSON structured logging
RUST_LOG=info RUST_LOG_FORMAT=json cargo run
```

### **Common Issues**

#### **Redis Connection Errors**
```rust
// Check Redis connectivity
async fn test_redis_connection() -> Result<(), RedisError> {
    let client = redis::Client::open("redis://localhost:6379")?;
    let mut conn = client.get_async_connection().await?;
    let _: String = conn.ping().await?;
    Ok(())
}
```

#### **Token Validation Failures**
```rust
// Debug token validation
#[tracing::instrument]
pub async fn debug_token_validation(token: &str) -> Result<Claims, AuthError> {
    tracing::debug!("Validating token: {}", token);
    
    // Check token format
    if !token.starts_with("eyJ") {
        tracing::error!("Invalid token format");
        return Err(AuthError::InvalidToken);
    }
    
    // Validate signature
    let claims = validate_jwt_signature(token)?;
    tracing::debug!("Token claims: {:?}", claims);
    
    Ok(claims)
}
```

#### **Performance Issues**
```rust
// Profile slow operations
use std::time::Instant;

pub async fn profile_operation<T, F>(name: &str, operation: F) -> T
where
    F: Future<Output = T>,
{
    let start = Instant::now();
    let result = operation.await;
    let duration = start.elapsed();
    
    if duration > Duration::from_millis(100) {
        tracing::warn!(
            operation = name,
            duration_ms = duration.as_millis(),
            "Slow operation detected"
        );
    }
    
    result
}
```

### **Development Tools**

#### **Database Inspection**
```bash
# Connect to Redis
redis-cli -h localhost -p 6379

# List all keys
KEYS *

# Get session data
GET session:sess_123

# Monitor commands
MONITOR
```

#### **HTTP Debugging**
```bash
# Test endpoints with curl
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test&client_secret=secret"

# Test with authentication
curl -X GET http://localhost:8080/userinfo \
  -H "Authorization: Bearer your_token_here"
```

#### **Load Testing**
```bash
# Install wrk
brew install wrk  # macOS
apt-get install wrk  # Ubuntu

# Run load test
wrk -t12 -c400 -d30s --latency http://localhost:8080/health

# Test with authentication
wrk -t4 -c100 -d10s -H "Authorization: Bearer token" \
  http://localhost:8080/userinfo
```

---

**Happy Coding! 🚀**

For questions or support, reach out to the development team or create an issue in the repository.