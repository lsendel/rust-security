# Security Fix Implementation Plan

## Phase 1: Critical Security Vulnerabilities

### 1. RSA Marvin Attack Fix (RUSTSEC-2023-0071)

**Issue**: The `rsa` crate has a timing side-channel vulnerability that could allow key recovery.

**Solution**: Replace RSA operations with `ring` crate implementation.

**Files to modify**:
- `auth-service/src/keys.rs`
- `auth-service/src/keys_secure.rs` 
- `auth-service/src/keys_optimized.rs`
- `auth-service/src/webauthn.rs`

**Implementation**:
```rust
// Replace rsa crate usage with ring
use ring::{
    rand::SystemRandom,
    signature::{RsaKeyPair, RSA_PKCS1_SHA256},
};

// Update key generation to use ring
pub fn generate_rsa_keypair() -> Result<RsaKeyPair, ring::error::Unspecified> {
    let rng = SystemRandom::new();
    RsaKeyPair::generate_pkcs1(&rng, 2048)
}
```

### 2. Dependency Security Updates

**Update Cargo.toml dependencies**:
```toml
# Remove vulnerable rsa crate
# rsa = "0.9.8"  # REMOVE

# Add secure alternatives
ring = "0.17"
webpki = "0.22"
rustls = "0.23"
```

### 3. Fix proc-macro-error Unmaintained Warning

**Solution**: Update utoipa to latest version that doesn't depend on proc-macro-error.

```toml
utoipa = "5.0"  # Update from 4.2.3
utoipa-swagger-ui = "8.0"  # Update from 6.0.0
```

## Phase 2: Code Quality Fixes

### 1. Fix Compiler Warnings

**Unused Imports**:
```rust
// auth-service/src/key_rotation.rs
// Remove: use crate::keys;

// auth-service/src/webauthn.rs  
// Remove: use base64::engine::general_purpose::URL_SAFE_NO_PAD;

// auth-service/src/lib.rs
// Remove: use utoipa::OpenApi;
// Remove: SessionError from session_manager import
```

**Never Type Fallback**:
```rust
// auth-service/src/session_manager.rs
// Fix Redis query_async calls
.query_async::<()>(&mut conn)  // Add explicit type annotation
```

**Unused Variables**:
```rust
// Prefix with underscore or remove
let _mfa_verified = ...;
let _time_window = ...;
```

### 2. Fix Failing Test

**File**: `auth-service/tests/authorization_it.rs`

**Issue**: Test expects INTERNAL_SERVER_ERROR but gets different status.

**Fix**: Update test assertion or fix the underlying authorization logic.

## Phase 3: Performance Optimizations

### 1. Optimize Token Store Operations

**Current Issue**: 7 separate Redis operations per token lookup.

**Solution**: Implement batch operations and caching.

```rust
// Implement Redis pipeline for batch operations
pub async fn get_record_optimized(&self, token: &str) -> Result<IntrospectionRecord> {
    let mut pipe = redis::pipe();
    pipe.hgetall(&token_key)
        .hgetall(&metadata_key)
        .expire(&token_key, ttl);
    
    let results: Vec<HashMap<String, String>> = pipe
        .query_async(&mut conn)
        .await?;
    
    // Process results in single operation
}
```

### 2. Async JWT Operations

**Replace blocking RSA operations with async alternatives**:
```rust
use tokio::task::spawn_blocking;

pub async fn sign_jwt_async(claims: &Claims) -> Result<String> {
    let key = self.key.clone();
    spawn_blocking(move || {
        // Perform RSA signing in thread pool
        sign_jwt_blocking(&key, claims)
    }).await?
}
```

## Phase 4: Documentation & Maintenance

### 1. Complete Documentation

**Files to update**:
- `product/mission.md` - Remove TODO items
- `product/roadmap.md` - Update implementation status
- `product/analysis-summary.md` - Add current status

### 2. Production Configuration Hardening

**Update docker-compose.yml**:
```yaml
# Use production-ready configurations
environment:
  - JWT_SECRET=${JWT_SECRET}  # Use env var
  - RUST_LOG=info  # Reduce log level for production
```

**Update .env.example**:
```bash
# Add missing production configurations
ENVIRONMENT=production
SECURITY_HEADERS_ENABLED=true
RATE_LIMIT_STRICT_MODE=true
```

## Implementation Timeline

### Week 1: Critical Security Fixes
- [ ] Day 1-2: Fix RSA vulnerability
- [ ] Day 3: Update dependencies
- [ ] Day 4-5: Test security fixes

### Week 2: Code Quality & Performance
- [ ] Day 1-2: Fix compiler warnings
- [ ] Day 3: Fix failing tests
- [ ] Day 4-5: Implement performance optimizations

### Week 3: Documentation & Final Testing
- [ ] Day 1-2: Complete documentation
- [ ] Day 3-4: Production configuration hardening
- [ ] Day 5: Comprehensive testing and validation

## Success Criteria

### Security
- [ ] All security vulnerabilities resolved
- [ ] Security audit passes with no critical issues
- [ ] Dependency audit clean

### Code Quality
- [ ] Zero compiler warnings
- [ ] All tests passing
- [ ] Code coverage > 80%

### Performance
- [ ] Token operations < 10ms P95 latency
- [ ] Memory usage optimized
- [ ] Load test performance improved by 30%

### Documentation
- [ ] All TODO items resolved
- [ ] Production deployment guide complete
- [ ] API documentation up to date
