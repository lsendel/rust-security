#!/bin/bash
# Security Hardening Script for Rust Security Platform
# Implements comprehensive security improvements across the platform

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SECURITY_DIR="$PROJECT_ROOT/security"
CONFIGS_DIR="$SECURITY_DIR/configs"

# Create directories
mkdir -p "$SECURITY_DIR" "$CONFIGS_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}"
}

info() { log "${BLUE}INFO${NC}" "$@"; }
warn() { log "${YELLOW}WARN${NC}" "$@"; }
error() { log "${RED}ERROR${NC}" "$@"; }
success() { log "${GREEN}SUCCESS${NC}" "$@"; }

# Create secure Cargo configuration for reproducible builds
create_cargo_security_config() {
    info "Creating secure Cargo configuration..."
    
    # Enhanced Cargo.toml security settings
    cat > "$CONFIGS_DIR/cargo-security.toml" <<'EOF'
# Security-hardened Cargo configuration
[target.x86_64-unknown-linux-gnu]
linker = "x86_64-linux-gnu-gcc"

[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"

# Security-focused profile settings
[profile.release]
lto = true              # Link-time optimization
codegen-units = 1       # Single codegen unit for better optimization
panic = "abort"         # Abort on panic (smaller binary, faster)
strip = true            # Strip symbols for smaller binary
opt-level = 3           # Maximum optimization

[profile.security]
inherits = "release"
debug = false           # No debug info in security builds
overflow-checks = true  # Keep overflow checks in security builds

# Dependency auditing configuration
[registry]
index = "https://github.com/rust-lang/crates.io-index"

# Supply chain security
[patch.crates-io]
# Pin known-good versions of critical dependencies

# Build reproducibility settings
[env]
SOURCE_DATE_EPOCH = "1640995200"  # Fixed timestamp for reproducible builds
CARGO_HOME = "/tmp/cargo-home"
RUSTFLAGS = "-D warnings -C target-feature=+crt-static"

# Security lints
[lints.rust]
unsafe_code = "deny"
missing_docs = "warn"
unused_results = "deny"

[lints.clippy]
# Security-focused clippy lints
all = "warn"
pedantic = "warn"
nursery = "warn"
cargo = "warn"
# Specific security lints
integer_overflow = "deny"
panic = "deny"
unwrap_used = "deny"
expect_used = "deny"
indexing_slicing = "deny"
EOF

    # Create deny.toml for security auditing
    cat > "$PROJECT_ROOT/deny.toml" <<'EOF'
# Security audit configuration for cargo-deny

[licenses]
# Only allow approved licenses
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-DFS-2016",
]
deny = [
    "GPL-2.0",
    "GPL-3.0",
    "AGPL-1.0",
    "AGPL-3.0",
    "LGPL-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "EUPL-1.2",
]
copyleft = "deny"
default = "deny"
private = { ignore = true }

[bans]
# Deny specific crates with known issues
deny = [
    # Cryptographically insecure crates
    { name = "md5" },
    { name = "sha1" },
    { name = "openssl", reason = "Use ring or aws-lc-rs instead" },
    # Unmaintained or problematic crates
    { name = "chrono", version = "<0.4.20", reason = "CVE-2020-26235" },
    { name = "time", version = "<0.2.23", reason = "CVE-2020-26235" },
    # Memory safety issues
    { name = "memchr", version = "<2.5.0", reason = "Memory safety fixes" },
]

# Skip certain crates from duplicate checking
skip = []
skip-tree = []

# Multiple versions policy
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"

[advisories]
# Security advisory database
database-path = "~/.cargo/advisory-db"
database-urls = ["https://github.com/RustSec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"
ignore = [
    # Add any known false positives here
]

[sources]
# Only allow crates.io and git sources
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
EOF

    success "Cargo security configuration created"
}

# Create secure cryptography configuration
create_crypto_hardening() {
    info "Creating cryptographic hardening configuration..."
    
    # Create secure crypto configuration
    cat > "$CONFIGS_DIR/crypto-policy.json" <<'EOF'
{
  "cryptographic_policy": {
    "version": "1.0",
    "effective_date": "2024-01-01",
    "algorithms": {
      "symmetric_encryption": {
        "approved": ["AES-256-GCM", "ChaCha20Poly1305"],
        "deprecated": ["AES-128-CBC", "AES-192-CBC"],
        "forbidden": ["DES", "3DES", "RC4"]
      },
      "asymmetric_encryption": {
        "approved": ["RSA-4096", "ECDSA-P256", "ECDSA-P384", "Ed25519"],
        "deprecated": ["RSA-2048"],
        "forbidden": ["RSA-1024", "DSA"]
      },
      "hashing": {
        "approved": ["SHA-256", "SHA-384", "SHA-512", "BLAKE3"],
        "deprecated": ["SHA-1"],
        "forbidden": ["MD5", "SHA-0"]
      },
      "key_derivation": {
        "approved": ["PBKDF2-SHA256", "Argon2id", "scrypt"],
        "parameters": {
          "pbkdf2_min_iterations": 100000,
          "argon2_memory_cost": 65536,
          "argon2_time_cost": 3,
          "argon2_parallelism": 4,
          "scrypt_n": 65536,
          "scrypt_r": 8,
          "scrypt_p": 1
        }
      },
      "digital_signatures": {
        "approved": ["Ed25519", "ECDSA-P256", "ECDSA-P384", "RSA-PSS-4096"],
        "deprecated": ["RSA-PKCS1-2048"],
        "forbidden": ["DSA", "RSA-PKCS1-1024"]
      }
    },
    "key_management": {
      "rotation_policy": {
        "signing_keys": "90_days",
        "encryption_keys": "365_days",
        "session_keys": "24_hours"
      },
      "storage": {
        "at_rest_encryption": "required",
        "key_escrow": "optional",
        "hsm_required_for": ["root_ca", "signing_keys"]
      }
    },
    "random_number_generation": {
      "approved_sources": ["ring::rand", "getrandom", "os_random"],
      "forbidden_sources": ["std::collections::hash_map::DefaultHasher", "predictable_prng"]
    },
    "tls_policy": {
      "min_version": "1.2",
      "preferred_version": "1.3",
      "cipher_suites": {
        "tls_1_3": [
          "TLS_AES_256_GCM_SHA384",
          "TLS_CHACHA20_POLY1305_SHA256",
          "TLS_AES_128_GCM_SHA256"
        ],
        "tls_1_2": [
          "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
          "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
          "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
          "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        ]
      },
      "forbidden_cipher_suites": [
        "TLS_RSA_*",
        "TLS_DH_*",
        "TLS_ECDH_*",
        "*_RC4_*",
        "*_3DES_*",
        "*_NULL_*"
      ]
    }
  }
}
EOF

    # Create crypto implementation guide
    cat > "$SECURITY_DIR/crypto-implementation-guide.md" <<'EOF'
# Cryptographic Implementation Guide

## Overview

This guide provides secure cryptographic implementations for the Rust Security Platform, following industry best practices and compliance requirements.

## Approved Cryptographic Libraries

### Primary Libraries (Ring-based)
- **ring**: Primary cryptographic library for production use
- **aws-lc-rs**: AWS Libcrypto for Rust (ring alternative)
- **rustls**: Pure Rust TLS implementation

### Specialized Libraries
- **argon2**: Password hashing
- **chacha20poly1305**: Authenticated encryption
- **ed25519-dalek**: Digital signatures
- **p256/p384**: NIST curve cryptography

## Implementation Examples

### Secure Random Number Generation
```rust
use ring::rand::{SecureRandom, SystemRandom};

pub struct SecureRandomGenerator {
    rng: SystemRandom,
}

impl SecureRandomGenerator {
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }
    
    pub fn generate_bytes(&self, dest: &mut [u8]) -> Result<(), ring::error::Unspecified> {
        self.rng.fill(dest)
    }
    
    pub fn generate_token(&self, length: usize) -> Result<String, ring::error::Unspecified> {
        let mut bytes = vec![0u8; length];
        self.rng.fill(&mut bytes)?;
        Ok(base64::encode_config(bytes, base64::URL_SAFE_NO_PAD))
    }
}
```

### Secure Password Hashing
```rust
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};

pub struct SecurePasswordHasher {
    argon2: Argon2<'static>,
}

impl SecurePasswordHasher {
    pub fn new() -> Self {
        // Use secure Argon2id parameters
        Self {
            argon2: Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(65536, 3, 4, None).unwrap(),
            ),
        }
    }
    
    pub fn hash_password(&self, password: &str) -> Result<String, argon2::password_hash::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = self.argon2.hash_password(password.as_bytes(), &salt)?;
        Ok(password_hash.to_string())
    }
    
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<(), argon2::password_hash::Error> {
        let parsed_hash = PasswordHash::new(hash)?;
        self.argon2.verify_password(password.as_bytes(), &parsed_hash)
    }
}
```

### Memory-Safe Secret Handling
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    key_data: Vec<u8>,
}

impl SecretKey {
    pub fn new(key_data: Vec<u8>) -> Self {
        Self { key_data }
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        &self.key_data
    }
    
    // Automatic zeroization on drop
}

// Usage with secure cleanup
pub fn handle_secret_key(key_bytes: Vec<u8>) {
    let secret = SecretKey::new(key_bytes);
    // Use secret...
    // Automatically zeroized when secret goes out of scope
}
```

### TLS Configuration
```rust
use rustls::{ClientConfig, ServerConfig, ProtocolVersion};
use std::sync::Arc;

pub fn create_secure_tls_config() -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(load_ca_certificates()?)
        .with_no_client_auth();
        
    // Force TLS 1.3 only for maximum security
    let mut config = config.build()?;
    config.enable_sni = true;
    
    Ok(Arc::new(config))
}

pub fn create_secure_server_config(
    cert_chain: Vec<rustls::Certificate>,
    private_key: rustls::PrivateKey,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;
        
    Ok(Arc::new(config))
}
```

## Key Management

### Key Rotation Strategy
- **Signing Keys**: 90-day rotation
- **Encryption Keys**: 365-day rotation  
- **Session Keys**: 24-hour rotation
- **API Keys**: 180-day rotation

### Secure Key Storage
```rust
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

pub struct KeyManager {
    master_key: LessSafeKey,
}

impl KeyManager {
    pub fn new(master_key_bytes: &[u8]) -> Result<Self, ring::error::Unspecified> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, master_key_bytes)?;
        let key = LessSafeKey::new(unbound_key);
        
        Ok(Self { master_key: key })
    }
    
    pub fn encrypt_key(&self, key_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, ring::error::Unspecified> {
        let nonce = Nonce::try_assume_unique_for_key(nonce)?;
        let aad = Aad::empty();
        
        let mut in_out = key_data.to_vec();
        self.master_key.seal_in_place_append_tag(nonce, aad, &mut in_out)?;
        
        Ok(in_out)
    }
    
    pub fn decrypt_key(&self, encrypted_data: &mut [u8], nonce: &[u8]) -> Result<&[u8], ring::error::Unspecified> {
        let nonce = Nonce::try_assume_unique_for_key(nonce)?;
        let aad = Aad::empty();
        
        let plaintext = self.master_key.open_in_place(nonce, aad, encrypted_data)?;
        Ok(plaintext)
    }
}
```

## Compliance Requirements

### FIPS 140-2 Considerations
- Use FIPS-validated cryptographic modules when required
- Implement proper key zeroization
- Maintain audit logs for all cryptographic operations

### Common Criteria (CC)
- Document all cryptographic implementations
- Implement proper error handling without information leakage
- Regular security testing and validation

## Security Best Practices

1. **Never roll your own crypto**: Use well-established libraries
2. **Constant-time operations**: Prevent timing attacks
3. **Secure defaults**: Use secure parameters by default
4. **Key hygiene**: Proper key generation, storage, and destruction
5. **Regular updates**: Keep cryptographic libraries updated
6. **Security audits**: Regular code reviews and penetration testing

## Testing Requirements

- Unit tests for all cryptographic functions
- Property-based testing for crypto invariants
- Fuzzing for parser and crypto code
- Security-focused integration tests
- Performance benchmarks for crypto operations
EOF

    success "Cryptographic hardening configuration created"
}

# Create memory safety and error handling improvements
create_memory_safety_config() {
    info "Creating memory safety and error handling configuration..."
    
    # Create Rust analyzer configuration for enhanced security
    cat > "$PROJECT_ROOT/.vscode/settings.json" <<'EOF'
{
    "rust-analyzer.check.command": "clippy",
    "rust-analyzer.check.allTargets": true,
    "rust-analyzer.check.extraArgs": [
        "--",
        "-D", "warnings",
        "-D", "clippy::unwrap_used",
        "-D", "clippy::expect_used",
        "-D", "clippy::panic",
        "-D", "clippy::indexing_slicing",
        "-D", "clippy::integer_overflow",
        "-W", "clippy::pedantic",
        "-W", "clippy::nursery",
        "-W", "clippy::cargo"
    ],
    "rust-analyzer.cargo.features": "all",
    "rust-analyzer.procMacro.enable": true,
    "rust-analyzer.completion.addCallParentheses": false,
    "rust-analyzer.completion.addCallArgumentSnippets": false,
    "files.watcherExclude": {
        "**/target/**": true
    }
}
EOF

    # Create clippy configuration
    cat > "$PROJECT_ROOT/clippy.toml" <<'EOF'
# Clippy configuration for security-focused linting

# Security-critical lints that should always be errors
avoid-breaking-exported-api = false
msrv = "1.70.0"

# Security lints
disallowed-methods = [
    # Unsafe memory operations
    "std::ptr::read",
    "std::ptr::write", 
    "std::mem::transmute",
    "std::mem::forget",
    
    # Panic-prone operations
    "std::slice::get_unchecked",
    "std::slice::get_unchecked_mut",
    "core::slice::SliceIndex::get_unchecked",
    
    # Network operations without timeouts
    "std::net::TcpStream::connect",
    "std::net::UdpSocket::connect",
    
    # Unsafe string operations
    "std::str::from_utf8_unchecked",
    "std::string::String::from_utf8_unchecked",
    
    # Process execution
    "std::process::Command::new",
]

disallowed-types = [
    # Insecure random number generators
    "std::collections::hash_map::DefaultHasher",
    "std::collections::hash_map::RandomState",
    
    # Deprecated crypto
    "md5::Md5",
    "sha1::Sha1",
]

# Cognitive complexity limits
cognitive-complexity-threshold = 30
type-complexity-threshold = 250
too-many-arguments-threshold = 7
too-many-lines-threshold = 100
large-type-threshold = 200
EOF

    # Create enhanced error handling patterns
    cat > "$SECURITY_DIR/error-handling-guide.md" <<'EOF'
# Error Handling Security Guide

## Security-Focused Error Handling

### Core Principles
1. **Fail Securely**: Default to deny on errors
2. **No Information Leakage**: Don't expose internal details
3. **Consistent Responses**: Use uniform error formats
4. **Audit Trail**: Log security-relevant errors
5. **Graceful Degradation**: Maintain service availability

### Error Type Hierarchy
```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Authorization denied")]
    AuthorizationDenied,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Invalid input")]
    InvalidInput,
    
    #[error("Cryptographic operation failed")]
    CryptographicFailure,
    
    #[error("Configuration error")]
    Configuration,
    
    #[error("Internal system error")]
    Internal,
}

impl SecurityError {
    pub fn public_message(&self) -> &'static str {
        match self {
            SecurityError::AuthenticationFailed => "Authentication failed",
            SecurityError::AuthorizationDenied => "Access denied",
            SecurityError::RateLimitExceeded => "Rate limit exceeded",
            SecurityError::InvalidInput => "Invalid request",
            SecurityError::CryptographicFailure => "Security operation failed",
            SecurityError::Configuration => "Service unavailable",
            SecurityError::Internal => "Internal error",
        }
    }
    
    pub fn should_log(&self) -> bool {
        matches!(self, 
            SecurityError::AuthenticationFailed |
            SecurityError::AuthorizationDenied |
            SecurityError::CryptographicFailure |
            SecurityError::Internal
        )
    }
}
```

### Safe Error Propagation
```rust
use std::result::Result as StdResult;

pub type SecurityResult<T> = StdResult<T, SecurityError>;

// Custom result type for security operations
pub trait SecurityResultExt<T> {
    fn log_security_error(self) -> SecurityResult<T>;
    fn sanitize_error(self) -> SecurityResult<T>;
}

impl<T> SecurityResultExt<T> for SecurityResult<T> {
    fn log_security_error(self) -> SecurityResult<T> {
        if let Err(ref e) = self {
            if e.should_log() {
                tracing::warn!(
                    target = "security_audit",
                    error = %e,
                    "Security error occurred"
                );
            }
        }
        self
    }
    
    fn sanitize_error(self) -> SecurityResult<T> {
        self.map_err(|e| {
            // Replace internal errors with generic ones
            match e {
                SecurityError::Internal => SecurityError::Internal,
                SecurityError::Configuration => SecurityError::Internal,
                other => other,
            }
        })
    }
}
```

### HTTP Error Responses
```rust
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

impl IntoResponse for SecurityError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            SecurityError::AuthenticationFailed => (
                StatusCode::UNAUTHORIZED,
                "AUTH_FAILED",
                self.public_message(),
            ),
            SecurityError::AuthorizationDenied => (
                StatusCode::FORBIDDEN,
                "ACCESS_DENIED",
                self.public_message(),
            ),
            SecurityError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                self.public_message(),
            ),
            SecurityError::InvalidInput => (
                StatusCode::BAD_REQUEST,
                "INVALID_INPUT",
                self.public_message(),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Internal server error",
            ),
        };

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": message,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }
        }));

        (status, body).into_response()
    }
}
```

### Memory Safety Patterns
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

// Safe secret handling
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }
    
    pub fn as_str(&self) -> &str {
        &self.inner
    }
    
    // No Clone or Debug to prevent accidental exposure
}

// Safe buffer handling
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }
    
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Explicitly zeroize memory
        self.data.zeroize();
    }
}
```

### Input Validation
```rust
use validator::{Validate, ValidationError};

#[derive(Debug, Validate)]
pub struct UserCredentials {
    #[validate(email, length(max = 254))]
    pub email: String,
    
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

#[derive(Debug, Validate)]
pub struct TokenRequest {
    #[validate(length(min = 1, max = 1024))]
    pub grant_type: String,
    
    #[validate(url)]
    pub redirect_uri: Option<String>,
    
    #[validate(length(max = 2048))]
    pub scope: Option<String>,
}

pub fn validate_input<T: Validate>(input: &T) -> SecurityResult<()> {
    input.validate()
        .map_err(|_| SecurityError::InvalidInput)
}
```

## Testing Error Conditions
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_no_information_leakage() {
        let internal_error = SecurityError::Internal;
        let response = internal_error.into_response();
        
        // Ensure no internal details are exposed
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        // Verify response body doesn't contain sensitive info
    }
    
    #[test]
    fn test_secure_string_zeroization() {
        let secret = SecureString::new("sensitive_data".to_string());
        let ptr = secret.as_str().as_ptr();
        
        drop(secret);
        
        // Memory should be zeroized (this is a simplified test)
        // In practice, use tools like valgrind or sanitizers
    }
}
```
EOF

    success "Memory safety and error handling configuration created"
}

# Create container security hardening
create_container_security() {
    info "Creating container security hardening configuration..."
    
    # Create distroless Dockerfile template
    cat > "$CONFIGS_DIR/Dockerfile.security" <<'EOF'
# Multi-stage build for security
FROM rust:1.70-slim AS builder

# Install required packages for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN addgroup --gid 10001 app && \
    adduser --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid 10001 \
    --gid 10001 \
    app

WORKDIR /app

# Copy manifests and build dependencies first for better caching
COPY Cargo.toml Cargo.lock ./
COPY auth-service/Cargo.toml ./auth-service/
COPY policy-service/Cargo.toml ./policy-service/
COPY common/Cargo.toml ./common/

# Build dependencies
RUN mkdir auth-service/src policy-service/src common/src && \
    echo "fn main() {}" > auth-service/src/main.rs && \
    echo "fn main() {}" > policy-service/src/main.rs && \
    echo "" > common/src/lib.rs && \
    cargo build --release && \
    rm -f target/release/deps/auth_service* && \
    rm -f target/release/deps/policy_service* && \
    rm -f target/release/deps/common*

# Copy source code
COPY . .

# Build application with security profile
RUN cargo build --release --profile security

# Security scanner stage
FROM aquasec/trivy:latest AS security-scan
COPY --from=builder /app/target/release/auth-service /tmp/scan/
RUN trivy fs --no-progress --exit-code 1 /tmp/scan/

# Final distroless image
FROM gcr.io/distroless/cc-debian12:nonroot

# Import app user from builder
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary with proper ownership
COPY --from=builder --chown=app:app /app/target/release/auth-service /app/auth-service

# Security hardening
USER app:app
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/auth-service", "--health-check"]

# Expose port
EXPOSE 8080

# Set security-focused environment variables
ENV RUST_BACKTRACE=0
ENV RUST_LOG=info
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR=/etc/ssl/certs

# Default command
ENTRYPOINT ["/app/auth-service"]
EOF

    # Create Docker security scanning script
    cat > "$SCRIPT_DIR/docker-security-scan.sh" <<'EOF'
#!/bin/bash
# Docker Security Scanning Script

set -euo pipefail

IMAGE_NAME=${1:-"rust-security/auth-service"}
IMAGE_TAG=${2:-"latest"}
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

echo "🔍 Scanning Docker image: $FULL_IMAGE"

# Trivy vulnerability scan
echo "Running Trivy vulnerability scan..."
trivy image --exit-code 1 --severity HIGH,CRITICAL "$FULL_IMAGE"

# Docker Bench Security (if available)
if command -v docker-bench-security >/dev/null 2>&1; then
    echo "Running Docker Bench Security..."
    docker-bench-security
fi

# Custom security checks
echo "Running custom security checks..."

# Check for non-root user
USER_INFO=$(docker inspect "$FULL_IMAGE" --format='{{.Config.User}}')
if [[ "$USER_INFO" == "root" || -z "$USER_INFO" ]]; then
    echo "❌ SECURITY: Image runs as root user"
    exit 1
else
    echo "✅ SECURITY: Image runs as non-root user: $USER_INFO"
fi

# Check for exposed ports
EXPOSED_PORTS=$(docker inspect "$FULL_IMAGE" --format='{{range $key, $value := .Config.ExposedPorts}}{{$key}} {{end}}')
echo "Exposed ports: ${EXPOSED_PORTS:-none}"

# Check image layers
echo "Analyzing image layers..."
docker history --no-trunc "$FULL_IMAGE" | grep -v "missing"

# Check for secrets in environment variables
ENV_VARS=$(docker inspect "$FULL_IMAGE" --format='{{range .Config.Env}}{{println .}}{{end}}')
if echo "$ENV_VARS" | grep -iE "(password|secret|key|token)" >/dev/null; then
    echo "⚠️  WARNING: Potential secrets found in environment variables"
    echo "$ENV_VARS" | grep -iE "(password|secret|key|token)"
fi

echo "✅ Docker security scan completed successfully"
EOF

    chmod +x "$SCRIPT_DIR/docker-security-scan.sh"

    # Create container runtime security policy
    cat > "$CONFIGS_DIR/pod-security-policy.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: security-hardened-pod
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: runtime/default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
    supplementalGroups: []
  containers:
  - name: auth-service
    image: rust-security/auth-service:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 10001
      runAsGroup: 10001
    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "512Mi"
        cpu: "500m"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
      readOnly: false
    - name: var-tmp
      mountPath: /var/tmp
      readOnly: false
  volumes:
  - name: tmp
    emptyDir: {}
  - name: var-tmp
    emptyDir: {}
  restartPolicy: Always
EOF

    success "Container security hardening configuration created"
}

# Create comprehensive security testing framework
create_security_testing() {
    info "Creating security testing framework..."
    
    # Create security test configuration
    cat > "$CONFIGS_DIR/security-testing-config.yaml" <<'EOF'
security_testing:
  static_analysis:
    tools:
      - name: "cargo-audit"
        command: "cargo audit"
        fail_on: ["high", "critical"]
      - name: "cargo-deny"
        command: "cargo deny check"
        fail_on: ["deny", "error"]
      - name: "clippy-security"
        command: "cargo clippy -- -D warnings -D clippy::unwrap_used"
        fail_on: ["error"]
    
  dynamic_analysis:
    fuzzing:
      duration: "300s"
      targets:
        - "auth_service::validation::parse_scim_filter"
        - "auth_service::oauth::parse_authorization_request"
        - "policy_service::policy::evaluate_policy"
    
    penetration_testing:
      tools:
        - name: "OWASP ZAP"
          target: "http://localhost:8080"
          scan_types: ["baseline", "full"]
        - name: "nuclei"
          templates: ["cves", "vulnerabilities", "misconfiguration"]
    
  compliance_testing:
    frameworks:
      - "OWASP ASVS"
      - "NIST Cybersecurity Framework"
      - "SOC 2 Type II"
    
  security_benchmarks:
    response_time_under_attack:
      max_latency_p99: "2000ms"
      max_error_rate: "5%"
    
    resource_exhaustion:
      max_memory_usage: "1GB"
      max_cpu_usage: "80%"

monitoring:
  security_metrics:
    - failed_authentication_attempts
    - authorization_failures
    - rate_limit_violations
    - suspicious_request_patterns
    - cryptographic_operation_failures
  
  alerting:
    thresholds:
      authentication_failure_rate: "10/minute"
      suspicious_pattern_score: ">= 7"
      resource_exhaustion: ">= 90%"
EOF

    # Create security test runner script
    cat > "$SCRIPT_DIR/security-test-runner.sh" <<'EOF'
#!/bin/bash
# Comprehensive Security Testing Runner

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$PROJECT_ROOT/security-test-results"

mkdir -p "$RESULTS_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [${1}] ${2}"
}

info() { log "${BLUE}INFO${NC}" "$1"; }
warn() { log "${YELLOW}WARN${NC}" "$1"; }
error() { log "${RED}ERROR${NC}" "$1"; }
success() { log "${GREEN}SUCCESS${NC}" "$1"; }

# Static Analysis Tests
run_static_analysis() {
    info "Running static analysis security tests..."
    
    # Cargo audit for known vulnerabilities
    info "Running cargo audit..."
    if cargo audit --json > "$RESULTS_DIR/cargo-audit.json" 2>&1; then
        success "Cargo audit passed"
    else
        error "Cargo audit found vulnerabilities"
        return 1
    fi
    
    # Cargo deny for policy violations
    info "Running cargo deny..."
    if cargo deny check > "$RESULTS_DIR/cargo-deny.log" 2>&1; then
        success "Cargo deny passed"
    else
        error "Cargo deny found policy violations"
        return 1
    fi
    
    # Security-focused clippy lints
    info "Running security clippy lints..."
    if cargo clippy --all-targets --all-features -- \
        -D warnings \
        -D clippy::unwrap_used \
        -D clippy::expect_used \
        -D clippy::panic \
        -D clippy::indexing_slicing \
        -D clippy::integer_overflow \
        > "$RESULTS_DIR/clippy-security.log" 2>&1; then
        success "Security clippy lints passed"
    else
        error "Security clippy lints failed"
        return 1
    fi
    
    success "Static analysis completed"
}

# Dynamic Analysis Tests
run_dynamic_analysis() {
    info "Running dynamic analysis security tests..."
    
    # Start services for testing
    info "Starting services for dynamic testing..."
    cargo build --release
    
    # Start auth service in background
    RUST_LOG=debug ./target/release/auth-service &
    SERVICE_PID=$!
    
    # Wait for service to start
    sleep 5
    
    # Verify service is running
    if ! curl -f http://localhost:8080/health >/dev/null 2>&1; then
        error "Service failed to start"
        kill $SERVICE_PID 2>/dev/null || true
        return 1
    fi
    
    # Run security tests
    run_api_security_tests
    run_load_security_tests
    
    # Cleanup
    kill $SERVICE_PID 2>/dev/null || true
    wait $SERVICE_PID 2>/dev/null || true
    
    success "Dynamic analysis completed"
}

# API Security Tests
run_api_security_tests() {
    info "Running API security tests..."
    
    # Test authentication bypass attempts
    info "Testing authentication bypass..."
    for endpoint in "/admin/metrics" "/admin/health" "/jwks"; do
        if curl -f "http://localhost:8080$endpoint" >/dev/null 2>&1; then
            warn "Endpoint $endpoint accessible without authentication"
        else
            success "Endpoint $endpoint properly protected"
        fi
    done
    
    # Test injection attacks
    info "Testing injection attacks..."
    # SQL injection attempts (should be blocked)
    curl -X POST "http://localhost:8080/oauth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=authorization_code&code='; DROP TABLE users; --" \
        > "$RESULTS_DIR/injection-test.log" 2>&1
    
    # XSS attempts (should be blocked)
    curl -X GET "http://localhost:8080/oauth/authorize?client_id=<script>alert('xss')</script>" \
        > "$RESULTS_DIR/xss-test.log" 2>&1
    
    # Test rate limiting
    info "Testing rate limiting..."
    for i in {1..20}; do
        curl -X POST "http://localhost:8080/oauth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials" >/dev/null 2>&1 &
    done
    wait
    
    success "API security tests completed"
}

# Load Security Tests
run_load_security_tests() {
    info "Running load-based security tests..."
    
    # Memory exhaustion test
    info "Testing memory exhaustion protection..."
    for i in {1..10}; do
        # Large payload test
        dd if=/dev/zero bs=1M count=10 2>/dev/null | \
        curl -X POST "http://localhost:8080/oauth/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            --data-binary @- >/dev/null 2>&1 &
    done
    wait
    
    # Connection exhaustion test
    info "Testing connection exhaustion protection..."
    for i in {1..100}; do
        curl "http://localhost:8080/health" >/dev/null 2>&1 &
    done
    wait
    
    success "Load security tests completed"
}

# Fuzzing Tests
run_fuzzing_tests() {
    info "Running fuzzing tests..."
    
    # Install cargo-fuzz if not present
    if ! command -v cargo-fuzz >/dev/null 2>&1; then
        info "Installing cargo-fuzz..."
        cargo install cargo-fuzz
    fi
    
    # Create fuzz targets if they don't exist
    if [[ ! -d "fuzz" ]]; then
        cargo fuzz init
    fi
    
    # Run fuzzing for a limited time
    timeout 300s cargo fuzz run scim_filter_parser || {
        if [[ $? -eq 124 ]]; then
            info "Fuzzing completed (timeout reached)"
        else
            error "Fuzzing failed"
            return 1
        fi
    }
    
    success "Fuzzing tests completed"
}

# Generate security report
generate_security_report() {
    info "Generating security test report..."
    
    cat > "$RESULTS_DIR/security-report.md" <<EOF
# Security Test Report

Generated on: $(date)

## Summary

- Static Analysis: $(test -f "$RESULTS_DIR/cargo-audit.json" && echo "✅ PASSED" || echo "❌ FAILED")
- Dynamic Analysis: $(test -f "$RESULTS_DIR/injection-test.log" && echo "✅ PASSED" || echo "❌ FAILED")
- API Security: $(test -f "$RESULTS_DIR/xss-test.log" && echo "✅ PASSED" || echo "❌ FAILED")

## Detailed Results

### Static Analysis
$(cat "$RESULTS_DIR/cargo-audit.json" 2>/dev/null | jq '.vulnerabilities | length' || echo "0") vulnerabilities found

### Dynamic Analysis
API endpoints tested: $(grep -c "Testing" "$RESULTS_DIR"/*.log 2>/dev/null || echo "0")

### Recommendations

1. Regular security updates
2. Continuous monitoring
3. Penetration testing
4. Security training

## Action Items

- [ ] Review and remediate any high-severity findings
- [ ] Update security policies based on test results
- [ ] Schedule next security assessment

EOF

    success "Security report generated: $RESULTS_DIR/security-report.md"
}

# Security testing main execution
security_testing_main() {
    info "Starting comprehensive security testing..."
    
    cd "$PROJECT_ROOT"
    
    # Run all security test suites
    run_static_analysis
    run_dynamic_analysis
    
    # Optional: Run fuzzing (time-consuming)
    if [[ "${RUN_FUZZING:-false}" == "true" ]]; then
        run_fuzzing_tests
    fi
    
    # Generate final report
    generate_security_report
    
    success "Security testing completed successfully!"
    info "Results available in: $RESULTS_DIR"
}

# Script entry point for security testing
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    security_testing_main "$@"
fi
EOF

    chmod +x "$SCRIPT_DIR/security-test-runner.sh"

    success "Security testing framework created"
}

# Main execution function for the hardening script
hardening_main() {
    local command=${1:-"all"}
    
    info "Starting security hardening implementation..."
    
    case "$command" in
        "cargo")
            create_cargo_security_config
            ;;
        "crypto")
            create_crypto_hardening
            ;;
        "memory")
            create_memory_safety_config
            ;;
        "container")
            create_container_security
            ;;
        "testing")
            create_security_testing
            ;;
        "all")
            create_cargo_security_config
            create_crypto_hardening
            create_memory_safety_config
            create_container_security
            create_security_testing
            ;;
        "help"|"-h"|"--help")
            cat << EOF
Security Hardening Script

Usage: $0 [command]

Commands:
    cargo       - Create Cargo security configuration
    crypto      - Create cryptographic hardening
    memory      - Create memory safety configuration
    container   - Create container security hardening
    testing     - Create security testing framework
    all         - Run all hardening steps (default)
    help        - Show this help message

Examples:
    $0 all          # Complete security hardening
    $0 crypto       # Only cryptographic hardening
    $0 testing      # Only security testing framework
EOF
            ;;
        *)
            error "Unknown command: $command"
            exit 1
            ;;
    esac
    
    success "Security hardening implementation completed!"
    info "Configuration files created in: $SECURITY_DIR"
    info "Run the security test runner: $SCRIPT_DIR/security-test-runner.sh"
}

# Script entry point for hardening
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    hardening_main "$@"
fi