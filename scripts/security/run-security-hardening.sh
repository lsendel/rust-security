#!/bin/bash
# Security Hardening Implementation Script
# Creates comprehensive security configurations and policies

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

# Create deny.toml for security auditing
create_deny_config() {
    info "Creating cargo-deny security configuration..."
    
    cat > "$PROJECT_ROOT/deny.toml" <<'EOF'
# Security audit configuration for cargo-deny

[licenses]
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
]
copyleft = "deny"
default = "deny"

[bans]
deny = [
    { name = "md5" },
    { name = "sha1" },
    { name = "openssl", reason = "Use ring or aws-lc-rs instead" },
    { name = "chrono", version = "<0.4.20", reason = "CVE-2020-26235" },
]

[advisories]
database-path = "~/.cargo/advisory-db"
database-urls = ["https://github.com/RustSec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
EOF

    success "Cargo deny configuration created"
}

# Create clippy security configuration
create_clippy_config() {
    info "Creating clippy security configuration..."
    
    cat > "$PROJECT_ROOT/clippy.toml" <<'EOF'
# Clippy configuration for security-focused linting
avoid-breaking-exported-api = false
msrv = "1.70.0"

disallowed-methods = [
    "std::ptr::read",
    "std::ptr::write", 
    "std::mem::transmute",
    "std::slice::get_unchecked",
    "std::str::from_utf8_unchecked",
]

disallowed-types = [
    "md5::Md5",
    "sha1::Sha1",
]

cognitive-complexity-threshold = 30
type-complexity-threshold = 250
EOF

    success "Clippy configuration created"
}

# Create security Dockerfile
create_secure_dockerfile() {
    info "Creating secure Dockerfile template..."
    
    cat > "$CONFIGS_DIR/Dockerfile.security" <<'EOF'
# Multi-stage security-hardened build
FROM rust:1.70-slim AS builder

# Install security updates first
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
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
COPY . .

# Build with security profile
RUN cargo build --release

# Final distroless image
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder --chown=app:app /app/target/release/auth-service /app/auth-service

USER app:app
WORKDIR /app

EXPOSE 8080
ENTRYPOINT ["/app/auth-service"]
EOF

    success "Secure Dockerfile created"
}

# Create Pod Security Policy
create_pod_security_policy() {
    info "Creating Pod Security Policy..."
    
    cat > "$CONFIGS_DIR/pod-security-standards.yaml" <<'EOF'
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
  volumes:
  - name: tmp
    emptyDir: {}
EOF

    success "Pod Security Policy created"
}

# Create cryptographic policy
create_crypto_policy() {
    info "Creating cryptographic policy..."
    
    cat > "$CONFIGS_DIR/crypto-policy.json" <<'EOF'
{
  "cryptographic_policy": {
    "version": "1.0",
    "algorithms": {
      "symmetric_encryption": {
        "approved": ["AES-256-GCM", "ChaCha20Poly1305"],
        "forbidden": ["DES", "3DES", "RC4"]
      },
      "asymmetric_encryption": {
        "approved": ["RSA-4096", "ECDSA-P256", "Ed25519"],
        "forbidden": ["RSA-1024", "DSA"]
      },
      "hashing": {
        "approved": ["SHA-256", "SHA-384", "SHA-512", "BLAKE3"],
        "forbidden": ["MD5", "SHA-1"]
      }
    },
    "key_management": {
      "rotation_policy": {
        "signing_keys": "90_days",
        "encryption_keys": "365_days"
      }
    }
  }
}
EOF

    success "Cryptographic policy created"
}

# Create security documentation
create_security_docs() {
    info "Creating security documentation..."
    
    cat > "$SECURITY_DIR/SECURITY-IMPLEMENTATION.md" <<'EOF'
# Security Implementation Guide

## Overview

This document outlines the comprehensive security hardening implementation for the Rust Security Platform.

## Security Configurations

### 1. Cargo Security (`deny.toml`)
- License policy enforcement
- Vulnerability scanning
- Dependency auditing
- Supply chain security

### 2. Clippy Security (`clippy.toml`)
- Security-focused lints
- Unsafe operation detection
- Memory safety checks
- Cryptographic validation

### 3. Container Security
- Distroless base images
- Non-root user execution
- Read-only root filesystem
- Minimal attack surface

### 4. Kubernetes Security
- Pod Security Standards
- Network policies
- RBAC controls
- Security contexts

### 5. Cryptographic Policy
- Approved algorithms
- Key management
- Rotation schedules
- Compliance requirements

## Implementation Steps

1. **Install Security Tools**
   ```bash
   cargo install cargo-audit cargo-deny
   ```

2. **Run Security Checks**
   ```bash
   cargo audit
   cargo deny check
   cargo clippy -- -D warnings
   ```

3. **Build Secure Images**
   ```bash
   docker build -f security/configs/Dockerfile.security .
   ```

4. **Deploy with Security**
   ```bash
   kubectl apply -f security/configs/pod-security-standards.yaml
   ```

## Monitoring and Alerting

- Continuous vulnerability scanning
- Security metrics collection
- Incident response procedures
- Compliance reporting

## Best Practices

1. Regular security updates
2. Principle of least privilege
3. Defense in depth
4. Zero trust architecture
5. Continuous monitoring
EOF

    success "Security documentation created"
}

# Main execution
main() {
    info "Starting comprehensive security hardening..."
    
    create_deny_config
    create_clippy_config
    create_secure_dockerfile
    create_pod_security_policy
    create_crypto_policy
    create_security_docs
    
    success "Security hardening implementation completed!"
    info "Security configurations created in: $SECURITY_DIR"
    info "Review the SECURITY-IMPLEMENTATION.md guide for next steps"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi