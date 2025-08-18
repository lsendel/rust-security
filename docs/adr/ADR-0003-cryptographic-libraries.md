# ADR-0003: Cryptographic Libraries Selection

## Status
Accepted

## Context
The Rust Security Platform requires robust cryptographic operations for:
- JWT signing and verification (RSA, ECDSA, EdDSA)
- Symmetric encryption for sensitive data
- Secure random number generation
- Key derivation and password hashing
- TLS/HTTPS communications
- Post-quantum cryptography preparation

We need to select cryptographic libraries that provide:
- Strong security guarantees
- Constant-time operations to prevent timing attacks
- Good performance characteristics
- Active maintenance and security updates
- Compliance with security standards

## Decision

### Primary Cryptographic Libraries

#### Core Cryptography: Ring
- **ring**: Primary library for cryptographic primitives
- **Rationale**: Audited, constant-time, high-performance, used by major projects
- **Use cases**: HMAC, AES-GCM, ECDSA, random number generation, key derivation

#### JWT Operations: jsonwebtoken + ring
- **jsonwebtoken**: High-level JWT library for token operations
- **ring integration**: Use ring for underlying cryptographic operations
- **Replaced**: Removed vulnerable `rsa` crate (RUSTSEC-2023-0071)

#### Password Hashing: Argon2
- **argon2**: Password hashing with configurable parameters
- **Rationale**: Winner of Password Hashing Competition, resistant to time-memory trade-offs

#### Additional Encryption: ChaCha20-Poly1305
- **chacha20poly1305**: For high-performance AEAD when AES-GCM isn't suitable
- **Rationale**: Excellent performance on systems without AES-NI

#### Secure Memory: zeroize
- **zeroize**: Zero sensitive data from memory
- **Rationale**: Prevents sensitive data from remaining in memory/swap

#### TLS: rustls
- **rustls**: Pure Rust TLS implementation
- **Rationale**: Memory-safe, audited, supports modern TLS versions

### Algorithm Choices

#### JWT Signing Algorithms (in order of preference)
1. **EdDSA (Ed25519)**: Fast, simple, secure
2. **ECDSA (P-256)**: NIST standard, widely supported  
3. **RSA (RSA-PSS, 2048+ bits)**: Legacy compatibility when needed

#### Symmetric Encryption
1. **AES-256-GCM**: Primary choice for authenticated encryption
2. **ChaCha20-Poly1305**: Alternative for non-AES-NI systems

#### Key Derivation
- **PBKDF2**: For legacy compatibility
- **Argon2id**: Preferred for new implementations

### Post-Quantum Preparation
- **pqcrypto-kyber**: Key encapsulation for hybrid schemes
- **pqcrypto-dilithium**: Digital signatures for hybrid schemes
- **Hybrid approach**: Combine classical and post-quantum algorithms

## Consequences

### Positive
- High security with audited, constant-time implementations
- Good performance characteristics
- Memory safety from Rust + careful library selection
- Clear migration path to post-quantum cryptography
- Compliance with modern security standards

### Negative
- Multiple dependencies to manage and audit
- Need for careful algorithm parameter selection
- Complexity in hybrid classical/post-quantum schemes
- Potential performance impact of constant-time operations

## Alternatives Considered

### OpenSSL Bindings
- **Rejected**: Foreign function interface complexity and security risks
- **Rejected**: Not memory-safe despite being widely used
- **Considered**: May be needed for specific compliance requirements

### Native Rust Implementations (RustCrypto)
- **Partially adopted**: Used for specific algorithms where ring doesn't suffice
- **Concern**: Less auditing than ring for critical operations
- **Use case**: Educational and specific algorithm support

### BoringSSL/AWS-LC
- **Considered**: Google's/AWS's OpenSSL fork with security improvements
- **Decision**: Use ring which is based on BoringSSL primitives

## Implementation Guidelines

### Key Management
```rust
// Secure key generation
use ring::rand::{SystemRandom, SecureRandom};
let rng = SystemRandom::new();
let mut key_bytes = [0u8; 32];
rng.fill(&mut key_bytes)?;

// Automatic zeroization
use zeroize::Zeroize;
struct SecretKey([u8; 32]);
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
```

### JWT Signing
```rust
// Use Ed25519 for new tokens
use jsonwebtoken::{Algorithm, EncodingKey};
let key = EncodingKey::from_ed_pem(ed25519_private_key)?;
let header = Header::new(Algorithm::EdDSA);
```

### Constant-Time Comparisons
```rust
use constant_time_eq::constant_time_eq;
// Always use constant-time comparison for secrets
if constant_time_eq(provided_token, expected_token) {
    // Token is valid
}
```

## Security Requirements

### Key Rotation
- Minimum 90-day rotation for signing keys
- Support for overlapping key validity periods
- Emergency rotation procedures documented

### Algorithm Deprecation
- Monitor NIST/industry guidance for algorithm lifecycle
- Prepare migration timelines for deprecated algorithms
- Maintain backward compatibility during transitions

### Compliance
- Ensure FIPS 140-2 compliance where required
- Document algorithm choices for security audits
- Regular security reviews of cryptographic implementations

## Related ADRs
- [ADR-0001](ADR-0001-service-boundaries.md): Service Boundaries and Responsibilities
- [ADR-0002](ADR-0002-token-storage-strategy.md): Token Storage Strategy