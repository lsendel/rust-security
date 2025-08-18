# ADR-0004: JWT Signing Key Management Strategy

## Status
Accepted

## Context
The auth-service requires a robust JWT signing key management strategy to ensure:
- Secure key generation and storage
- Regular key rotation for security hygiene
- Zero-downtime key rotation
- Audit trail for key lifecycle events
- Emergency key revocation capabilities
- Backward compatibility during rotation periods

Currently, the key management system is basic with limited security controls, no formal rotation cadence, and minimal observability.

## Decision
We will implement a comprehensive key management strategy with the following components:

### 1. Key Generation
- **Algorithm**: RSA-2048 with RS256 for JWT signing (future support for ECDSA P-256)
- **Key Source**: Hardware Security Module (HSM) or secure key derivation in production
- **Key Derivation**: PBKDF2 or Argon2 for master key derivation from entropy sources
- **Random Source**: System cryptographically secure random number generator

### 2. Key Storage
- **At Rest**: Keys encrypted with master key derived from HSM or environment-specific secrets
- **In Memory**: Keys stored in secure memory with zeroization on cleanup
- **Backup**: Encrypted key backups in secure storage with versioning
- **Access Control**: Role-based access with audit logging for all key operations

### 3. Key Rotation Cadence
- **Regular Rotation**: Every 24 hours in production, 1 hour in development
- **Emergency Rotation**: Immediate rotation capability with API endpoint
- **Overlap Period**: 48-hour overlap to allow in-flight tokens to remain valid
- **Maximum Key Age**: 72 hours absolute maximum before key is purged

### 4. Key Lifecycle States
- **PENDING**: Key generated but not yet active
- **ACTIVE**: Primary signing key for new tokens
- **ROTATING**: Key in rotation, still valid for verification
- **DEPRECATED**: Key no longer used for signing, valid for verification only
- **REVOKED**: Key compromised, immediately invalid for all operations

### 5. Audit and Monitoring
- **Key Events**: Generation, activation, rotation, deprecation, revocation
- **Metrics**: Key age, rotation frequency, usage statistics
- **Alerts**: Failed rotations, key age violations, suspicious access patterns
- **Compliance**: Detailed audit logs for security compliance requirements

### 6. Emergency Procedures
- **Compromise Response**: Immediate key revocation and rotation
- **Recovery**: Multi-step recovery process with authorization
- **Rollback**: Ability to rollback to previous key generation in emergency
- **Communication**: Automated notification to dependent services

## Implementation Details

### Key Management Service
```rust
pub struct KeyManagementService {
    // Key storage with encryption at rest
    key_store: Arc<dyn SecureKeyStore>,
    // Metrics and monitoring
    metrics: Arc<KeyMetrics>,
    // Audit logger for compliance
    audit_logger: Arc<dyn AuditLogger>,
    // Configuration for rotation policies
    config: KeyManagementConfig,
}
```

### Key Rotation Algorithm
1. Generate new key pair
2. Update JWKS endpoint with new key (maintaining old keys)
3. Activate new key for signing
4. Maintain old key for verification (overlap period)
5. Deprecate old key after overlap period
6. Purge expired keys after retention period

### Configuration
```rust
pub struct KeyManagementConfig {
    pub rotation_interval: Duration,
    pub overlap_period: Duration,
    pub max_key_age: Duration,
    pub key_size: u32,
    pub algorithm: KeyAlgorithm,
    pub backup_enabled: bool,
    pub audit_enabled: bool,
}
```

## Consequences

### Positive
- **Enhanced Security**: Regular rotation reduces exposure window
- **Zero Downtime**: Overlapping keys ensure continuous service availability
- **Compliance Ready**: Audit trails meet regulatory requirements
- **Operational Safety**: Emergency procedures for compromise scenarios
- **Observability**: Comprehensive metrics and monitoring

### Negative
- **Complexity**: Increased system complexity requiring careful testing
- **Storage Requirements**: Multiple keys and audit logs require storage
- **Performance Impact**: Key rotation operations may cause brief latency spikes
- **Dependencies**: Requires secure storage infrastructure

### Risks and Mitigations
- **Risk**: Key rotation failure during critical operations
  - **Mitigation**: Robust retry logic and fallback mechanisms
- **Risk**: Key compromise detection delay
  - **Mitigation**: Real-time monitoring and anomaly detection
- **Risk**: Clock synchronization issues affecting key validity
  - **Mitigation**: NTP synchronization and grace periods

## Alternatives Considered

### Alternative 1: External Key Management Service (AWS KMS, HashiCorp Vault)
- **Pros**: Managed service, HSM backing, compliance features
- **Cons**: Vendor lock-in, latency for key operations, cost
- **Decision**: Implement internal system first, with external KMS as future option

### Alternative 2: Static Key Management
- **Pros**: Simple implementation, no rotation complexity
- **Cons**: Poor security posture, compliance issues, compromise exposure
- **Decision**: Rejected due to security requirements

### Alternative 3: Client-Side Key Management
- **Pros**: Distributed security model
- **Cons**: Complex coordination, inconsistent implementations
- **Decision**: Rejected due to operational complexity

## References
- [RFC 7517: JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518: JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [NIST SP 800-57: Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)