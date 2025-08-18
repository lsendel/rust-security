# Cryptographic Key Lifecycle Management

This document describes the cryptographic key lifecycle management implemented in the auth-service, including key generation, rotation, storage, and revocation procedures.

## Overview

The auth-service implements a comprehensive key management system that handles:

- **RSA Keys**: For JWT signing and verification
- **Symmetric Keys**: For HMAC operations and token binding
- **Post-Quantum Keys**: For future-proof cryptographic operations (optional)
- **Request Signing Keys**: For critical operation authentication

## Key Types and Usage

### 1. RSA Key Pairs

**Purpose**: JWT token signing and verification  
**Key Size**: 2048-bit minimum (configurable up to 4096-bit)  
**Algorithm**: RS256 (RSA with SHA-256)  
**Location**: `auth-service/src/keys.rs`

```rust
// Key generation
let rsa_key = generate_rsa_key_pair(2048)?;

// Usage in JWT
let token = encode(&header, &claims, &encoding_key)?;
```

### 2. HMAC Symmetric Keys

**Purpose**: Request signature validation, token binding  
**Key Size**: 256-bit minimum  
**Algorithm**: HMAC-SHA256  
**Environment Variable**: `REQUEST_SIGNING_SECRET`

### 3. Post-Quantum Keys (Optional)

**Purpose**: Future-proof cryptographic operations  
**Algorithms**: Kyber (encryption), Dilithium (signatures)  
**Feature Flag**: `post-quantum`

## Key Generation

### Initial Key Generation

Keys are generated during service startup through `keys::initialize_keys()`:

```rust
pub async fn initialize_keys() -> Result<(), KeyError> {
    // Generate RSA key pair
    let rsa_key = generate_rsa_key_pair(2048)?;
    
    // Store in secure location
    store_key_securely(&rsa_key).await?;
    
    // Validate key strength
    validate_key_security(&rsa_key)?;
    
    Ok(())
}
```

### Key Strength Validation

All keys undergo strength validation:

- **Minimum key sizes**: RSA 2048-bit, HMAC 256-bit
- **Entropy checks**: Ensures sufficient randomness
- **Algorithm validation**: Only approved algorithms accepted

## Key Storage

### Storage Locations

1. **Development**: Local filesystem with appropriate permissions
2. **Production**: 
   - Environment variables (secrets)
   - External secret management (Vault, AWS Secrets Manager)
   - Hardware Security Modules (HSM) support

### Security Measures

- **Encryption at rest**: All stored keys are encrypted
- **Access controls**: Strict file permissions (600)
- **Memory protection**: Keys cleared from memory after use
- **Audit logging**: All key operations logged

```rust
// Secure key storage
async fn store_key_securely(key: &RsaKey) -> Result<(), KeyError> {
    let encrypted_key = encrypt_key_with_master_key(key)?;
    write_with_permissions(&encrypted_key, 0o600).await?;
    audit_log("Key stored securely", &key.fingerprint());
    Ok(())
}
```

## Key Rotation

### Automatic Rotation

Keys are automatically rotated based on:

- **Time-based**: Default 90 days for RSA keys
- **Usage-based**: After N signatures/verifications
- **Security events**: Immediate rotation on compromise

### Rotation Process

1. **Generate new key pair**
2. **Overlap period**: Both old and new keys valid
3. **Update key references**
4. **Revoke old keys**
5. **Cleanup old key material**

```rust
pub async fn rotate_keys() -> Result<RotationResult, KeyError> {
    let old_key = get_current_key().await?;
    let new_key = generate_rsa_key_pair(2048)?;
    
    // Overlap period: 24 hours
    set_key_rotation_schedule(&old_key, &new_key, Duration::hours(24)).await?;
    
    // Update JWKs endpoint
    update_jwks_with_new_key(&new_key).await?;
    
    // Schedule old key cleanup
    schedule_key_cleanup(&old_key, Duration::days(7)).await?;
    
    Ok(RotationResult::Success)
}
```

### Manual Rotation

Emergency key rotation can be triggered via:

- **Admin API**: `/admin/keys/rotate` endpoint
- **Environment variable**: `FORCE_KEY_ROTATION=true`
- **CLI command**: `auth-service rotate-keys`

## Key Distribution

### JWKS Endpoint

Public keys are distributed via the JWKS (JSON Web Key Set) endpoint:

**Endpoint**: `GET /.well-known/jwks.json`

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-id-1",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### Key Versioning

- **Key ID (kid)**: Unique identifier for each key
- **Versioning scheme**: `auth-service-{timestamp}-{counter}`
- **Multiple keys**: Support for multiple active keys during rotation

## Key Revocation

### Revocation Triggers

- **Compromise detection**: Automatic revocation
- **Scheduled rotation**: Planned revocation
- **Manual intervention**: Admin-triggered revocation

### Revocation Process

1. **Add to revocation list**
2. **Update JWKS endpoint**
3. **Notify dependent services**
4. **Monitor for usage**
5. **Secure key deletion**

```rust
pub async fn revoke_key(key_id: &str, reason: RevocationReason) -> Result<(), KeyError> {
    // Add to revocation list
    add_to_revocation_list(key_id, reason).await?;
    
    // Update JWKS to remove public key
    remove_from_jwks(key_id).await?;
    
    // Audit log
    audit_log("Key revoked", &format!("kid={}, reason={:?}", key_id, reason));
    
    // Schedule secure deletion
    schedule_secure_deletion(key_id, Duration::days(30)).await?;
    
    Ok(())
}
```

## Security Considerations

### Key Protection

- **Memory protection**: Use `zeroize` crate to clear sensitive data
- **Constant-time operations**: Prevent timing attacks
- **Secure random generation**: Use OS-provided entropy sources

```rust
use zeroize::Zeroize;

struct SecretKey {
    key_material: Vec<u8>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.key_material.zeroize();
    }
}
```

### Threat Mitigation

- **Key compromise**: Rapid rotation capabilities
- **Side-channel attacks**: Constant-time implementations
- **Quantum threats**: Post-quantum algorithm support

### Compliance

- **FIPS 140-2**: Hardware security module support
- **Common Criteria**: Evaluated cryptographic modules
- **SOC 2**: Key management controls and auditing

## Monitoring and Alerting

### Key Metrics

- **Key age**: Alert when approaching rotation time
- **Usage patterns**: Detect unusual key usage
- **Failure rates**: Monitor cryptographic operation failures

### Audit Events

All key operations generate audit events:

```rust
#[derive(Serialize, Deserialize)]
pub struct KeyAuditEvent {
    pub event_type: KeyEventType,
    pub key_id: String,
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub metadata: HashMap<String, String>,
}

pub enum KeyEventType {
    KeyGenerated,
    KeyRotated,
    KeyRevoked,
    KeyAccessed,
    KeyCompromised,
}
```

## Configuration

### Environment Variables

```bash
# Key generation
RSA_KEY_SIZE=2048                    # RSA key size in bits
KEY_ROTATION_INTERVAL_DAYS=90        # Automatic rotation interval

# Storage
KEY_STORAGE_PATH=/secure/keys        # Key storage directory
MASTER_KEY_PATH=/secure/master.key   # Master encryption key

# External providers
VAULT_ENABLED=true                   # Enable HashiCorp Vault
VAULT_PATH=secret/auth-service       # Vault secret path
AWS_KMS_ENABLED=false               # Enable AWS KMS

# Post-quantum (optional)
POST_QUANTUM_ENABLED=false          # Enable PQ algorithms
PQ_KEY_SIZE=1024                    # Post-quantum key size
```

### Production Recommendations

1. **Use external key management**: Vault, AWS KMS, Azure Key Vault
2. **Enable hardware security modules**: For high-security environments
3. **Implement key escrow**: For disaster recovery
4. **Regular key rotation**: 90 days or less for production
5. **Monitor key usage**: Alert on unusual patterns

## Disaster Recovery

### Key Backup

- **Encrypted backups**: Regular encrypted key backups
- **Multiple locations**: Geographically distributed storage
- **Access controls**: Multi-person authorization for restore

### Recovery Procedures

1. **Identify scope**: Determine which keys need recovery
2. **Validate integrity**: Verify backup integrity
3. **Restore keys**: Import keys with new rotation schedule
4. **Update references**: Notify all dependent services
5. **Monitor**: Ensure proper operation post-recovery

## Implementation Checklist

### Development Phase

- [ ] Implement key generation with secure randomness
- [ ] Add key storage with encryption at rest
- [ ] Implement JWKS endpoint for public key distribution
- [ ] Add key rotation with configurable intervals
- [ ] Implement key revocation procedures
- [ ] Add comprehensive audit logging
- [ ] Write unit tests for all key operations
- [ ] Add property-based tests for key security

### Production Deployment

- [ ] Configure external key management system
- [ ] Set up key rotation automation
- [ ] Implement monitoring and alerting
- [ ] Create disaster recovery procedures
- [ ] Document operational runbooks
- [ ] Train operations team on key management
- [ ] Conduct security review and penetration testing

### Ongoing Operations

- [ ] Regular key rotation verification
- [ ] Monitor key usage patterns
- [ ] Update cryptographic algorithms as needed
- [ ] Review and update security policies
- [ ] Conduct regular security assessments
- [ ] Maintain disaster recovery procedures

## References

- [RFC 7517: JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC 7518: JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [NIST SP 800-57: Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [FIPS 140-2 Security Requirements](https://csrc.nist.gov/publications/detail/fips/140/2/final)