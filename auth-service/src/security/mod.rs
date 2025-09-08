//! Security Module
//!
//! Consolidated security functionality including:
//! - Unified rate limiting with multiple strategies
//! - Core cryptographic operations (encryption, hashing, password security)
//! - JWT and JWKS management with key rotation
//! - Post-quantum cryptography for future-proofing
//! - IP filtering and banning
//! - Adaptive rate limiting based on system load
//! - Distributed rate limiting with Redis support

#[cfg(feature = "crypto")]
pub mod cryptography;
#[cfg(feature = "crypto")]
pub mod jwt;
#[cfg(feature = "post-quantum")]
pub mod post_quantum;
pub mod rate_limiting;
pub mod threat_detection;
pub mod headers;
pub mod config_validation;
pub mod audit_logging;

// Re-export rate limiting functionality
pub use rate_limiting::{
    start_rate_limit_cleanup_task, unified_rate_limit_middleware, RateLimitConfig, RateLimitResult,
    RateLimitStats, UnifiedRateLimiter,
};

// Re-export security headers functionality
pub use headers::{
    security_headers_middleware, SecurityHeadersConfig, SecurityHeadersLayer, SecurityHeadersService,
    FrameOptions, ReferrerPolicy, XssProtection, CacheControl,
};

// Re-export configuration validation functionality
pub use config_validation::{
    SecurityConfigValidator, ValidationResult, ValidationIssue, ValidationSeverity,
    ConfigValidationError,
};

// Re-export audit logging functionality
pub use audit_logging::{
    initialize_audit_logger, get_audit_logger, SecurityAuditLogger, AuditLoggerConfig,
    SecurityEvent, SecurityEventType, SecuritySeverity, SecurityOutcome,
};

// Re-export core cryptography functionality
#[cfg(feature = "crypto")]
pub use cryptography::{
    decrypt_global, encrypt_global, get_global_crypto, hash_password_global,
    initialize_global_crypto, verify_password_global, CryptoConfig, CryptoError, CryptoMetrics,
    EncryptedData, HashAlgorithm, HmacResult, SymmetricAlgorithm, UnifiedCryptography,
};

// Re-export JWT functionality
#[cfg(feature = "crypto")]
pub use jwt::{
    create_token_global, get_global_jwt_manager, get_jwks_global, initialize_global_jwt_manager,
    validate_token_global, Claims, CryptoKey as JwtKey, Jwks, JwtAlgorithm, JwtConfig, JwtError,
    JwtMetrics, UnifiedJwtManager, ValidationResult as JwtValidationResult,
};

// Re-export post-quantum functionality
#[cfg(feature = "post-quantum")]
pub use post_quantum::{
    MigrationHelper, PostQuantumAlgorithm, PostQuantumConfig, PostQuantumError, PostQuantumKeyPair,
    PostQuantumMetrics, PostQuantumService, PostQuantumSignature, SecurityLevel,
};

// Re-export threat detection functionality
pub use threat_detection::*;
