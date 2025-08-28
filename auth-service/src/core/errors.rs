//! Core error types for the authentication service
//!
//! This module provides a unified error system that consolidates all error types
//! used throughout the authentication service for better error handling and debugging.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use common::CommonError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Core result type for authentication operations
pub type CoreResult<T> = Result<T, CoreError>;

/// Unified core error type that encompasses all possible errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum CoreError {
    /// Authentication-related errors
    #[error("Authentication error: {0}")]
    Authentication(#[from] AuthenticationError),

    /// Authorization-related errors
    #[error("Authorization error: {0}")]
    Authorization(#[from] AuthorizationError),

    /// Cryptographic operation errors
    #[error("Cryptographic error: {0}")]
    Cryptographic(#[from] CryptographicError),

    /// Token-related errors
    #[error("Token error: {0}")]
    Token(#[from] TokenError),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Configuration(#[from] ConfigurationError),

    /// Network-related errors
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Storage/persistence errors
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// Rate limiting errors
    #[error("Rate limit error: {0}")]
    RateLimit(#[from] RateLimitError),

    /// Security violation errors
    #[error("Security error: {0}")]
    Security(#[from] SecurityError),

    /// Validation errors
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    /// Cache operation errors
    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),

    /// Internal system errors
    #[error("Internal error: {message}")]
    Internal { message: String },
}

/// Authentication-specific errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Account locked")]
    AccountLocked,
    #[error("Account disabled")]
    AccountDisabled,
    #[error("Multi-factor authentication required")]
    MfaRequired,
    #[error("Invalid MFA token")]
    InvalidMfaToken,
    #[error("Authentication timeout")]
    Timeout,
    #[error("Too many authentication attempts")]
    TooManyAttempts,
    #[error("Password expired")]
    PasswordExpired,
    #[error("Authentication method not supported")]
    MethodNotSupported,
}

/// Authorization-specific errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum AuthorizationError {
    #[error("Access denied")]
    AccessDenied,
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error("Missing required scope: {scope}")]
    MissingScope { scope: String },
    #[error("Resource not found")]
    ResourceNotFound,
    #[error("Forbidden operation")]
    ForbiddenOperation,
    #[error("Policy evaluation failed")]
    PolicyEvaluationFailed,
    #[error("Role assignment error")]
    RoleAssignmentError,
}

/// Cryptographic operation errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum CryptographicError {
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Hash computation failed")]
    HashComputationFailed,
    #[error("Random generation failed")]
    RandomGenerationFailed,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Certificate validation failed")]
    CertificateValidationFailed,
}

/// Token-related errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum TokenError {
    #[error("Token expired")]
    Expired,
    #[error("Invalid token format")]
    InvalidFormat,
    #[error("Token signature invalid")]
    InvalidSignature,
    #[error("Token not found")]
    NotFound,
    #[error("Token revoked")]
    Revoked,
    #[error("Token generation failed")]
    GenerationFailed,
    #[error("Token binding validation failed")]
    BindingValidationFailed,
    #[error("Refresh token invalid")]
    InvalidRefreshToken,
    #[error("Token audience mismatch")]
    AudienceMismatch,
    #[error("Token issuer invalid")]
    InvalidIssuer,
}

/// Configuration-related errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum ConfigurationError {
    #[error("Missing required configuration: {key}")]
    MissingRequired { key: String },
    #[error("Invalid configuration value: {key}")]
    InvalidValue { key: String },
    #[error("Configuration file not found")]
    FileNotFound,
    #[error("Configuration parsing failed")]
    ParsingFailed,
    #[error("Environment variable not set: {var}")]
    EnvVarNotSet { var: String },
    #[error("Configuration validation failed")]
    ValidationFailed,
}

/// Network-related errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum NetworkError {
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("Connection refused")]
    ConnectionRefused,
    #[error("DNS resolution failed")]
    DnsResolutionFailed,
    #[error("TLS handshake failed")]
    TlsHandshakeFailed,
    #[error("HTTP request failed: {status}")]
    HttpRequestFailed { status: u16 },
    #[error("Network unreachable")]
    NetworkUnreachable,
    #[error("Invalid URL")]
    InvalidUrl,
}

/// Storage/persistence errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum StorageError {
    #[error("Database connection failed")]
    ConnectionFailed,
    #[error("Query execution failed")]
    QueryFailed,
    #[error("Transaction failed")]
    TransactionFailed,
    #[error("Record not found")]
    RecordNotFound,
    #[error("Constraint violation")]
    ConstraintViolation,
    #[error("Serialization failed")]
    SerializationFailed,
    #[error("Deserialization failed")]
    DeserializationFailed,
    #[error("Storage quota exceeded")]
    QuotaExceeded,
}

/// Rate limiting errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitError {
    #[error("Rate limit exceeded")]
    Exceeded,
    #[error("Rate limit configuration invalid")]
    InvalidConfiguration,
    #[error("Rate limiter unavailable")]
    Unavailable,
    #[error("Quota exhausted")]
    QuotaExhausted,
}

/// Security-related errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum SecurityError {
    #[error("Security policy violation")]
    PolicyViolation,
    #[error("Suspicious activity detected")]
    SuspiciousActivity,
    #[error("Security scan failed")]
    ScanFailed,
    #[error("Threat detected: {threat_type}")]
    ThreatDetected { threat_type: String },
    #[error("Security audit failed")]
    AuditFailed,
    #[error("Compliance violation")]
    ComplianceViolation,
    #[error("Anomaly detected")]
    AnomalyDetected,
}

/// Validation errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum ValidationError {
    #[error("Field validation failed: {field}")]
    FieldValidation { field: String },
    #[error("Format validation failed")]
    FormatValidation,
    #[error("Length validation failed")]
    LengthValidation,
    #[error("Range validation failed")]
    RangeValidation,
    #[error("Pattern validation failed")]
    PatternValidation,
    #[error("Required field missing: {field}")]
    RequiredFieldMissing { field: String },
    #[error("Schema validation failed")]
    SchemaValidation,
}

/// Cache operation errors
#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum CacheError {
    #[error("Cache miss")]
    Miss,
    #[error("Cache write failed")]
    WriteFailed,
    #[error("Cache read failed")]
    ReadFailed,
    #[error("Cache invalidation failed")]
    InvalidationFailed,
    #[error("Cache connection failed")]
    ConnectionFailed,
    #[error("Cache timeout")]
    Timeout,
    #[error("Cache capacity exceeded")]
    CapacityExceeded,
}

impl CoreError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Authentication(auth_err) => match auth_err {
                AuthenticationError::InvalidCredentials
                | AuthenticationError::InvalidMfaToken
                | AuthenticationError::PasswordExpired => StatusCode::UNAUTHORIZED,
                AuthenticationError::AccountLocked
                | AuthenticationError::AccountDisabled
                | AuthenticationError::TooManyAttempts => StatusCode::FORBIDDEN,
                AuthenticationError::MfaRequired => StatusCode::PRECONDITION_REQUIRED,
                AuthenticationError::Timeout => StatusCode::REQUEST_TIMEOUT,
                AuthenticationError::MethodNotSupported => StatusCode::METHOD_NOT_ALLOWED,
            },
            Self::Authorization(_) => StatusCode::FORBIDDEN,
            Self::Token(token_err) => match token_err {
                TokenError::Expired | TokenError::Revoked => StatusCode::UNAUTHORIZED,
                TokenError::NotFound => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_REQUEST,
            },
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Network(net_err) => match net_err {
                NetworkError::ConnectionTimeout => StatusCode::REQUEST_TIMEOUT,
                NetworkError::ConnectionRefused
                | NetworkError::NetworkUnreachable => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::BAD_GATEWAY,
            },
            Self::Storage(storage_err) => match storage_err {
                StorageError::RecordNotFound => StatusCode::NOT_FOUND,
                StorageError::ConstraintViolation => StatusCode::CONFLICT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Security(_) => StatusCode::FORBIDDEN,
            Self::Cache(_) | Self::Cryptographic(_) | Self::Internal { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// Get the error category for logging and metrics
    pub fn category(&self) -> &'static str {
        match self {
            Self::Authentication(_) => "authentication",
            Self::Authorization(_) => "authorization",
            Self::Cryptographic(_) => "cryptographic",
            Self::Token(_) => "token",
            Self::Configuration(_) => "configuration",
            Self::Network(_) => "network",
            Self::Storage(_) => "storage",
            Self::RateLimit(_) => "rate_limit",
            Self::Security(_) => "security",
            Self::Validation(_) => "validation",
            Self::Cache(_) => "cache",
            Self::Internal { .. } => "internal",
        }
    }

    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Network(NetworkError::ConnectionTimeout)
                | Self::Network(NetworkError::NetworkUnreachable)
                | Self::Storage(StorageError::ConnectionFailed)
                | Self::Cache(CacheError::Timeout)
                | Self::Cache(CacheError::ConnectionFailed)
                | Self::RateLimit(RateLimitError::Exceeded)
        )
    }

    /// Create an internal error
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

impl IntoResponse for CoreError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_response = ErrorResponse {
            error: self.category().to_string(),
            message: self.to_string(),
            code: status.as_u16(),
        };

        (status, Json(error_response)).into_response()
    }
}

/// Error response structure for API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub code: u16,
}

/// Convert common errors to core errors
impl From<CommonError> for CoreError {
    fn from(err: CommonError) -> Self {
        match err {
            CommonError::Authentication { message: _ } => {
                Self::Authentication(AuthenticationError::InvalidCredentials)
            }
            CommonError::Authorization { message: _ } => {
                Self::Authorization(AuthorizationError::AccessDenied)
            }
            CommonError::Configuration { message: _ } => {
                Self::Configuration(ConfigurationError::ValidationFailed)
            }
            CommonError::Network { message: _ } => Self::Network(NetworkError::InvalidUrl),
            CommonError::Database { message: _ } => {
                Self::Storage(StorageError::ConnectionFailed)
            }
            CommonError::Cache { message: _ } => Self::Cache(CacheError::ConnectionFailed),
            CommonError::RateLimit { message: _ } => Self::RateLimit(RateLimitError::Exceeded),
            CommonError::Security { message: _ } => {
                Self::Security(SecurityError::PolicyViolation)
            }
            CommonError::ServiceUnavailable { message: _ } => {
                Self::Network(NetworkError::NetworkUnreachable)
            }
            CommonError::InvalidInput { message: _ } => {
                Self::Validation(ValidationError::FormatValidation)
            }
            CommonError::NotFound { resource: _ } => {
                Self::Authorization(AuthorizationError::ResourceNotFound)
            }
            CommonError::Internal { message } => Self::Internal { message },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            CoreError::Authentication(AuthenticationError::InvalidCredentials).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            CoreError::Authorization(AuthorizationError::AccessDenied).status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            CoreError::Token(TokenError::NotFound).status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            CoreError::RateLimit(RateLimitError::Exceeded).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn test_error_categories() {
        assert_eq!(
            CoreError::Authentication(AuthenticationError::InvalidCredentials).category(),
            "authentication"
        );
        assert_eq!(
            CoreError::Token(TokenError::Expired).category(),
            "token"
        );
        assert_eq!(
            CoreError::Security(SecurityError::PolicyViolation).category(),
            "security"
        );
    }

    #[test]
    fn test_retryable_errors() {
        assert!(CoreError::Network(NetworkError::ConnectionTimeout).is_retryable());
        assert!(CoreError::RateLimit(RateLimitError::Exceeded).is_retryable());
        assert!(!CoreError::Authentication(AuthenticationError::InvalidCredentials).is_retryable());
    }

    #[test]
    fn test_internal_error_creation() {
        let error = CoreError::internal("test message");
        assert_eq!(error.category(), "internal");
        assert_eq!(error.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}