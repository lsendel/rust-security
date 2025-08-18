use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MfaError {
    // Storage errors
    #[error("Storage error: {0}")]
    Storage(#[from] crate::mfa::storage::MfaStorageError),

    // Cryptographic errors
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::mfa::crypto::CryptoError),

    // TOTP specific errors
    #[error("TOTP error: {0}")]
    Totp(#[from] crate::mfa::totp_enhanced::TotpError),

    // Rate limiting errors
    #[error("Rate limit error: {0}")]
    RateLimit(#[from] crate::mfa::rate_limiting::RateLimitError),

    // Replay protection errors
    #[error("Replay protection error: {0}")]
    ReplayProtection(#[from] crate::mfa::replay_protection::ReplayProtectionError),

    // Audit errors
    #[error("Audit error: {0}")]
    Audit(#[from] crate::mfa::audit::AuditError),

    // Validation errors
    #[error("Invalid input: {field}: {message}")]
    InvalidInput { field: String, message: String },

    #[error("Missing required field: {field}")]
    MissingField { field: String },

    #[error("Invalid format: {field}: {message}")]
    InvalidFormat { field: String, message: String },

    // Authentication errors
    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("User not found: {user_id}")]
    UserNotFound { user_id: String },

    #[error("MFA not enabled for user: {user_id}")]
    MfaNotEnabled { user_id: String },

    #[error("MFA already enabled for user: {user_id}")]
    MfaAlreadyEnabled { user_id: String },

    #[error("Invalid verification code")]
    InvalidCode,

    #[error("Verification code expired")]
    CodeExpired,

    #[error("Backup code not found")]
    BackupCodeNotFound,

    #[error("All backup codes have been used")]
    NoBackupCodesRemaining,

    // Rate limiting specific
    #[error("Rate limit exceeded: {limit_type}, retry after {retry_after_secs} seconds")]
    RateLimitExceeded {
        limit_type: String,
        retry_after_secs: u64,
        remaining_attempts: i64,
    },

    // Security errors
    #[error("Replay attack detected")]
    ReplayAttack,

    #[error("Suspicious activity detected: {reason}")]
    SuspiciousActivity { reason: String },

    #[error("Security policy violation: {policy}")]
    SecurityPolicyViolation { policy: String },

    // Configuration errors
    #[error("Configuration error: {message}")]
    Configuration { message: String },

    #[error("Feature not enabled: {feature}")]
    FeatureNotEnabled { feature: String },

    // Service errors
    #[error("Service unavailable: {service}")]
    ServiceUnavailable { service: String },

    #[error("External service error: {service}: {message}")]
    ExternalServiceError { service: String, message: String },

    #[error("Timeout error: {operation}")]
    Timeout { operation: String },

    // Generic errors
    #[error("Internal server error")]
    Internal,

    #[error("Bad request: {message}")]
    BadRequest { message: String },

    #[error("Forbidden: {message}")]
    Forbidden { message: String },

    #[error("Conflict: {message}")]
    Conflict { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaErrorResponse {
    pub error: ErrorDetails,
    pub request_id: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorDetails {
    pub code: String,
    pub message: String,
    pub category: ErrorCategory,
    pub retryable: bool,
    pub retry_after_secs: Option<u64>,
    pub details: HashMap<String, serde_json::Value>,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorCategory {
    Validation,
    Authentication,
    Authorization,
    RateLimit,
    Security,
    Configuration,
    Service,
    Internal,
}

impl MfaError {
    pub fn error_code(&self) -> &'static str {
        match self {
            MfaError::Storage(_) => "STORAGE_ERROR",
            MfaError::Crypto(_) => "CRYPTO_ERROR",
            MfaError::Totp(_) => "TOTP_ERROR",
            MfaError::RateLimit(_) => "RATE_LIMIT_ERROR",
            MfaError::ReplayProtection(_) => "REPLAY_PROTECTION_ERROR",
            MfaError::Audit(_) => "AUDIT_ERROR",
            MfaError::InvalidInput { .. } => "INVALID_INPUT",
            MfaError::MissingField { .. } => "MISSING_FIELD",
            MfaError::InvalidFormat { .. } => "INVALID_FORMAT",
            MfaError::AuthenticationFailed { .. } => "AUTHENTICATION_FAILED",
            MfaError::UserNotFound { .. } => "USER_NOT_FOUND",
            MfaError::MfaNotEnabled { .. } => "MFA_NOT_ENABLED",
            MfaError::MfaAlreadyEnabled { .. } => "MFA_ALREADY_ENABLED",
            MfaError::InvalidCode => "INVALID_CODE",
            MfaError::CodeExpired => "CODE_EXPIRED",
            MfaError::BackupCodeNotFound => "BACKUP_CODE_NOT_FOUND",
            MfaError::NoBackupCodesRemaining => "NO_BACKUP_CODES_REMAINING",
            MfaError::RateLimitExceeded { .. } => "RATE_LIMIT_EXCEEDED",
            MfaError::ReplayAttack => "REPLAY_ATTACK",
            MfaError::SuspiciousActivity { .. } => "SUSPICIOUS_ACTIVITY",
            MfaError::SecurityPolicyViolation { .. } => "SECURITY_POLICY_VIOLATION",
            MfaError::Configuration { .. } => "CONFIGURATION_ERROR",
            MfaError::FeatureNotEnabled { .. } => "FEATURE_NOT_ENABLED",
            MfaError::ServiceUnavailable { .. } => "SERVICE_UNAVAILABLE",
            MfaError::ExternalServiceError { .. } => "EXTERNAL_SERVICE_ERROR",
            MfaError::Timeout { .. } => "TIMEOUT",
            MfaError::Internal => "INTERNAL_ERROR",
            MfaError::BadRequest { .. } => "BAD_REQUEST",
            MfaError::Forbidden { .. } => "FORBIDDEN",
            MfaError::Conflict { .. } => "CONFLICT",
        }
    }

    pub fn category(&self) -> ErrorCategory {
        match self {
            MfaError::InvalidInput { .. }
            | MfaError::MissingField { .. }
            | MfaError::InvalidFormat { .. }
            | MfaError::BadRequest { .. } => ErrorCategory::Validation,

            MfaError::AuthenticationFailed { .. }
            | MfaError::InvalidCode
            | MfaError::CodeExpired
            | MfaError::BackupCodeNotFound => ErrorCategory::Authentication,

            MfaError::UserNotFound { .. }
            | MfaError::MfaNotEnabled { .. }
            | MfaError::Forbidden { .. } => ErrorCategory::Authorization,

            MfaError::RateLimit(_) | MfaError::RateLimitExceeded { .. } => ErrorCategory::RateLimit,

            MfaError::ReplayAttack
            | MfaError::SuspiciousActivity { .. }
            | MfaError::SecurityPolicyViolation { .. } => ErrorCategory::Security,

            MfaError::Configuration { .. } | MfaError::FeatureNotEnabled { .. } => {
                ErrorCategory::Configuration
            }

            MfaError::ServiceUnavailable { .. }
            | MfaError::ExternalServiceError { .. }
            | MfaError::Timeout { .. } => ErrorCategory::Service,

            _ => ErrorCategory::Internal,
        }
    }

    pub fn http_status_code(&self) -> StatusCode {
        match self {
            MfaError::InvalidInput { .. }
            | MfaError::MissingField { .. }
            | MfaError::InvalidFormat { .. }
            | MfaError::BadRequest { .. }
            | MfaError::InvalidCode
            | MfaError::CodeExpired => StatusCode::BAD_REQUEST,

            MfaError::AuthenticationFailed { .. } => StatusCode::UNAUTHORIZED,

            MfaError::UserNotFound { .. }
            | MfaError::MfaNotEnabled { .. }
            | MfaError::Forbidden { .. } => StatusCode::FORBIDDEN,

            MfaError::MfaAlreadyEnabled { .. } | MfaError::Conflict { .. } => StatusCode::CONFLICT,

            MfaError::RateLimit(_) | MfaError::RateLimitExceeded { .. } => {
                StatusCode::TOO_MANY_REQUESTS
            }

            MfaError::ReplayAttack | MfaError::SuspiciousActivity { .. } => StatusCode::FORBIDDEN,

            MfaError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,

            MfaError::Timeout { .. } => StatusCode::REQUEST_TIMEOUT,

            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn is_retryable(&self) -> bool {
        match self {
            MfaError::ServiceUnavailable { .. }
            | MfaError::ExternalServiceError { .. }
            | MfaError::Timeout { .. }
            | MfaError::Storage(_)
            | MfaError::Internal => true,

            MfaError::RateLimitExceeded { .. } => true, // Retryable after waiting

            _ => false,
        }
    }

    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            MfaError::RateLimitExceeded {
                retry_after_secs, ..
            } => Some(*retry_after_secs),
            MfaError::ServiceUnavailable { .. } => Some(60), // Default retry after 1 minute
            MfaError::Timeout { .. } => Some(30),            // Retry after 30 seconds
            _ => None,
        }
    }

    pub fn suggestions(&self) -> Vec<String> {
        match self {
            MfaError::InvalidCode => vec![
                "Ensure you're using the current code from your authenticator app".to_string(),
                "Check that your device's time is synchronized".to_string(),
                "Try using a backup code if available".to_string(),
            ],
            MfaError::CodeExpired => vec![
                "Generate a new code from your authenticator app".to_string(),
                "Ensure your device's time is accurate".to_string(),
            ],
            MfaError::RateLimitExceeded { .. } => vec![
                "Wait before attempting again".to_string(),
                "Use a backup code if available".to_string(),
                "Contact support if you're having persistent issues".to_string(),
            ],
            MfaError::BackupCodeNotFound => vec![
                "Ensure you're entering the backup code correctly".to_string(),
                "Try using your authenticator app instead".to_string(),
                "Contact support to regenerate backup codes".to_string(),
            ],
            MfaError::NoBackupCodesRemaining => vec![
                "Generate new backup codes from your security settings".to_string(),
                "Use your authenticator app for verification".to_string(),
            ],
            MfaError::MfaNotEnabled { .. } => vec![
                "Enable MFA in your security settings".to_string(),
                "Contact your administrator if MFA should be enabled".to_string(),
            ],
            _ => vec![],
        }
    }

    pub fn additional_details(&self) -> HashMap<String, serde_json::Value> {
        let mut details = HashMap::new();

        match self {
            MfaError::InvalidInput { field, .. } => {
                details.insert("field".to_string(), serde_json::Value::String(field.clone()));
            }
            MfaError::RateLimitExceeded {
                limit_type,
                remaining_attempts,
                ..
            } => {
                details.insert(
                    "limit_type".to_string(),
                    serde_json::Value::String(limit_type.clone()),
                );
                details.insert(
                    "remaining_attempts".to_string(),
                    serde_json::Value::Number((*remaining_attempts).into()),
                );
            }
            MfaError::UserNotFound { user_id } => {
                details.insert(
                    "user_id".to_string(),
                    serde_json::Value::String(user_id.clone()),
                );
            }
            MfaError::ServiceUnavailable { service } => {
                details.insert(
                    "service".to_string(),
                    serde_json::Value::String(service.clone()),
                );
            }
            _ => {}
        }

        details
    }
}

impl IntoResponse for MfaError {
    fn into_response(self) -> Response {
        let status = self.http_status_code();
        let request_id = uuid::Uuid::new_v4().to_string();

        let error_response = MfaErrorResponse {
            error: ErrorDetails {
                code: self.error_code().to_string(),
                message: self.to_string(),
                category: self.category(),
                retryable: self.is_retryable(),
                retry_after_secs: self.retry_after_secs(),
                details: self.additional_details(),
                suggestions: self.suggestions(),
            },
            request_id: Some(request_id),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Log the error for debugging
        tracing::error!(
            target: "mfa_error",
            error_code = %error_response.error.code,
            category = ?error_response.error.category,
            retryable = %error_response.error.retryable,
            request_id = %error_response.request_id.as_ref().unwrap(),
            "MFA error occurred: {}",
            error_response.error.message
        );

        let mut response = Json(error_response).into_response();
        *response.status_mut() = status;

        // Add retry-after header for rate limiting
        if let Some(retry_after) = self.retry_after_secs() {
            response.headers_mut().insert(
                "Retry-After",
                retry_after.to_string().parse().unwrap(),
            );
        }

        response
    }
}

// Helper functions for creating common errors
impl MfaError {
    pub fn invalid_input(field: &str, message: &str) -> Self {
        MfaError::InvalidInput {
            field: field.to_string(),
            message: message.to_string(),
        }
    }

    pub fn missing_field(field: &str) -> Self {
        MfaError::MissingField {
            field: field.to_string(),
        }
    }

    pub fn user_not_found(user_id: &str) -> Self {
        MfaError::UserNotFound {
            user_id: user_id.to_string(),
        }
    }

    pub fn authentication_failed(reason: &str) -> Self {
        MfaError::AuthenticationFailed {
            reason: reason.to_string(),
        }
    }

    pub fn rate_limit_exceeded(limit_type: &str, retry_after_secs: u64, remaining: i64) -> Self {
        MfaError::RateLimitExceeded {
            limit_type: limit_type.to_string(),
            retry_after_secs,
            remaining_attempts: remaining,
        }
    }

    pub fn suspicious_activity(reason: &str) -> Self {
        MfaError::SuspiciousActivity {
            reason: reason.to_string(),
        }
    }

    pub fn service_unavailable(service: &str) -> Self {
        MfaError::ServiceUnavailable {
            service: service.to_string(),
        }
    }

    pub fn configuration_error(message: &str) -> Self {
        MfaError::Configuration {
            message: message.to_string(),
        }
    }
}

// Result type alias for MFA operations
pub type MfaResult<T> = Result<T, MfaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categorization() {
        let validation_error = MfaError::invalid_input("code", "must be 6 digits");
        assert!(matches!(validation_error.category(), ErrorCategory::Validation));
        assert_eq!(validation_error.http_status_code(), StatusCode::BAD_REQUEST);
        assert!(!validation_error.is_retryable());

        let rate_limit_error = MfaError::rate_limit_exceeded("verification", 60, 0);
        assert!(matches!(rate_limit_error.category(), ErrorCategory::RateLimit));
        assert_eq!(rate_limit_error.http_status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert!(rate_limit_error.is_retryable());
        assert_eq!(rate_limit_error.retry_after_secs(), Some(60));
    }

    #[test]
    fn test_error_suggestions() {
        let invalid_code_error = MfaError::InvalidCode;
        let suggestions = invalid_code_error.suggestions();
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.contains("authenticator app")));

        let rate_limit_error = MfaError::rate_limit_exceeded("verification", 60, 0);
        let suggestions = rate_limit_error.suggestions();
        assert!(suggestions.iter().any(|s| s.contains("Wait before")));
    }

    #[test]
    fn test_error_details() {
        let user_error = MfaError::user_not_found("user123");
        let details = user_error.additional_details();
        assert_eq!(
            details.get("user_id"),
            Some(&serde_json::Value::String("user123".to_string()))
        );

        let rate_limit_error = MfaError::rate_limit_exceeded("verification", 60, 3);
        let details = rate_limit_error.additional_details();
        assert_eq!(
            details.get("limit_type"),
            Some(&serde_json::Value::String("verification".to_string()))
        );
        assert_eq!(
            details.get("remaining_attempts"),
            Some(&serde_json::Value::Number(3.into()))
        );
    }

    #[tokio::test]
    async fn test_into_response() {
        let error = MfaError::invalid_input("code", "must be numeric");
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // In a real test, you'd deserialize the response body and check the structure
    }
}