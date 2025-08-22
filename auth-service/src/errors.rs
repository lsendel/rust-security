use crate::pii_protection::{redact_log, PiiSpiRedactor};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

/// Comprehensive error type for the auth service
#[derive(Debug, Error)]
pub enum AuthError {
    // Authentication errors
    #[error("Missing client ID")]
    MissingClientId,
    #[error("Missing client secret")]
    MissingClientSecret,
    #[error("Invalid client credentials")]
    InvalidClientCredentials,
    #[error("Missing refresh token")]
    MissingRefreshToken,
    #[error("Invalid refresh token")]
    InvalidRefreshToken,
    #[error("Invalid scope: {scope}")]
    InvalidScope { scope: String },
    #[error("Invalid token: {reason}")]
    InvalidToken { reason: String },
    #[error("Unsupported grant type: {grant_type}")]
    UnsupportedGrantType { grant_type: String },
    #[error("Unsupported response type: {response_type}")]
    UnsupportedResponseType { response_type: String },
    #[error("Unauthorized client: {client_id}")]
    UnauthorizedClient { client_id: String },
    #[error("Invalid request: {reason}")]
    InvalidRequest { reason: String },
    #[error("Forbidden: {reason}")]
    Forbidden { reason: String },

    // Rate limiting errors
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Rate limit exceeded for IP: {ip}")]
    IpRateLimitExceeded { ip: String },
    #[error("Rate limit exceeded for client: {client_id}")]
    ClientRateLimitExceeded { client_id: String },

    // Storage/persistence errors
    #[error("Redis connection error")]
    RedisConnectionError { source: redis::RedisError },
    #[error("Token store error: {operation}")]
    TokenStoreError {
        operation: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("Serialization error")]
    SerializationError { source: serde_json::Error },

    // Atomic operation errors
    #[error("Transaction failed: {reason}")]
    TransactionFailed { reason: String },
    #[error("Concurrent modification detected")]
    ConcurrentModification,
    #[error("Token family revocation failed: {reason}")]
    TokenFamilyRevocationFailed { reason: String },
    #[error("Refresh token reuse detected")]
    RefreshTokenReuse,

    // Cryptographic errors
    #[error("Key generation failed")]
    KeyGenerationError {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("JWT signing failed")]
    JwtSigningError {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("JWT verification failed")]
    JwtVerificationError { reason: String },
    #[error("Cryptographic operation failed")]
    CryptographicError {
        operation: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    // Network/HTTP errors
    #[error("HTTP client error")]
    HttpClientError { source: reqwest::Error },
    #[error("Service unavailable: {reason}")]
    ServiceUnavailable { reason: String },
    #[error("Timeout error: {operation}")]
    TimeoutError { operation: String },
    #[error("Circuit breaker open for: {service}")]
    CircuitBreakerOpen { service: String },

    // Configuration errors
    #[error("Configuration error: {field}")]
    ConfigurationError { field: String, reason: String },
    #[error("Missing required environment variable: {variable}")]
    MissingEnvironmentVariable { variable: String },

    // Validation errors
    #[error("Input validation failed")]
    ValidationError { field: String, reason: String },
    #[error("SCIM filter validation failed")]
    ScimFilterError { filter: String, reason: String },
    #[error("Redirect URI validation failed")]
    RedirectUriError { uri: String, reason: String },

    // Session errors
    #[error("Session error: {reason}")]
    SessionError { reason: String },
    #[error("Session expired")]
    SessionExpired,
    #[error("Session not found")]
    SessionNotFound,
    #[error("{resource} not found")]
    NotFound { resource: String },

    // MFA errors
    #[error("MFA challenge required")]
    MfaChallengeRequired { challenge_id: String },
    #[error("MFA verification failed")]
    MfaVerificationFailed { reason: String },

    // OIDC/OAuth errors
    #[error("OIDC provider error: {provider}")]
    OidcProviderError { provider: String, reason: String },
    #[error("OAuth state mismatch")]
    OAuthStateMismatch,
    #[error("Authorization code expired")]
    AuthorizationCodeExpired,

    // Generic errors (use sparingly)
    #[error("Internal server error")]
    InternalError { error_id: Uuid, context: String },
}

impl From<Box<dyn std::error::Error + Send + Sync>> for AuthError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        AuthError::InternalError {
            error_id: Uuid::new_v4(),
            context: err.to_string(),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_code, user_message, log_details) = match &self {
            AuthError::InvalidClientCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Authentication failed",
                false,
            ),
            AuthError::InvalidToken { .. } => (
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Token validation failed",
                false,
            ),
            AuthError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded",
                "Too many requests",
                false,
            ),
            AuthError::IpRateLimitExceeded { ip } => {
                // Log security event but don't expose IP to client
                tracing::warn!(
                    ip = %ip,
                    "Rate limit exceeded for IP"
                );
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limit_exceeded",
                    "Too many requests",
                    false,
                )
            }
            AuthError::ValidationError { field, .. } => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Request validation failed",
                false,
            ),
            AuthError::SessionExpired => (
                StatusCode::UNAUTHORIZED,
                "session_expired",
                "Session has expired",
                false,
            ),
            AuthError::MfaChallengeRequired { .. } => (
                StatusCode::UNAUTHORIZED,
                "mfa_required",
                "Multi-factor authentication required",
                false,
            ),
            // Internal errors - don't leak details to client
            AuthError::InternalError { error_id, context } => {
                // Log full details internally with error ID for tracking
                tracing::error!(
                    error_id = %error_id,
                    context = %context,
                    error = %self,
                    "Internal server error occurred"
                );

                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred",
                    true,
                )
            }
            AuthError::TokenStoreError { operation, .. } => {
                let error_id = uuid::Uuid::new_v4();
                tracing::error!(
                    error_id = %error_id,
                    operation = %operation,
                    error = %self,
                    "Token store operation failed"
                );

                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred",
                    true,
                )
            }
            AuthError::RedisConnectionError { .. } => {
                let error_id = uuid::Uuid::new_v4();
                tracing::error!(
                    error_id = %error_id,
                    error = %self,
                    "Redis connection failed"
                );

                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    "Service temporarily unavailable",
                    true,
                )
            }
            AuthError::ConfigurationError { field, .. } => {
                let error_id = uuid::Uuid::new_v4();
                tracing::error!(
                    error_id = %error_id,
                    field = %field,
                    error = %self,
                    "Configuration error"
                );

                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred",
                    true,
                )
            }
            // Default case for any other errors
            _ => {
                let error_id = uuid::Uuid::new_v4();
                tracing::error!(
                    error_id = %error_id,
                    error = %self,
                    "Unhandled error occurred"
                );

                (
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Request could not be processed",
                    true,
                )
            }
        };

        // Create sanitized error response
        let mut error_response = ErrorResponse {
            error: error_code.to_string(),
            error_description: user_message.to_string(),
            error_id: None,
        };

        // Only include error_id for internal errors to help with debugging
        if log_details {
            if let AuthError::InternalError { error_id, .. } = &self {
                error_response.error_id = Some(*error_id);
            }
        }

        // Add security headers
        let mut response = (status, Json(error_response)).into_response();

        // Add security headers to error responses
        let headers = response.headers_mut();
        headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
        headers.insert("X-Frame-Options", "DENY".parse().unwrap());
        headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
        headers.insert(
            "Referrer-Policy",
            "strict-origin-when-cross-origin".parse().unwrap(),
        );

        response
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
    pub error_uri: Option<String>,
    pub error_id: Option<String>,
    pub correlation_id: Option<String>,
    pub details: Option<HashMap<String, serde_json::Value>>,
}

impl ErrorResponse {
    pub fn new(error: &str, description: &str) -> Self {
        Self {
            error: error.to_string(),
            error_description: description.to_string(),
            error_uri: None,
            error_id: None,
            correlation_id: None,
            details: None,
        }
    }

    pub fn with_error_id(mut self, error_id: Uuid) -> Self {
        self.error_id = Some(error_id.to_string());
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    pub fn with_detail(mut self, key: &str, value: serde_json::Value) -> Self {
        if self.details.is_none() {
            self.details = Some(HashMap::new());
        }
        self.details
            .as_mut()
            .unwrap()
            .insert(key.to_string(), value);
        self
    }

    pub fn with_error_uri(mut self, uri: String) -> Self {
        self.error_uri = Some(uri);
        self
    }
}

// Error conversion implementations

impl From<redis::RedisError> for AuthError {
    fn from(err: redis::RedisError) -> Self {
        AuthError::RedisConnectionError { source: err }
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(err: serde_json::Error) -> Self {
        AuthError::SerializationError { source: err }
    }
}

impl From<reqwest::Error> for AuthError {
    fn from(err: reqwest::Error) -> Self {
        AuthError::HttpClientError { source: err }
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidToken => AuthError::JwtVerificationError {
                reason: "invalid token format".to_string(),
            },
            jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::JwtVerificationError {
                reason: "invalid signature".to_string(),
            },
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::JwtVerificationError {
                reason: "token expired".to_string(),
            },
            _ => AuthError::JwtVerificationError {
                reason: "token validation failed".to_string(),
            },
        }
    }
}

impl From<anyhow::Error> for AuthError {
    fn from(err: anyhow::Error) -> Self {
        let error_id = uuid::Uuid::new_v4();
        tracing::error!(error_id = %error_id, error = %redact_log(&err.to_string()), "Converting anyhow error to AuthError");
        AuthError::InternalError {
            error_id,
            context: format!("Internal error: {}", err),
        }
    }
}

// Utility functions for PII/SPI protection

/// Redact client ID to prevent information leakage while preserving some utility
fn redact_client_id(client_id: &str) -> String {
    let _redactor = PiiSpiRedactor::new();
    // Use partial redaction for client IDs to maintain some utility for debugging
    if client_id.len() <= 8 {
        client_id.to_string()
    } else {
        format!("{}****", &client_id[..4])
    }
}

/// Enhanced PII/SPI redaction for error contexts
#[allow(dead_code)]
fn redact_error_with_context(input: &str, context: &str) -> String {
    let redactor = PiiSpiRedactor::new();
    let redacted = redactor.redact_error_message(input);

    // Log for audit purposes (without the sensitive data)
    if redacted != input {
        tracing::warn!(
            context = context,
            original_length = input.len(),
            redacted_length = redacted.len(),
            "Sensitive data redacted from error message"
        );
    }

    redacted
}

/// Create an internal error with proper context
pub fn internal_error(context: &str) -> AuthError {
    let error_id = Uuid::new_v4();
    tracing::error!(error_id = %error_id, context = %redact_log(context), "Internal error created");
    AuthError::InternalError {
        error_id,
        context: context.to_string(),
    }
}

/// Create a validation error
pub fn validation_error(field: &str, reason: &str) -> AuthError {
    AuthError::ValidationError {
        field: field.to_string(),
        reason: reason.to_string(),
    }
}

/// Create a token store error
pub fn token_store_error(
    operation: &str,
    source: Box<dyn std::error::Error + Send + Sync>,
) -> AuthError {
    AuthError::TokenStoreError {
        operation: operation.to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_error() {
        assert!(redact_error("user@example.com").contains("u****@example.com"));
        assert!(redact_error("555-123-4567").contains("****4567"));
        assert!(
            redact_error("eyJhbGciOiJIUzI1NiJ9.payload.signature").contains("JwtToken_REDACTED")
        );
        assert_eq!(redact_error("normal text"), "normal text");
    }

    #[test]
    fn test_redact_client_id() {
        assert_eq!(redact_client_id("short"), "short");
        assert_eq!(redact_client_id("longerClientId"), "long****");
    }

    #[test]
    fn test_error_response_building() {
        let error = ErrorResponse::new("test_error", "test description")
            .with_error_id(Uuid::new_v4())
            .with_correlation_id("corr-123".to_string())
            .with_detail("field", serde_json::Value::String("value".to_string()));

        assert_eq!(error.error, "test_error");
        assert_eq!(error.error_description, "test description");
        assert!(error.error_id.is_some());
        assert_eq!(error.correlation_id, Some("corr-123".to_string()));
        assert!(error.details.is_some());
    }
}
