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
    TokenStoreError { operation: String, source: Box<dyn std::error::Error + Send + Sync> },
    #[error("Serialization error")]
    SerializationError { source: serde_json::Error },

    // Cryptographic errors
    #[error("Key generation failed")]
    KeyGenerationError { source: Box<dyn std::error::Error + Send + Sync> },
    #[error("JWT signing failed")]
    JwtSigningError { source: Box<dyn std::error::Error + Send + Sync> },
    #[error("JWT verification failed")]
    JwtVerificationError { reason: String },
    #[error("Cryptographic operation failed")]
    CryptographicError { operation: String, source: Box<dyn std::error::Error + Send + Sync> },

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
    InternalError { 
        error_id: Uuid,
        context: String,
    },
}

/// Structured error response for API clients
#[derive(Debug, Serialize, Deserialize)]
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
        self.details.as_mut().unwrap().insert(key.to_string(), value);
        self
    }

    pub fn with_error_uri(mut self, uri: String) -> Self {
        self.error_uri = Some(uri);
        self
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_response) = match self {
            // Client errors (4xx)
            AuthError::MissingClientId => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_request", "missing client_id")
            ),
            AuthError::MissingClientSecret => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_request", "missing client_secret")
            ),
            AuthError::InvalidClientCredentials => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("invalid_client", "invalid client credentials")
            ),
            AuthError::MissingRefreshToken => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_request", "missing refresh_token")
            ),
            AuthError::InvalidRefreshToken => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("invalid_grant", "invalid refresh token")
            ),
            AuthError::InvalidScope { scope } => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_scope", &format!("invalid scope: {}", 
                    sanitize_user_input(&scope)))
            ),
            AuthError::InvalidToken { reason } => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("invalid_token", &sanitize_user_input(&reason))
            ),
            AuthError::UnsupportedGrantType { grant_type } => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("unsupported_grant_type", &format!("unsupported grant type: {}", 
                    sanitize_user_input(&grant_type)))
            ),
            AuthError::UnsupportedResponseType { response_type } => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("unsupported_response_type", &format!("unsupported response type: {}", 
                    sanitize_user_input(&response_type)))
            ),
            AuthError::UnauthorizedClient { client_id } => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("unauthorized_client", "unauthorized client")
                    .with_detail("client_id", serde_json::Value::String(sanitize_client_id(&client_id)))
            ),
            AuthError::InvalidRequest { reason } => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_request", &sanitize_user_input(&reason))
            ),
            AuthError::Forbidden { reason } => (
                StatusCode::FORBIDDEN,
                ErrorResponse::new("access_denied", &sanitize_user_input(&reason))
            ),
            AuthError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorResponse::new("rate_limit_exceeded", "rate limit exceeded")
            ),
            AuthError::IpRateLimitExceeded { ip: _ } => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorResponse::new("rate_limit_exceeded", "too many requests from this IP")
            ),
            AuthError::ClientRateLimitExceeded { client_id: _ } => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorResponse::new("rate_limit_exceeded", "too many requests from this client")
            ),
            AuthError::ValidationError { field, reason } => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_request", &format!("validation failed for field: {}", 
                    sanitize_user_input(&field)))
                    .with_detail("validation_error", serde_json::Value::String(sanitize_user_input(&reason)))
            ),
            AuthError::ScimFilterError { filter: _, reason } => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_filter", &sanitize_user_input(&reason))
            ),
            AuthError::RedirectUriError { uri: _, reason } => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_redirect_uri", &sanitize_user_input(&reason))
            ),
            AuthError::SessionExpired => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("session_expired", "session has expired")
            ),
            AuthError::SessionNotFound => (
                StatusCode::NOT_FOUND,
                ErrorResponse::new("session_not_found", "session not found")
            ),
            AuthError::SessionError { reason } => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("session_error", &sanitize_user_input(&reason))
            ),
            AuthError::MfaChallengeRequired { challenge_id } => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("mfa_required", "multi-factor authentication required")
                    .with_detail("challenge_id", serde_json::Value::String(challenge_id))
            ),
            AuthError::MfaVerificationFailed { reason } => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("mfa_failed", &sanitize_user_input(&reason))
            ),
            AuthError::OAuthStateMismatch => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_request", "OAuth state parameter mismatch")
            ),
            AuthError::AuthorizationCodeExpired => (
                StatusCode::BAD_REQUEST,
                ErrorResponse::new("invalid_grant", "authorization code has expired")
            ),

            // Server errors (5xx) - log but don't expose details
            AuthError::RedisConnectionError { source } => {
                let error_id = Uuid::new_v4();
                tracing::error!(error_id = %error_id, error = %source, "Redis connection error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new("internal_error", "temporary service unavailability")
                        .with_error_id(error_id)
                )
            },
            AuthError::TokenStoreError { operation, source } => {
                let error_id = Uuid::new_v4();
                tracing::error!(error_id = %error_id, operation = %operation, error = %source, "Token store error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new("internal_error", "temporary service unavailability")
                        .with_error_id(error_id)
                )
            },
            AuthError::SerializationError { source } => {
                let error_id = Uuid::new_v4();
                tracing::error!(error_id = %error_id, error = %source, "Serialization error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new("internal_error", "internal service error")
                        .with_error_id(error_id)
                )
            },
            AuthError::KeyGenerationError { source } => {
                let error_id = Uuid::new_v4();
                tracing::error!(error_id = %error_id, error = %source, "Key generation error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new("internal_error", "cryptographic service unavailable")
                        .with_error_id(error_id)
                )
            },
            AuthError::JwtSigningError { source } => {
                let error_id = Uuid::new_v4();
                tracing::error!(error_id = %error_id, error = %source, "JWT signing error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new("internal_error", "token service unavailable")
                        .with_error_id(error_id)
                )
            },
            AuthError::JwtVerificationError { reason } => (
                StatusCode::UNAUTHORIZED,
                ErrorResponse::new("invalid_token", &sanitize_user_input(&reason))
            ),
            AuthError::CryptographicError { operation, source } => {
                let error_id = Uuid::new_v4();
                tracing::error!(error_id = %error_id, operation = %operation, error = %source, "Cryptographic error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new("internal_error", "cryptographic service error")
                        .with_error_id(error_id)
                )
            },
            AuthError::HttpClientError { source } => {
                let error_id = Uuid::new_v4();
                tracing::error!(error_id = %error_id, error = %source, "HTTP client error");
                (
                    StatusCode::BAD_GATEWAY,
                    ErrorResponse::new("service_unavailable", "external service unavailable")
                        .with_error_id(error_id)
                )
            },
            AuthError::ServiceUnavailable { reason } => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorResponse::new("service_unavailable", &sanitize_user_input(&reason))
            ),
            AuthError::TimeoutError { operation } => {
                let error_id = Uuid::new_v4();
                tracing::warn!(error_id = %error_id, operation = %operation, "Operation timeout");
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    ErrorResponse::new("timeout", "operation timed out")
                        .with_error_id(error_id)
                )
            },
            AuthError::CircuitBreakerOpen { service } => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorResponse::new("service_unavailable", &format!("service temporarily unavailable: {}", 
                    sanitize_user_input(&service)))
            ),
            AuthError::ConfigurationError { field, reason } => {
                let error_id = Uuid::new_v4();
                tracing::error!(error_id = %error_id, field = %field, reason = %reason, "Configuration error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new("internal_error", "service configuration error")
                        .with_error_id(error_id)
                )
            },
            AuthError::MissingEnvironmentVariable { variable } => {
                let error_id = Uuid::new_v4();
                tracing::error!(error_id = %error_id, variable = %variable, "Missing environment variable");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new("internal_error", "service configuration error")
                        .with_error_id(error_id)
                )
            },
            AuthError::OidcProviderError { provider, reason } => {
                let error_id = Uuid::new_v4();
                tracing::error!(error_id = %error_id, provider = %provider, reason = %reason, "OIDC provider error");
                (
                    StatusCode::BAD_GATEWAY,
                    ErrorResponse::new("external_service_error", "authentication provider unavailable")
                        .with_error_id(error_id)
                )
            },
            AuthError::InternalError { error_id, context } => {
                tracing::error!(error_id = %error_id, context = %context, "Internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse::new("internal_error", "internal service error")
                        .with_error_id(error_id)
                )
            },
        };

        let mut response = Json(error_response).into_response();
        *response.status_mut() = status;
        response
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
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                AuthError::JwtVerificationError { reason: "invalid token format".to_string() }
            },
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                AuthError::JwtVerificationError { reason: "invalid signature".to_string() }
            },
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                AuthError::JwtVerificationError { reason: "token expired".to_string() }
            },
            _ => AuthError::JwtVerificationError { reason: "token validation failed".to_string() }
        }
    }
}

impl From<anyhow::Error> for AuthError {
    fn from(err: anyhow::Error) -> Self {
        let error_id = uuid::Uuid::new_v4();
        tracing::error!(error_id = %error_id, error = %err, "Converting anyhow error to AuthError");
        AuthError::InternalError {
            error_id,
            context: format!("Internal error: {}", err),
        }
    }
}

// Utility functions for PII sanitization

/// Sanitize user input to prevent sensitive information leakage
fn sanitize_user_input(input: &str) -> String {
    // Remove potential PII patterns
    let mut sanitized = input.to_string();
    
    // Email pattern
    let email_re = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
    sanitized = email_re.replace_all(&sanitized, "[EMAIL_REDACTED]").to_string();
    
    // Phone pattern (basic)
    let phone_re = regex::Regex::new(r"\b\d{3}-?\d{3}-?\d{4}\b").unwrap();
    sanitized = phone_re.replace_all(&sanitized, "[PHONE_REDACTED]").to_string();
    
    // Token-like patterns (32+ hex chars)
    let token_re = regex::Regex::new(r"\b[a-fA-F0-9]{32,}\b").unwrap();
    sanitized = token_re.replace_all(&sanitized, "[TOKEN_REDACTED]").to_string();
    
    // Limit length and escape for safety
    if sanitized.len() > 200 {
        sanitized = format!("{}...", &sanitized[..197]);
    }
    
    sanitized
}

/// Sanitize client ID to prevent information leakage while preserving some utility
fn sanitize_client_id(client_id: &str) -> String {
    if client_id.len() <= 8 {
        client_id.to_string()
    } else {
        format!("{}****", &client_id[..4])
    }
}

/// Create an internal error with proper context
pub fn internal_error(context: &str) -> AuthError {
    let error_id = Uuid::new_v4();
    tracing::error!(error_id = %error_id, context = %context, "Internal error created");
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
pub fn token_store_error(operation: &str, source: Box<dyn std::error::Error + Send + Sync>) -> AuthError {
    AuthError::TokenStoreError {
        operation: operation.to_string(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_user_input() {
        assert_eq!(sanitize_user_input("user@example.com"), "[EMAIL_REDACTED]");
        assert_eq!(sanitize_user_input("123-456-7890"), "[PHONE_REDACTED]");
        assert_eq!(sanitize_user_input("abcdef123456789012345678901234567890"), "[TOKEN_REDACTED]");
        assert_eq!(sanitize_user_input("normal text"), "normal text");
    }

    #[test]
    fn test_sanitize_client_id() {
        assert_eq!(sanitize_client_id("short"), "short");
        assert_eq!(sanitize_client_id("longerClientId"), "long****");
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