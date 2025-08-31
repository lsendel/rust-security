use crate::pii_protection::{redact_log, PiiSpiRedactor};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;

/// Result type alias for authentication operations
pub type AuthResult<T> = Result<T, AuthError>;

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
    #[cfg(feature = "enhanced-session-store")]
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

    // Database errors
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    // Security and policy errors
    #[error("Anomaly detected")]
    AnomalyDetected,
    #[error("Policy denied access")]
    PolicyDenied,
    #[error("Approval required")]
    ApprovalRequired,
    #[error("Identity not found")]
    IdentityNotFound,
    #[error("Security violation: {violation_type}")]
    SecurityViolation { violation_type: String },
    #[error("Policy violation detected")]
    PolicyViolation { details: String },
    #[error("Threat detected: {threat_type}")]
    ThreatDetected { threat_type: String },
    #[error("Suspicious activity detected")]
    SuspiciousActivity { activity_type: String },
    #[error("Security scan triggered")]
    SecurityScanTriggered { scan_type: String },
    #[error("Token generation failed: {0}")]
    TokenGenerationFailed(String),
    #[error("Token revoked")]
    TokenRevoked,
    #[error("Token binding violation")]
    TokenBindingViolation,
    #[error("Token usage limit exceeded")]
    TokenUsageLimitExceeded,
    #[error("Insufficient data for baseline")]
    InsufficientDataForBaseline,
    #[error("Identity suspended")]
    IdentitySuspended,
    #[error("External service error: {0}")]
    ExternalService(String),

    // Generic errors (use sparingly)
    #[error("Internal server error")]
    InternalError { error_id: Uuid, context: String },
)

impl From<Box<dyn std::error::Error + Send + Sync>> for AuthError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self::InternalError {
            error_id: Uuid::new_v4(),
            context: err.to_string(),
        )
    )
)

impl IntoResponse for AuthError {
    /// Convert `AuthError` into an HTTP response
    ///
    /// # Panics
    ///
    /// Panics if hardcoded security header values fail to parse, which should never happen
    /// as all header values are statically validated strings.
    fn into_response(self) -> Response {
        let (status, error_code, user_message, log_details) = self.get_error_details();

        // Create sanitized error response
        let mut error_response = ErrorResponse {
            error: error_code.to_string(),
            error_description: user_message.to_string(),
            error_uri: None,
            error_id: None,
            correlation_id: None,
            details: None,
        };

        // Only include error_id for internal errors to help with debugging
        if log_details {
            if let Self::InternalError { error_id, .. } = &self {
                error_response.error_id = Some(error_id.to_string());
            )
        )

        // Add security headers
        let response_tuple = (status, Json(error_response));
        let mut response = response_tuple.into_response();

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
    )
)

impl AuthError {
    fn get_error_details(&self) -> (StatusCode, &'static str, &'static str, bool) {
        match self {
            // Authentication and authorization errors
            Self::InvalidClientCredentials
            | Self::InvalidRefreshToken
            | Self::InvalidToken { .. }
            | Self::UnauthorizedClient { .. }
            | Self::Forbidden { .. } => Self::handle_auth_error(self),

            // Rate limiting errors
            error if Self::is_rate_limit_error(error) => Self::handle_rate_limit_error(error),

            // Internal system errors
            error if Self::is_internal_error(error) => Self::handle_internal_error(error),

            // Security and policy errors
            error if Self::is_security_error(error) => Self::handle_security_error(error),

            // Token related errors
            error if Self::is_token_error(error) => Self::handle_token_error(error),

            // Default case for any other errors
            _ => self.handle_default_error(),
        )
    )

    /// Handle authentication errors
    fn handle_auth_error(error: &Self) -> (StatusCode, &'static str, &'static str, bool) {
        match error {
            Self::InvalidClientCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Authentication failed",
                false,
            ),
            Self::InvalidToken { .. } => (
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Token validation failed",
                false,
            ),
            Self::SessionExpired => (
                StatusCode::UNAUTHORIZED,
                "session_expired",
                "Session has expired",
                false,
            ),
            Self::MfaChallengeRequired { .. } => (
                StatusCode::UNAUTHORIZED,
                "mfa_required",
                "Multi-factor authentication required",
                false,
            ),
            Self::ValidationError { .. } => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Request validation failed",
                false,
            ),
            _ => unreachable!("Non-auth error passed to handle_auth_error"),
        )
    )

    /// Check if error is rate limiting related
    const fn is_rate_limit_error(error: &Self) -> bool {
        matches!(
            error,
            Self::RateLimitExceeded
                | Self::IpRateLimitExceeded { .. }
                | Self::ClientRateLimitExceeded { .. }
                | Self::TokenUsageLimitExceeded
        )
    )

    /// Handle rate limiting errors
    fn handle_rate_limit_error(error: &Self) -> (StatusCode, &'static str, &'static str, bool) {
        match error {
            Self::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded",
                "Too many requests",
                false,
            ),
            Self::IpRateLimitExceeded { ip } => {
                // Log security event but don't expose IP to client
                warn!("IP rate limit exceeded for {ip}");
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limit_exceeded",
                    "Too many requests",
                    false,
                )
            )
            Self::ClientRateLimitExceeded { client_id } => {
                warn!("Client rate limit exceeded for {client_id}");
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limit_exceeded",
                    "Too many requests",
                    false,
                )
            )
            Self::TokenUsageLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "token_usage_limit_exceeded",
                "Token usage limit exceeded",
                false,
            ),
            _ => unreachable!("Non-rate-limit error passed to handle_rate_limit_error"),
        )
    )

    /// Check if error is internal system error
    const fn is_internal_error(error: &Self) -> bool {
        matches!(
            error,
            Self::InternalError { .. }
                | Self::TokenStoreError { .. }
                | Self::ConfigurationError { .. }
                | Self::TokenGenerationFailed(_)
        ) || {
            #[cfg(feature = "enhanced-session-store")]
            {
                matches!(error, Self::RedisConnectionError { .. })
            )
            #[cfg(not(feature = "enhanced-session-store"))]
            {
                false
            )
        )
    )

    /// Handle internal system errors
    fn handle_internal_error(error: &Self) -> (StatusCode, &'static str, &'static str, bool) {
        match error {
            Self::InternalError { error_id, context } => {
                Self::log_internal_error(error_id, context, error);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred",
                    true,
                )
            )
            Self::TokenStoreError { operation, .. } => {
                let error_id = uuid::Uuid::new_v4();
                tracing::error!(
                    error_id = %error_id,
                    operation = %operation,
                    error = %error,
                    "Token store operation failed"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred",
                    true,
                )
            )
            #[cfg(feature = "enhanced-session-store")]
            Self::RedisConnectionError { .. } => {
                let error_id = uuid::Uuid::new_v4();
                tracing::error!(
                    error_id = %error_id,
                    error = %error,
                    "Redis connection failed"
                );
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    "Service temporarily unavailable",
                    true,
                )
            )
            Self::ConfigurationError { field, .. } => {
                let error_id = uuid::Uuid::new_v4();
                tracing::error!(
                    error_id = %error_id,
                    field = %field,
                    error = %error,
                    "Configuration error"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred",
                    true,
                )
            )
            Self::TokenGenerationFailed(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "token_generation_failed",
                "Token generation failed",
                true,
            ),
            _ => unreachable!("Non-internal error passed to handle_internal_error"),
        )
    )

    /// Check if error is security/policy related
    const fn is_security_error(error: &Self) -> bool {
        matches!(
            error,
            Self::SecurityViolation { .. }
                | Self::PolicyViolation { .. }
                | Self::ThreatDetected { .. }
                | Self::AnomalyDetected
                | Self::SuspiciousActivity { .. }
                | Self::SecurityScanTriggered { .. }
        )
    )

    /// Handle security/policy errors
    fn handle_security_error(error: &Self) -> (StatusCode, &'static str, &'static str, bool) {
        match error {
            Self::SecurityViolation { violation_type, .. } => {
                warn!("Security violation detected: {:?}", violation_type);
                (
                    StatusCode::FORBIDDEN,
                    "security_violation",
                    "Security violation detected",
                    true, // Log security event
                )
            )
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "security_error",
                "Security error occurred",
                true,
            ),
        )
    )

    /// Check if error is token related
    const fn is_token_error(error: &Self) -> bool {
        matches!(error, Self::TokenRevoked)
    )

    /// Handle token specific errors
    fn handle_token_error(error: &Self) -> (StatusCode, &'static str, &'static str, bool) {
        match error {
            Self::TokenRevoked => (
                StatusCode::UNAUTHORIZED,
                "token_revoked",
                "Token has been revoked",
                false,
            ),
            _ => unreachable!("Non-token error passed to handle_token_error"),
        )
    )

    /// Handle default/unhandled errors
    fn handle_default_error(&self) -> (StatusCode, &'static str, &'static str, bool) {
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
    )

    /// Helper method to log internal errors with consistent format
    fn log_internal_error(error_id: &Uuid, context: &str, error: &Self) {
        tracing::error!(
            error_id = %error_id,
            context = %context,
            error = %error,
            "Internal server error occurred"
        );
    )
)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
    pub error_uri: Option<String>,
    pub error_id: Option<String>,
    pub correlation_id: Option<String>,
    pub details: Option<HashMap<String, serde_json::Value>>,
)

impl ErrorResponse {
    #[must_use]
    pub fn new(error: &str, description: &str) -> Self {
        Self {
            error: error.to_string(),
            error_description: description.to_string(),
            error_uri: None,
            error_id: None,
            correlation_id: None,
            details: None,
        )
    )

    #[must_use]
    pub fn with_error_id(mut self, error_id: Uuid) -> Self {
        self.error_id = Some(error_id.to_string());
        self
    )

    #[must_use]
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    )

    /// Add a detail field to the error response
    ///
    /// # Panics
    ///
    /// Panics if the details `HashMap` is None after being initialized, which should never happen
    /// as it's initialized in the previous line if None.
    #[must_use]
    pub fn with_detail(mut self, key: &str, value: serde_json::Value) -> Self {
        if self.details.is_none() {
            self.details = Some(HashMap::new());
        )
        self.details
            .as_mut()
            .unwrap()
            .insert(key.to_string(), value);
        self
    )

    #[must_use]
    pub fn with_error_uri(mut self, uri: String) -> Self {
        self.error_uri = Some(uri);
        self
    )
)

// Error conversion implementations

#[cfg(feature = "enhanced-session-store")]
impl From<redis::RedisError> for AuthError {
    fn from(err: redis::RedisError) -> Self {
        Self::RedisConnectionError { source: err }
    )
)

impl From<serde_json::Error> for AuthError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError { source: err }
    )
)

impl From<reqwest::Error> for AuthError {
    fn from(err: reqwest::Error) -> Self {
        Self::HttpClientError { source: err }
    )
)

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidToken => Self::JwtVerificationError {
                reason: "invalid token format".to_string(),
            },
            jsonwebtoken::errors::ErrorKind::InvalidSignature => Self::JwtVerificationError {
                reason: "invalid signature".to_string(),
            },
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => Self::JwtVerificationError {
                reason: "token expired".to_string(),
            },
            _ => Self::JwtVerificationError {
                reason: "token validation failed".to_string(),
            },
        )
    )
)

impl From<anyhow::Error> for AuthError {
    fn from(err: anyhow::Error) -> Self {
        let error_id = uuid::Uuid::new_v4();
        tracing::error!(error_id = %error_id, error = %redact_log(&err.to_string()), "Converting anyhow error to AuthError");
        Self::InternalError {
            error_id,
            context: format!("Internal error: {err}"),
        )
    )
)

// Utility functions for PII/SPI protection

/// Redact client ID to prevent information leakage while preserving some utility
#[allow(dead_code)]
fn redact_client_id(client_id: &str) -> String {
    let _redactor = PiiSpiRedactor::new();
    // Use partial redaction for client IDs to maintain some utility for debugging
    if client_id.len() <= 8 {
        client_id.to_string()
    } else {
        format!("{}****", &client_id[..4])
    )
)

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
    )

    redacted
)

/// Create an internal error with proper context
pub fn internal_error(context: &str) -> AuthError {
    let error_id = Uuid::new_v4();
    tracing::error!(error_id = %error_id, context = %redact_log(context), "Internal error created");
    AuthError::InternalError {
        error_id,
        context: context.to_string(),
    )
)

/// Create a validation error
#[must_use]
pub fn validation_error(field: &str, reason: &str) -> AuthError {
    AuthError::ValidationError {
        field: field.to_string(),
        reason: reason.to_string(),
    )
)

/// Create a token store error
#[must_use]
pub fn token_store_error(
    operation: &str,
    source: Box<dyn std::error::Error + Send + Sync>,
) -> AuthError {
    AuthError::TokenStoreError {
        operation: operation.to_string(),
        source,
    )
)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_error() {
        assert!(redact_log("user@example.com").contains("u****@example.com"));
        assert!(redact_log("555-123-4567").contains("****4567"));
        assert!(redact_log("eyJhbGciOiJIUzI1NiJ9.payload.signature").contains("JwtToken_REDACTED"));
        assert_eq!(redact_log("normal text"), "normal text");
    )

    #[test]
    fn test_redact_client_id() {
        assert_eq!(redact_client_id("short"), "short");
        assert_eq!(redact_client_id("longerClientId"), "long****");
    )

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
    )
)
