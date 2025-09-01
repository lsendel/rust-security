//! Shared Error Types
//!
//! Common error types used throughout the application.

use thiserror::Error;

/// Result type alias for application operations
pub type AppResult<T> = Result<T, AppError>;

/// Main application error type
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Authentication error: {0}")]
    Auth(#[from] crate::services::auth_service::AuthError),

    #[error("Repository error: {0}")]
    Repository(#[from] crate::domain::repositories::RepositoryError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Cryptographic error: {0}")]
    CryptographicError(String),

    #[error("Key generation error: {message}")]
    KeyGenerationError { message: String },

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Token store error: {operation} - {source}")]
    TokenStoreError {
        operation: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Unauthorized client: {0}")]
    UnauthorizedClient(String),

    #[error("Anomaly detected")]
    AnomalyDetected,

    #[error("Policy denied")]
    PolicyDenied,

    #[error("Approval required")]
    ApprovalRequired,

    #[error("Identity not found")]
    IdentityNotFound,

    #[error("Identity suspended")]
    IdentitySuspended,

    #[error("Forbidden: {reason}")]
    Forbidden { reason: String },

    #[error("Invalid request: {reason}")]
    InvalidRequest { reason: String },

    #[error("Service unavailable: {reason}")]
    ServiceUnavailable { reason: String },

    #[error("Circuit breaker open")]
    CircuitBreakerOpen,

    #[error("Timeout error")]
    TimeoutError,

    #[error("Validation error")]
    ValidationError,

    #[error("Internal error")]
    InternalError,

    #[error("Insufficient data for baseline")]
    InsufficientDataForBaseline,

    #[error("External service error")]
    ExternalService,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("User inactive")]
    UserInactive,

    #[error("User not verified")]
    UserNotVerified,

    #[error("Crypto error")]
    Crypto,

    #[error("Session error")]
    Session,
}

impl AppError {
    /// Create an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Create a validation error
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    /// Create a not found error
    pub fn not_found(resource: impl Into<String>) -> Self {
        Self::NotFound(resource.into())
    }

    /// Create an unauthorized error
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    /// Create a bad request error
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> axum::http::StatusCode {
        match self {
            Self::Auth(_) => axum::http::StatusCode::UNAUTHORIZED,
            Self::NotFound(_) => axum::http::StatusCode::NOT_FOUND,
            Self::Unauthorized(_) => axum::http::StatusCode::UNAUTHORIZED,
            Self::UnauthorizedClient(_) => axum::http::StatusCode::UNAUTHORIZED,
            Self::BadRequest(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::InvalidRequest { .. } => axum::http::StatusCode::BAD_REQUEST,
            Self::Validation(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::RateLimitExceeded => axum::http::StatusCode::TOO_MANY_REQUESTS,
            Self::ServiceUnavailable { .. } => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Self::Repository(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::Config(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::ConfigurationError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::Internal(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::CryptographicError(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::TokenStoreError { .. } => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::KeyGenerationError { .. } => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidToken(_) => axum::http::StatusCode::UNAUTHORIZED,
            Self::AnomalyDetected => axum::http::StatusCode::TOO_MANY_REQUESTS,
            Self::PolicyDenied => axum::http::StatusCode::FORBIDDEN,
            Self::ApprovalRequired => axum::http::StatusCode::ACCEPTED,
            Self::IdentityNotFound => axum::http::StatusCode::NOT_FOUND,
            Self::IdentitySuspended => axum::http::StatusCode::FORBIDDEN,
            Self::Forbidden { .. } => axum::http::StatusCode::FORBIDDEN,
            Self::CircuitBreakerOpen => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Self::TimeoutError => axum::http::StatusCode::REQUEST_TIMEOUT,
            Self::ValidationError => axum::http::StatusCode::BAD_REQUEST,
            Self::InternalError => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::InsufficientDataForBaseline => axum::http::StatusCode::PRECONDITION_FAILED,
            Self::ExternalService => axum::http::StatusCode::BAD_GATEWAY,
            Self::InvalidCredentials => axum::http::StatusCode::UNAUTHORIZED,
            Self::UserNotFound => axum::http::StatusCode::NOT_FOUND,
            Self::UserInactive => axum::http::StatusCode::FORBIDDEN,
            Self::UserNotVerified => axum::http::StatusCode::FORBIDDEN,
            Self::Crypto => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::Session => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get a user-friendly error message
    pub fn user_message(&self) -> &str {
        match self {
            Self::Auth(_) => "Authentication failed",
            Self::NotFound(_) => "Resource not found",
            Self::Unauthorized(_) => "Unauthorized access",
            Self::UnauthorizedClient(_) => "Unauthorized client",
            Self::BadRequest(_) => "Invalid request",
            Self::InvalidRequest { .. } => "Invalid request",
            Self::Validation(_) => "Validation failed",
            Self::RateLimitExceeded => "Rate limit exceeded",
            Self::ServiceUnavailable { .. } => "Service temporarily unavailable",
            Self::Repository(_) => "Service temporarily unavailable",
            Self::Config(_) => "Service configuration error",
            Self::ConfigurationError(_) => "Service configuration error",
            Self::Internal(_) => "Internal server error",
            Self::CryptographicError(_) => "Cryptographic operation failed",
            Self::TokenStoreError { .. } => "Token storage operation failed",
            Self::KeyGenerationError { .. } => "Key generation failed",
            Self::InvalidToken(_) => "Invalid token provided",
            Self::AnomalyDetected => "Anomalous behavior detected",
            Self::PolicyDenied => "Policy denied access",
            Self::ApprovalRequired => "Approval required",
            Self::IdentityNotFound => "Identity not found",
            Self::IdentitySuspended => "Identity suspended",
            Self::Forbidden { .. } => "Access forbidden",
            Self::CircuitBreakerOpen => "Service temporarily unavailable",
            Self::TimeoutError => "Request timeout",
            Self::ValidationError => "Validation failed",
            Self::InternalError => "Internal server error",
            Self::InsufficientDataForBaseline => "Insufficient data for baseline",
            Self::ExternalService => "External service error",
            Self::InvalidCredentials => "Invalid credentials",
            Self::UserNotFound => "User not found",
            Self::UserInactive => "User account inactive",
            Self::UserNotVerified => "User account not verified",
            Self::Crypto => "Cryptographic operation failed",
            Self::Session => "Session error",
        }
    }
}

/// Convert AppError to axum response
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status_code();
        let body = serde_json::json!({
            "error": {
                "code": status.as_u16(),
                "message": self.user_message(),
                "details": self.to_string(),
            }
        });

        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            AppError::not_found("user").status_code(),
            axum::http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::unauthorized("access").status_code(),
            axum::http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::bad_request("input").status_code(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn test_error_user_messages() {
        assert_eq!(
            AppError::not_found("user").user_message(),
            "Resource not found"
        );
        assert_eq!(
            AppError::unauthorized("access").user_message(),
            "Unauthorized access"
        );
        assert_eq!(
            AppError::bad_request("input").user_message(),
            "Invalid request"
        );
    }
}
