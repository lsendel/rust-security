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
            Self::BadRequest(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::Validation(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::Repository(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::Config(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::Internal(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get a user-friendly error message
    pub fn user_message(&self) -> &str {
        match self {
            Self::Auth(_) => "Authentication failed",
            Self::NotFound(_) => "Resource not found",
            Self::Unauthorized(_) => "Unauthorized access",
            Self::BadRequest(_) => "Invalid request",
            Self::Validation(_) => "Validation failed",
            Self::Repository(_) => "Service temporarily unavailable",
            Self::Config(_) => "Service configuration error",
            Self::Internal(_) => "Internal server error",
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
