//! Error types for the auth-core crate

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Result type alias for auth-core operations
pub type Result<T> = std::result::Result<T, AuthError>;

/// Main error type for auth-core
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid client credentials")]
    InvalidClient,

    #[error("Invalid grant type: {0}")]
    InvalidGrantType(String),

    #[error("Invalid scope: {0}")]
    InvalidScope(String),

    #[error("Token not found or expired")]
    InvalidToken,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Server configuration error: {0}")]
    Configuration(String),

    #[error("JSON serialization/deserialization error")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JWT error")]
    #[cfg(feature = "jwt")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            AuthError::InvalidClient => (
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed",
            ),
            AuthError::InvalidGrantType(ref _grant_type) => (
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "Grant type is not supported",
            ),
            AuthError::InvalidScope(ref _scope) => (
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "Scope is not valid",
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "The access token is invalid or expired",
            ),
            AuthError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_exceeded",
                "Too many requests, please slow down",
            ),
            AuthError::Configuration(ref _msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Server configuration error",
            ),
            AuthError::Json(_) => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid JSON in request body",
            ),
            AuthError::Io(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal I/O error",
            ),
            #[cfg(feature = "jwt")]
            AuthError::Jwt(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "JWT processing error",
            ),
            AuthError::Internal(ref _msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal server error",
            ),
        };

        let body = json!({
            "error": error_code,
            "error_description": message
        });

        (status, Json(body)).into_response()
    }
}
