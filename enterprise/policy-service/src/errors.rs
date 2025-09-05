//! Error handling for MVP policy service

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Main application error type for MVP
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Authorization error: {0}")]
    Authorization(#[from] AuthorizationError),
    
    #[error("Policy error: {0}")]
    Policy(#[from] Box<PolicyError>),
    
    #[error("IO error: {reason}: {source}")]
    Io { reason: String, source: std::io::Error },
}

/// Authorization-specific errors
#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("Invalid action: {action}")]
    InvalidAction { action: String },
    
    #[error("Invalid principal: {details}")]
    InvalidPrincipal { details: String },
    
    #[error("Invalid resource: {details}")]
    InvalidResource { details: String },
    
    #[error("Invalid context: {reason}")]
    InvalidContext { reason: String },
    
    #[error("Request failed: {reason}")]
    RequestFailed { reason: String },
}

/// Policy-specific errors
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy compilation failed")]
    CompilationFailed { 
        #[from]
        source: cedar_policy::ParseErrors 
    },
    
    #[error("Policy validation failed: {reason}")]
    ValidationFailed { reason: String },
}

impl AppError {
    /// Create IO error with context
    pub fn io(reason: &str, source: std::io::Error) -> Self {
        Self::Io {
            reason: reason.to_string(),
            source,
        }
    }
}

/// Convert AppError to HTTP response for MVP
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Authorization(auth_err) => match auth_err {
                AuthorizationError::InvalidAction { .. } 
                | AuthorizationError::InvalidPrincipal { .. }
                | AuthorizationError::InvalidResource { .. }
                | AuthorizationError::InvalidContext { .. } => {
                    (StatusCode::BAD_REQUEST, auth_err.to_string())
                }
                AuthorizationError::RequestFailed { .. } => {
                    (StatusCode::BAD_REQUEST, auth_err.to_string())
                }
            },
            AppError::Policy(policy_err) => {
                (StatusCode::INTERNAL_SERVER_ERROR, policy_err.to_string())
            }
            AppError::Io { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}

/// Convert AuthorizationError to HTTP response
impl IntoResponse for AuthorizationError {
    fn into_response(self) -> Response {
        AppError::Authorization(self).into_response()
    }
}