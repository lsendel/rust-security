//! Error types for API contracts and versioning

use thiserror::Error;
use serde::{Deserialize, Serialize};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use crate::{ApiVersion, types::{ApiResponse, ApiErrorDetail}};

/// Main API error type
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Versioning error: {0}")]
    Versioning(#[from] VersioningError),
    
    #[error("Contract error: {0}")]
    Contract(#[from] ContractError),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("Authorization error: {0}")]
    Authorization(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
    
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
    
    #[error("Bad request: {0}")]
    BadRequest(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
}

impl ApiError {
    /// Get HTTP status code for the error
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::Versioning(e) => e.status_code(),
            ApiError::Contract(e) => e.status_code(),
            ApiError::Authentication(_) => StatusCode::UNAUTHORIZED,
            ApiError::Authorization(_) => StatusCode::FORBIDDEN,
            ApiError::Validation(_) => StatusCode::BAD_REQUEST,
            ApiError::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
        }
    }
    
    /// Get error code for the error
    pub fn error_code(&self) -> String {
        match self {
            ApiError::Versioning(e) => e.error_code(),
            ApiError::Contract(e) => e.error_code(),
            ApiError::Authentication(_) => "AUTHENTICATION_ERROR".to_string(),
            ApiError::Authorization(_) => "AUTHORIZATION_ERROR".to_string(),
            ApiError::Validation(_) => "VALIDATION_ERROR".to_string(),
            ApiError::RateLimit(_) => "RATE_LIMIT_EXCEEDED".to_string(),
            ApiError::Internal(_) => "INTERNAL_SERVER_ERROR".to_string(),
            ApiError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE".to_string(),
            ApiError::BadRequest(_) => "BAD_REQUEST".to_string(),
            ApiError::NotFound(_) => "NOT_FOUND".to_string(),
            ApiError::Conflict(_) => "CONFLICT".to_string(),
        }
    }
    
    /// Convert to API error detail
    pub fn to_error_detail(&self) -> ApiErrorDetail {
        ApiErrorDetail::new(self.error_code(), self.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_detail = self.to_error_detail();
        let response = ApiResponse::<()>::error(error_detail);
        
        (status, Json(response)).into_response()
    }
}

/// API versioning errors
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum VersioningError {
    #[error("Invalid version format: {0}")]
    InvalidVersion(String),
    
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(ApiVersion),
    
    #[error("Version not found: {0}")]
    VersionNotFound(ApiVersion),
    
    #[error("Cannot deprecate current version: {0}")]
    CannotDeprecateCurrentVersion(ApiVersion),
    
    #[error("Version not deprecated: {0}")]
    VersionNotDeprecated(ApiVersion),
    
    #[error("Too early for sunset: {0}, sunset date: {1}")]
    TooEarlyForSunset(ApiVersion, DateTime<Utc>),
    
    #[error("Version configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Migration required from {0} to {1}")]
    MigrationRequired(ApiVersion, ApiVersion),
}

impl VersioningError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            VersioningError::InvalidVersion(_) => StatusCode::BAD_REQUEST,
            VersioningError::UnsupportedVersion(_) => StatusCode::BAD_REQUEST,
            VersioningError::VersionNotFound(_) => StatusCode::NOT_FOUND,
            VersioningError::CannotDeprecateCurrentVersion(_) => StatusCode::BAD_REQUEST,
            VersioningError::VersionNotDeprecated(_) => StatusCode::BAD_REQUEST,
            VersioningError::TooEarlyForSunset(_, _) => StatusCode::BAD_REQUEST,
            VersioningError::ConfigurationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            VersioningError::MigrationRequired(_, _) => StatusCode::BAD_REQUEST,
        }
    }
    
    pub fn error_code(&self) -> String {
        match self {
            VersioningError::InvalidVersion(_) => "INVALID_VERSION".to_string(),
            VersioningError::UnsupportedVersion(_) => "UNSUPPORTED_VERSION".to_string(),
            VersioningError::VersionNotFound(_) => "VERSION_NOT_FOUND".to_string(),
            VersioningError::CannotDeprecateCurrentVersion(_) => "CANNOT_DEPRECATE_CURRENT_VERSION".to_string(),
            VersioningError::VersionNotDeprecated(_) => "VERSION_NOT_DEPRECATED".to_string(),
            VersioningError::TooEarlyForSunset(_, _) => "TOO_EARLY_FOR_SUNSET".to_string(),
            VersioningError::ConfigurationError(_) => "VERSION_CONFIGURATION_ERROR".to_string(),
            VersioningError::MigrationRequired(_, _) => "MIGRATION_REQUIRED".to_string(),
        }
    }
}

/// Service contract errors
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum ContractError {
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
    
    #[error("Invalid trace context: {0}")]
    InvalidTraceContext(String),
    
    #[error("Contract violation: {0}")]
    ContractViolation(String),
    
    #[error("Communication error: {0}")]
    CommunicationError(String),
    
    #[error("Timeout error: {0}")]
    Timeout(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Authentication service error: {0}")]
    AuthenticationService(String),
    
    #[error("Policy service error: {0}")]
    PolicyService(String),
    
    #[error("Data validation error: {0}")]
    DataValidation(String),
}

impl ContractError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            ContractError::InvalidConfiguration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ContractError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ContractError::InvalidTraceContext(_) => StatusCode::BAD_REQUEST,
            ContractError::ContractViolation(_) => StatusCode::BAD_REQUEST,
            ContractError::CommunicationError(_) => StatusCode::SERVICE_UNAVAILABLE,
            ContractError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
            ContractError::Serialization(_) => StatusCode::BAD_REQUEST,
            ContractError::AuthenticationService(_) => StatusCode::SERVICE_UNAVAILABLE,
            ContractError::PolicyService(_) => StatusCode::SERVICE_UNAVAILABLE,
            ContractError::DataValidation(_) => StatusCode::BAD_REQUEST,
        }
    }
    
    pub fn error_code(&self) -> String {
        match self {
            ContractError::InvalidConfiguration(_) => "INVALID_CONFIGURATION".to_string(),
            ContractError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE".to_string(),
            ContractError::InvalidTraceContext(_) => "INVALID_TRACE_CONTEXT".to_string(),
            ContractError::ContractViolation(_) => "CONTRACT_VIOLATION".to_string(),
            ContractError::CommunicationError(_) => "COMMUNICATION_ERROR".to_string(),
            ContractError::Timeout(_) => "TIMEOUT_ERROR".to_string(),
            ContractError::Serialization(_) => "SERIALIZATION_ERROR".to_string(),
            ContractError::AuthenticationService(_) => "AUTH_SERVICE_ERROR".to_string(),
            ContractError::PolicyService(_) => "POLICY_SERVICE_ERROR".to_string(),
            ContractError::DataValidation(_) => "DATA_VALIDATION_ERROR".to_string(),
        }
    }
}

/// Validation error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationErrorDetail {
    pub field: String,
    pub code: String,
    pub message: String,
    pub value: Option<serde_json::Value>,
}

/// Rate limiting error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitErrorDetail {
    pub limit: u32,
    pub remaining: u32,
    pub reset_at: DateTime<Utc>,
    pub retry_after_seconds: u32,
}

/// Service error context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    pub service: String,
    pub operation: String,
    pub request_id: uuid::Uuid,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<uuid::Uuid>,
    pub additional_data: std::collections::HashMap<String, serde_json::Value>,
}

impl ErrorContext {
    pub fn new(service: String, operation: String) -> Self {
        Self {
            service,
            operation,
            request_id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            user_id: None,
            additional_data: std::collections::HashMap::new(),
        }
    }
    
    pub fn with_user(mut self, user_id: uuid::Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }
    
    pub fn with_data(mut self, key: String, value: serde_json::Value) -> Self {
        self.additional_data.insert(key, value);
        self
    }
}

/// Error builder for consistent error creation
pub struct ErrorBuilder {
    error_type: String,
    message: String,
    context: Option<ErrorContext>,
    details: Option<serde_json::Value>,
    help_url: Option<String>,
}

impl ErrorBuilder {
    pub fn new(error_type: String, message: String) -> Self {
        Self {
            error_type,
            message,
            context: None,
            details: None,
            help_url: None,
        }
    }
    
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = Some(context);
        self
    }
    
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
    
    pub fn with_help_url(mut self, help_url: String) -> Self {
        self.help_url = Some(help_url);
        self
    }
    
    pub fn build(self) -> ApiErrorDetail {
        let mut error_detail = ApiErrorDetail::new(self.error_type, self.message);
        
        if let Some(details) = self.details {
            error_detail = error_detail.with_details(details);
        }
        
        if let Some(help_url) = self.help_url {
            error_detail = error_detail.with_help_url(help_url);
        }
        
        error_detail
    }
}

/// Utility functions for error handling
pub mod utils {
    use super::*;
    use validator::ValidationErrors;
    
    /// Convert validation errors to API error
    pub fn validation_errors_to_api_error(errors: ValidationErrors) -> ApiError {
        let mut field_errors = std::collections::HashMap::new();
        
        for (field, field_errors_vec) in errors.field_errors() {
            let messages: Vec<String> = field_errors_vec
                .iter()
                .map(|e| e.message.as_ref().unwrap_or(&std::borrow::Cow::Borrowed("Validation failed")).to_string())
                .collect();
            field_errors.insert(field.to_string(), messages);
        }
        
        let error_detail = ApiErrorDetail::new(
            "VALIDATION_ERROR".to_string(),
            "Request validation failed".to_string(),
        ).with_field_errors(field_errors);
        
        ApiError::Validation(error_detail.message)
    }
    
    /// Convert serde JSON error to API error
    pub fn serde_error_to_api_error(error: serde_json::Error) -> ApiError {
        ApiError::BadRequest(format!("JSON parsing error: {}", error))
    }
    
    /// Convert reqwest error to contract error
    pub fn reqwest_error_to_contract_error(error: reqwest::Error) -> ContractError {
        if error.is_timeout() {
            ContractError::Timeout(error.to_string())
        } else if error.is_connect() {
            ContractError::CommunicationError(error.to_string())
        } else {
            ContractError::ServiceUnavailable(error.to_string())
        }
    }
    
    /// Create standard not found error
    pub fn not_found_error(resource: &str, id: &str) -> ApiError {
        ApiError::NotFound(format!("{} with id '{}' not found", resource, id))
    }
    
    /// Create standard conflict error
    pub fn conflict_error(resource: &str, reason: &str) -> ApiError {
        ApiError::Conflict(format!("{} conflict: {}", resource, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_error_status_codes() {
        assert_eq!(ApiError::Authentication("test".to_string()).status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(ApiError::Authorization("test".to_string()).status_code(), StatusCode::FORBIDDEN);
        assert_eq!(ApiError::Validation("test".to_string()).status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(ApiError::NotFound("test".to_string()).status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_versioning_error_codes() {
        let error = VersioningError::InvalidVersion("1.x.x".to_string());
        assert_eq!(error.error_code(), "INVALID_VERSION");
        assert_eq!(error.status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_contract_error_codes() {
        let error = ContractError::ServiceUnavailable("auth-service".to_string());
        assert_eq!(error.error_code(), "SERVICE_UNAVAILABLE");
        assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_error_builder() {
        let error = ErrorBuilder::new(
            "TEST_ERROR".to_string(),
            "Test error message".to_string(),
        )
        .with_details(serde_json::json!({"key": "value"}))
        .with_help_url("https://docs.example.com/errors/test-error".to_string())
        .build();
        
        assert_eq!(error.code, "TEST_ERROR");
        assert_eq!(error.message, "Test error message");
        assert!(error.details.is_some());
        assert!(error.help_url.is_some());
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::new("auth-service".to_string(), "authenticate".to_string())
            .with_user(uuid::Uuid::new_v4())
            .with_data("attempt".to_string(), serde_json::json!(3));
        
        assert_eq!(context.service, "auth-service");
        assert_eq!(context.operation, "authenticate");
        assert!(context.user_id.is_some());
        assert!(context.additional_data.contains_key("attempt"));
    }
}