//! SOAR Case Management Error Types
//!
//! This module defines domain-specific error types for SOAR case management operations.


use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Result type alias for SOAR case management operations
pub type SoarResult<T> = Result<T, SoarError>;

/// Domain-specific error types for SOAR case management
#[derive(Debug, Error)]
pub enum SoarError {
    /// Case not found
    #[error("Case not found: {case_id}")]
    CaseNotFound { case_id: String },

    /// Case already exists
    #[error("Case already exists: {case_id}")]
    CaseAlreadyExists { case_id: String },

    /// Invalid case status transition
    #[error("Invalid status transition from {current_status} to {new_status}")]
    InvalidStatusTransition {
        current_status: String,
        new_status: String,
    },

    /// Workflow execution failed
    #[error("Workflow execution failed: {workflow_name}")]
    WorkflowExecutionFailed {
        workflow_name: String,
        reason: String,
    },

    /// SLA violation detected
    #[error("SLA violation for case {case_id}: {violation_type}")]
    SlaViolation {
        case_id: String,
        violation_type: String,
    },

    /// Evidence processing failed
    #[error("Evidence processing failed: {evidence_id}")]
    EvidenceProcessingFailed { evidence_id: String, reason: String },

    /// Configuration error
    #[error("Configuration error: {field}")]
    ConfigurationError { field: String, reason: String },

    /// Database operation failed
    #[error("Database operation failed: {operation}")]
    DatabaseError {
        operation: String,
        source: sqlx::Error,
    },

    /// Serialization/deserialization error
    #[error("Serialization error: {operation}")]
    SerializationError {
        operation: String,
        source: serde_json::Error,
    },

    /// Invalid input data
    #[error("Invalid input: {field} - {reason}")]
    InvalidInput { field: String, reason: String },

    /// Resource limit exceeded
    #[error("Resource limit exceeded: {resource}")]
    ResourceLimitExceeded { resource: String, limit: usize },

    /// Concurrent modification error
    #[error("Concurrent modification detected for case {case_id}")]
    ConcurrentModification { case_id: String },

    /// Permission denied
    #[error("Permission denied: {operation}")]
    PermissionDenied { operation: String },

    /// External service error
    #[error("External service error: {service}")]
    ExternalServiceError { service: String, reason: String },

    /// Template processing failed
    #[error("Template processing failed: {template_id}")]
    TemplateProcessingFailed { template_id: String, reason: String },

    /// Analytics computation failed
    #[error("Analytics computation failed: {operation}")]
    AnalyticsError { operation: String, reason: String },
}

impl SoarError {
    /// Create a new case not found error
    pub fn case_not_found(case_id: impl Into<String>) -> Self {
        Self::CaseNotFound {
            case_id: case_id.into(),
        }
    }

    /// Create a new invalid input error
    pub fn invalid_input(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidInput {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Create a new configuration error
    pub fn config_error(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ConfigurationError {
            field: field.into(),
            reason: reason.into(),
        }
    }

    /// Create a new database error
    pub fn database_error(operation: impl Into<String>, source: sqlx::Error) -> Self {
        Self::DatabaseError {
            operation: operation.into(),
            source,
        }
    }

    /// Create a new serialization error
    pub fn serialization_error(operation: impl Into<String>, source: serde_json::Error) -> Self {
        Self::SerializationError {
            operation: operation.into(),
            source,
        }
    }

    /// Get the error category for logging and monitoring
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::CaseNotFound { .. } | Self::CaseAlreadyExists { .. } => ErrorCategory::NotFound,
            Self::InvalidInput { .. } | Self::InvalidStatusTransition { .. } => {
                ErrorCategory::Validation
            }
            Self::ConfigurationError { .. } => ErrorCategory::Configuration,
            Self::DatabaseError { .. } | Self::SerializationError { .. } => {
                ErrorCategory::Infrastructure
            }
            Self::WorkflowExecutionFailed { .. }
            | Self::EvidenceProcessingFailed { .. }
            | Self::TemplateProcessingFailed { .. } => ErrorCategory::Processing,
            Self::SlaViolation { .. } => ErrorCategory::Sla,
            Self::PermissionDenied { .. } => ErrorCategory::Security,
            Self::ResourceLimitExceeded { .. } => ErrorCategory::Resource,
            Self::ConcurrentModification { .. } => ErrorCategory::Concurrency,
            Self::ExternalServiceError { .. } => ErrorCategory::External,
            Self::AnalyticsError { .. } => ErrorCategory::Analytics,
        }
    }

    /// Check if this is a retryable error
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::DatabaseError { source, .. } => {
                // Check if it's a transient database error
                matches!(
                    source,
                    sqlx::Error::PoolTimedOut
                        | sqlx::Error::PoolClosed
                        | sqlx::Error::Io(_)
                        | sqlx::Error::Tls(_)
                )
            }
            Self::ExternalServiceError { .. } => true,
            Self::ConcurrentModification { .. } => true,
            _ => false,
        }
    }

    /// Get the HTTP status code for this error
    pub fn http_status_code(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Self::CaseNotFound { .. } => StatusCode::NOT_FOUND,
            Self::CaseAlreadyExists { .. } => StatusCode::CONFLICT,
            Self::InvalidInput { .. } | Self::InvalidStatusTransition { .. } => {
                StatusCode::BAD_REQUEST
            }
            Self::PermissionDenied { .. } => StatusCode::FORBIDDEN,
            Self::ConfigurationError { .. } | Self::ResourceLimitExceeded { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::DatabaseError { .. }
            | Self::SerializationError { .. }
            | Self::WorkflowExecutionFailed { .. }
            | Self::EvidenceProcessingFailed { .. }
            | Self::TemplateProcessingFailed { .. }
            | Self::AnalyticsError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ConcurrentModification { .. } => StatusCode::CONFLICT,
            Self::ExternalServiceError { .. } => StatusCode::BAD_GATEWAY,
            Self::SlaViolation { .. } => StatusCode::ACCEPTED,
        }
    }
}

/// Error categories for monitoring and alerting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCategory {
    /// Resource not found
    NotFound,
    /// Input validation errors
    Validation,
    /// Configuration errors
    Configuration,
    /// Infrastructure errors (database, network, etc.)
    Infrastructure,
    /// Processing errors (workflows, evidence, templates)
    Processing,
    /// SLA violations
    Sla,
    /// Security/permission errors
    Security,
    /// Resource limit exceeded
    Resource,
    /// Concurrency conflicts
    Concurrency,
    /// External service errors
    External,
    /// Analytics computation errors
    Analytics,
}

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let category_str = match self {
            Self::NotFound => "not_found",
            Self::Validation => "validation",
            Self::Configuration => "configuration",
            Self::Infrastructure => "infrastructure",
            Self::Processing => "processing",
            Self::Sla => "sla",
            Self::Security => "security",
            Self::Resource => "resource",
            Self::Concurrency => "concurrency",
            Self::External => "external",
            Self::Analytics => "analytics",
        };
        write!(f, "{category_str}")
    }
}

/// Error context for enhanced error reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Unique error ID for tracking
    pub error_id: Uuid,
    /// Operation that failed
    pub operation: String,
    /// User ID if applicable
    pub user_id: Option<String>,
    /// Case ID if applicable
    pub case_id: Option<String>,
    /// Timestamp when error occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Additional context data
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self {
            error_id: Uuid::new_v4(),
            operation: String::new(),
            user_id: None,
            case_id: None,
            timestamp: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
        }
    }
}

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Error ID: {}, Operation: {}, Timestamp: {}",
            self.error_id, self.operation, self.timestamp
        )
    }
}

impl From<String> for SoarError {
    fn from(err: String) -> Self {
        Self::InvalidInput {
            field: "unknown".to_string(),
            reason: err,
        }
    }
}

impl From<&str> for SoarError {
    fn from(err: &str) -> Self {
        Self::InvalidInput {
            field: "unknown".to_string(),
            reason: err.to_string(),
        }
    }
}

impl ErrorContext {
    /// Create a new error context
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            ..Default::default()
        }
    }

    /// Add user ID to context
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Add case ID to context
    pub fn with_case_id(mut self, case_id: impl Into<String>) -> Self {
        self.case_id = Some(case_id.into());
        self
    }

    /// Add metadata to context
    pub fn with_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Enhanced error with context
#[derive(Debug, Error)]
#[error("{error}: {context}")]
pub struct ContextualError {
    /// The underlying error
    pub error: SoarError,
    /// Error context
    pub context: ErrorContext,
}

impl ContextualError {
    /// Create a new contextual error
    pub fn new(error: SoarError, context: ErrorContext) -> Self {
        Self { error, context }
    }

    /// Create a contextual error with operation
    pub fn with_operation(error: SoarError, operation: impl Into<String>) -> Self {
        Self::new(error, ErrorContext::new(operation))
    }
}

/// Error recovery strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    /// Retry the operation
    Retry {
        /// Maximum number of retries
        max_attempts: u32,
        /// Delay between retries in seconds
        delay_seconds: u64,
    },
    /// Fallback to alternative method
    Fallback {
        /// Alternative method to use
        method: String,
    },
    /// Degrade gracefully
    Degrade {
        /// Reduced functionality description
        description: String,
    },
    /// Manual intervention required
    Manual {
        /// Instructions for manual resolution
        instructions: String,
    },
}

/// Error recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRecoveryConfig {
    /// Recovery strategies by error category
    pub strategies: std::collections::HashMap<ErrorCategory, RecoveryStrategy>,
    /// Global retry configuration
    pub global_retry: RetryConfig,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Initial delay in seconds
    pub initial_delay_seconds: u64,
    /// Maximum delay in seconds
    pub max_delay_seconds: u64,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_seconds: 1,
            max_delay_seconds: 60,
            backoff_multiplier: 2.0,
        }
    }
}

impl Default for ErrorRecoveryConfig {
    fn default() -> Self {
        let mut strategies = std::collections::HashMap::new();

        // Infrastructure errors should be retried
        strategies.insert(
            ErrorCategory::Infrastructure,
            RecoveryStrategy::Retry {
                max_attempts: 3,
                delay_seconds: 2,
            },
        );

        // External service errors should be retried with backoff
        strategies.insert(
            ErrorCategory::External,
            RecoveryStrategy::Retry {
                max_attempts: 5,
                delay_seconds: 5,
            },
        );

        // Concurrency errors should be retried with shorter delay
        strategies.insert(
            ErrorCategory::Concurrency,
            RecoveryStrategy::Retry {
                max_attempts: 3,
                delay_seconds: 1,
            },
        );

        Self {
            strategies,
            global_retry: RetryConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        let not_found = SoarError::case_not_found("test-case");
        assert_eq!(not_found.category(), ErrorCategory::NotFound);

        let invalid_input = SoarError::invalid_input("field", "reason");
        assert_eq!(invalid_input.category(), ErrorCategory::Validation);
    }

    #[test]
    fn test_retryable_errors() {
        let db_error = SoarError::database_error("test", sqlx::Error::PoolTimedOut);
        assert!(db_error.is_retryable());

        let not_found = SoarError::case_not_found("test");
        assert!(!not_found.is_retryable());
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::new("test_operation")
            .with_user_id("user123")
            .with_case_id("case456")
            .with_metadata("key", "value");

        assert_eq!(context.operation, "test_operation");
        assert_eq!(context.user_id, Some("user123".to_string()));
        assert_eq!(context.case_id, Some("case456".to_string()));
        assert_eq!(
            context.metadata.get("key"),
            Some(&serde_json::json!("value"))
        );
    }

    #[test]
    fn test_recovery_config() {
        let config = ErrorRecoveryConfig::default();
        assert!(config
            .strategies
            .contains_key(&ErrorCategory::Infrastructure));
        assert!(config.strategies.contains_key(&ErrorCategory::External));
    }
}
