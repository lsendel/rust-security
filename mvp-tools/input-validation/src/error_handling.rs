//! Error handling module for input validation framework
//!
//! Provides structured error types and results without information leakage

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

/// Security-focused error type that avoids information leakage
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    #[error("Input validation failed")]
    ValidationFailed,

    #[error("Input size limit exceeded")]
    SizeLimitExceeded,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Injection attempt detected")]
    InjectionAttempt,

    #[error("Malformed input")]
    MalformedInput,

    #[error("Unsupported operation")]
    UnsupportedOperation,

    #[error("Resource exhaustion detected")]
    ResourceExhaustion,

    #[error("Parser error")]
    ParserError,

    #[error("Configuration error")]
    ConfigurationError,

    #[error("Internal error")]
    InternalError,
}

/// Detailed validation error with field-specific information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationError {
    /// Field that failed validation
    pub field: String,

    /// Error code (never contains sensitive information)
    pub code: String,

    /// Human-readable message (sanitized)
    pub message: String,

    /// Optional context (sanitized)
    pub context: Option<String>,
}

impl ValidationError {
    /// Create a new validation error
    pub fn new(
        field: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self { field: field.into(), code: code.into(), message: message.into(), context: None }
    }

    /// Add context to the error
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Create a length validation error
    pub fn length(field: impl Into<String>, max_length: usize) -> Self {
        Self::new(field, "length_exceeded", format!("Maximum length {} exceeded", max_length))
    }

    /// Create a format validation error
    pub fn format(field: impl Into<String>, expected_format: impl Into<String>) -> Self {
        Self::new(field, "invalid_format", format!("Expected format: {}", expected_format.into()))
    }

    /// Create an injection attempt error
    pub fn injection(field: impl Into<String>) -> Self {
        Self::new(field, "injection_attempt", "Potentially malicious input detected")
    }

    /// Create a required field error
    pub fn required(field: impl Into<String>) -> Self {
        Self::new(field, "required", "Field is required")
    }

    /// Create a range validation error
    pub fn range(field: impl Into<String>, min: impl fmt::Display, max: impl fmt::Display) -> Self {
        Self::new(field, "out_of_range", format!("Value must be between {} and {}", min, max))
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} ({})", self.field, self.message, self.code)
    }
}

impl std::error::Error for ValidationError {}

/// Result type for validation operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether validation passed
    pub valid: bool,

    /// List of validation errors
    pub errors: Vec<ValidationError>,

    /// Validation metadata
    pub metadata: ValidationMetadata,
}

impl ValidationResult {
    /// Create a successful validation result
    pub fn success() -> Self {
        Self { valid: true, errors: Vec::new(), metadata: ValidationMetadata::default() }
    }

    /// Create a failed validation result with errors
    pub fn failure(errors: Vec<ValidationError>) -> Self {
        Self { valid: false, errors, metadata: ValidationMetadata::default() }
    }

    /// Create a failed validation result with a single error
    pub fn single_error(error: ValidationError) -> Self {
        Self::failure(vec![error])
    }

    /// Add an error to the result
    pub fn add_error(&mut self, error: ValidationError) {
        self.valid = false;
        self.errors.push(error);
    }

    /// Add multiple errors to the result
    pub fn add_errors(&mut self, mut errors: Vec<ValidationError>) {
        if !errors.is_empty() {
            self.valid = false;
            self.errors.append(&mut errors);
        }
    }

    /// Get errors grouped by field
    pub fn errors_by_field(&self) -> HashMap<String, Vec<&ValidationError>> {
        let mut grouped = HashMap::new();
        for error in &self.errors {
            grouped.entry(error.field.clone()).or_insert_with(Vec::new).push(error);
        }
        grouped
    }

    /// Check if validation passed
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Get the first error for a specific field
    pub fn first_error_for_field(&self, field: &str) -> Option<&ValidationError> {
        self.errors.iter().find(|e| e.field == field)
    }

    /// Convert to Result type
    pub fn into_result(self) -> Result<(), Vec<ValidationError>> {
        if self.valid {
            Ok(())
        } else {
            Err(self.errors)
        }
    }
}

/// Metadata about validation operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationMetadata {
    /// Number of rules applied
    pub rules_applied: u32,

    /// Validation duration in microseconds
    pub duration_micros: u64,

    /// Input size in bytes
    pub input_size: usize,

    /// Validation level (e.g., "strict", "normal", "relaxed")
    pub level: String,

    /// Custom metadata
    pub custom: HashMap<String, String>,
}

impl Default for ValidationMetadata {
    fn default() -> Self {
        Self {
            rules_applied: 0,
            duration_micros: 0,
            input_size: 0,
            level: "normal".to_string(),
            custom: HashMap::new(),
        }
    }
}

/// Security-focused result type that prevents information leakage
pub type SecureResult<T> = Result<T, SecurityError>;

/// Convert validation errors to security errors (sanitized)
impl From<ValidationResult> for SecurityError {
    fn from(result: ValidationResult) -> Self {
        if !result.valid {
            // Don't leak specific validation details in security errors
            SecurityError::ValidationFailed
        } else {
            SecurityError::InternalError
        }
    }
}

/// Error context for better error tracking without leakage
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// Operation being performed
    pub operation: String,

    /// Component that generated the error
    pub component: String,

    /// Request ID for correlation
    pub request_id: Option<String>,

    /// User ID (if available and safe to log)
    pub user_id: Option<String>,

    /// Additional safe context
    pub context: HashMap<String, String>,
}

impl ErrorContext {
    pub fn new(operation: impl Into<String>, component: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            component: component.into(),
            request_id: None,
            user_id: None,
            context: HashMap::new(),
        }
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }
}

/// Sanitize error messages to prevent information leakage
pub fn sanitize_error_message(message: &str) -> String {
    // Remove potentially sensitive patterns
    let patterns_to_remove = [
        // File paths
        r"(/[a-zA-Z0-9_\-./]*)",
        // IP addresses (partial masking)
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}",
        // Email domains (keep local part generic)
        r"@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        // Database connection strings
        r"(jdbc:|postgresql://|mysql://)[^\s]+",
        // API keys and tokens
        r"(key|token|secret)=[a-zA-Z0-9]+",
    ];

    let mut sanitized = message.to_string();

    for pattern in &patterns_to_remove {
        if let Ok(re) = fancy_regex::Regex::new(pattern) {
            sanitized = re.replace_all(&sanitized, "[REDACTED]").to_string();
        }
    }

    sanitized
}

/// Log validation errors securely
pub fn log_validation_error(error: &ValidationError, context: &ErrorContext) {
    tracing::warn!(
        operation = %context.operation,
        component = %context.component,
        request_id = ?context.request_id,
        field = %error.field,
        code = %error.code,
        message = %sanitize_error_message(&error.message),
        "Validation error occurred"
    );
}

/// Log security errors with minimal information leakage
pub fn log_security_error(error: &SecurityError, context: &ErrorContext) {
    tracing::error!(
        operation = %context.operation,
        component = %context.component,
        request_id = ?context.request_id,
        error_type = ?error,
        "Security error occurred"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_creation() {
        let error = ValidationError::new("username", "too_long", "Username is too long");
        assert_eq!(error.field, "username");
        assert_eq!(error.code, "too_long");
        assert_eq!(error.message, "Username is too long");
    }

    #[test]
    fn test_validation_result() {
        let mut result = ValidationResult::success();
        assert!(result.is_valid());

        result.add_error(ValidationError::required("email"));
        assert!(!result.is_valid());
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_error_sanitization() {
        let message = "Error in file /etc/passwd with IP 192.168.1.100 and key=secret123";
        let sanitized = sanitize_error_message(message);

        assert!(sanitized.contains("[REDACTED]"));
        assert!(!sanitized.contains("/etc/passwd"));
        assert!(!sanitized.contains("192.168.1.100"));
        assert!(!sanitized.contains("secret123"));
    }

    #[test]
    fn test_errors_by_field() {
        let mut result = ValidationResult::success();
        result.add_error(ValidationError::required("email"));
        result.add_error(ValidationError::length("email", 50));
        result.add_error(ValidationError::required("name"));

        let grouped = result.errors_by_field();
        assert_eq!(grouped.get("email").unwrap().len(), 2);
        assert_eq!(grouped.get("name").unwrap().len(), 1);
    }

    #[test]
    fn test_security_error_conversion() {
        let mut result = ValidationResult::success();
        result.add_error(ValidationError::required("field"));

        let security_error: SecurityError = result.into();
        assert_eq!(security_error, SecurityError::ValidationFailed);
    }
}
