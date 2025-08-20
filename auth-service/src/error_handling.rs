//! Security-focused error handling for the auth service
//! 
//! This module provides comprehensive error handling patterns that prioritize
//! security, prevent information leakage, and maintain system resilience.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::fmt;
use thiserror::Error;
use tracing::{error, warn};

/// Security-focused error types that prevent information leakage
#[derive(Error, Debug, Clone)]
pub enum SecurityError {
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Authorization denied")]
    AuthorizationDenied,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Invalid input provided")]
    InvalidInput,
    
    #[error("Cryptographic operation failed")]
    CryptographicFailure,
    
    #[error("Configuration error")]
    Configuration,
    
    #[error("Service temporarily unavailable")]
    ServiceUnavailable,
    
    #[error("Internal system error")]
    Internal,
    
    #[error("Request timeout")]
    Timeout,
    
    #[error("Resource not found")]
    NotFound,
    
    #[error("Conflict with existing resource")]
    Conflict,
    
    #[error("Request payload too large")]
    PayloadTooLarge,
}

impl SecurityError {
    /// Get the public-facing error message that's safe to expose
    pub fn public_message(&self) -> &'static str {
        match self {
            SecurityError::AuthenticationFailed => "Authentication failed",
            SecurityError::AuthorizationDenied => "Access denied",
            SecurityError::RateLimitExceeded => "Rate limit exceeded",
            SecurityError::InvalidInput => "Invalid request",
            SecurityError::CryptographicFailure => "Security operation failed",
            SecurityError::Configuration => "Service unavailable",
            SecurityError::ServiceUnavailable => "Service temporarily unavailable",
            SecurityError::Internal => "Internal error",
            SecurityError::Timeout => "Request timeout",
            SecurityError::NotFound => "Resource not found",
            SecurityError::Conflict => "Resource conflict",
            SecurityError::PayloadTooLarge => "Request payload too large",
        }
    }
    
    /// Check if this error should be logged for security monitoring
    pub fn should_log(&self) -> bool {
        matches!(self, 
            SecurityError::AuthenticationFailed |
            SecurityError::AuthorizationDenied |
            SecurityError::CryptographicFailure |
            SecurityError::Internal |
            SecurityError::Configuration
        )
    }
    
    /// Get the severity level for logging
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            SecurityError::Internal | SecurityError::CryptographicFailure => ErrorSeverity::High,
            SecurityError::AuthenticationFailed | SecurityError::AuthorizationDenied => ErrorSeverity::Medium,
            SecurityError::RateLimitExceeded | SecurityError::InvalidInput => ErrorSeverity::Low,
            _ => ErrorSeverity::Low,
        }
    }
    
    /// Get error code for monitoring and alerting
    pub fn error_code(&self) -> &'static str {
        match self {
            SecurityError::AuthenticationFailed => "AUTH_FAILED",
            SecurityError::AuthorizationDenied => "ACCESS_DENIED",
            SecurityError::RateLimitExceeded => "RATE_LIMITED",
            SecurityError::InvalidInput => "INVALID_INPUT",
            SecurityError::CryptographicFailure => "CRYPTO_FAILURE",
            SecurityError::Configuration => "CONFIG_ERROR",
            SecurityError::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            SecurityError::Internal => "INTERNAL_ERROR",
            SecurityError::Timeout => "TIMEOUT",
            SecurityError::NotFound => "NOT_FOUND",
            SecurityError::Conflict => "CONFLICT",
            SecurityError::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
        }
    }
    
    /// Check if the operation should be retried
    pub fn is_retryable(&self) -> bool {
        matches!(self, 
            SecurityError::ServiceUnavailable |
            SecurityError::Timeout |
            SecurityError::Internal
        )
    }
}

/// Error severity levels for logging and alerting
#[derive(Debug, Clone, Copy)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Low => write!(f, "LOW"),
            ErrorSeverity::Medium => write!(f, "MEDIUM"),
            ErrorSeverity::High => write!(f, "HIGH"),
            ErrorSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Custom result type for security operations
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Extensions for SecurityResult to add logging and sanitization
pub trait SecurityResultExt<T> {
    fn log_security_error(self) -> SecurityResult<T>;
    fn log_security_error_with_context(self, context: &str) -> SecurityResult<T>;
    fn sanitize_error(self) -> SecurityResult<T>;
    fn map_internal_error(self) -> SecurityResult<T>;
}

impl<T> SecurityResultExt<T> for SecurityResult<T> {
    fn log_security_error(self) -> SecurityResult<T> {
        if let Err(ref e) = self {
            if e.should_log() {
                match e.severity() {
                    ErrorSeverity::High | ErrorSeverity::Critical => {
                        error!(
                            target = "security_audit",
                            error_code = %e.error_code(),
                            severity = %e.severity(),
                            error = %e,
                            "High severity security error occurred"
                        );
                    }
                    ErrorSeverity::Medium => {
                        warn!(
                            target = "security_audit",
                            error_code = %e.error_code(),
                            severity = %e.severity(),
                            error = %e,
                            "Medium severity security error occurred"
                        );
                    }
                    ErrorSeverity::Low => {
                        tracing::info!(
                            target = "security_audit",
                            error_code = %e.error_code(),
                            severity = %e.severity(),
                            error = %e,
                            "Low severity security error occurred"
                        );
                    }
                }
            }
        }
        self
    }
    
    fn log_security_error_with_context(self, context: &str) -> SecurityResult<T> {
        if let Err(ref e) = self {
            if e.should_log() {
                error!(
                    target = "security_audit",
                    context = %context,
                    error_code = %e.error_code(),
                    severity = %e.severity(),
                    error = %e,
                    "Security error occurred with context"
                );
            }
        }
        self
    }
    
    fn sanitize_error(self) -> SecurityResult<T> {
        self.map_err(|e| {
            // Replace internal errors with generic ones to prevent information leakage
            match e {
                SecurityError::Internal | SecurityError::Configuration => SecurityError::Internal,
                other => other,
            }
        })
    }
    
    fn map_internal_error(self) -> SecurityResult<T> {
        self.map_err(|_| SecurityError::Internal)
    }
}

/// HTTP response implementation for SecurityError
impl IntoResponse for SecurityError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            SecurityError::AuthenticationFailed => (
                StatusCode::UNAUTHORIZED,
                self.error_code(),
                self.public_message(),
            ),
            SecurityError::AuthorizationDenied => (
                StatusCode::FORBIDDEN,
                self.error_code(),
                self.public_message(),
            ),
            SecurityError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                self.error_code(),
                self.public_message(),
            ),
            SecurityError::InvalidInput => (
                StatusCode::BAD_REQUEST,
                self.error_code(),
                self.public_message(),
            ),
            SecurityError::NotFound => (
                StatusCode::NOT_FOUND,
                self.error_code(),
                self.public_message(),
            ),
            SecurityError::Conflict => (
                StatusCode::CONFLICT,
                self.error_code(),
                self.public_message(),
            ),
            SecurityError::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                self.error_code(),
                self.public_message(),
            ),
            SecurityError::Timeout => (
                StatusCode::REQUEST_TIMEOUT,
                self.error_code(),
                self.public_message(),
            ),
            SecurityError::ServiceUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                self.error_code(),
                self.public_message(),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Internal server error",
            ),
        };

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": message,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "request_id": tracing::Span::current().id().map(|id| format!("{:?}", id)),
            }
        }));

        // Log the error response for monitoring
        tracing::info!(
            status_code = %status,
            error_code = %error_code,
            "Error response sent"
        );

        (status, body).into_response()
    }
}

/// Circuit breaker for external service calls
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    recovery_timeout: std::time::Duration,
    current_failures: std::sync::Arc<std::sync::atomic::AtomicU32>,
    last_failure_time: std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

#[derive(Debug, Clone, Copy)]
pub enum CircuitState {
    Closed = 0,
    Open = 1,
    HalfOpen = 2,
}

impl From<u8> for CircuitState {
    fn from(value: u8) -> Self {
        match value {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, recovery_timeout: std::time::Duration) -> Self {
        Self {
            failure_threshold,
            recovery_timeout,
            current_failures: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            last_failure_time: std::sync::Arc::new(std::sync::Mutex::new(None)),
            state: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(CircuitState::Closed as u8)),
        }
    }
    
    pub async fn call<F, T, E>(&self, operation: F) -> Result<T, SecurityError>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: Into<SecurityError>,
    {
        let current_state = self.get_state();
        
        match current_state {
            CircuitState::Open => {
                if self.should_attempt_reset() {
                    self.set_state(CircuitState::HalfOpen);
                } else {
                    return Err(SecurityError::ServiceUnavailable);
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited calls in half-open state
            }
            CircuitState::Closed => {
                // Normal operation
            }
        }
        
        match operation.await {
            Ok(result) => {
                self.on_success();
                Ok(result)
            }
            Err(e) => {
                self.on_failure();
                Err(e.into())
            }
        }
    }
    
    fn get_state(&self) -> CircuitState {
        self.state.load(std::sync::atomic::Ordering::Relaxed).into()
    }
    
    fn set_state(&self, new_state: CircuitState) {
        self.state.store(new_state as u8, std::sync::atomic::Ordering::Relaxed);
    }
    
    fn on_success(&self) {
        self.current_failures.store(0, std::sync::atomic::Ordering::Relaxed);
        if matches!(self.get_state(), CircuitState::HalfOpen) {
            self.set_state(CircuitState::Closed);
        }
    }
    
    fn on_failure(&self) {
        let failures = self.current_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        
        if failures >= self.failure_threshold {
            self.set_state(CircuitState::Open);
            *self.last_failure_time.lock().unwrap() = Some(std::time::Instant::now());
        }
    }
    
    fn should_attempt_reset(&self) -> bool {
        if let Some(last_failure) = *self.last_failure_time.lock().unwrap() {
            std::time::Instant::now().duration_since(last_failure) > self.recovery_timeout
        } else {
            false
        }
    }
}

/// Retry mechanism with exponential backoff
pub struct RetryPolicy {
    max_attempts: u32,
    base_delay: std::time::Duration,
    max_delay: std::time::Duration,
    jitter: bool,
}

impl RetryPolicy {
    pub fn new(max_attempts: u32, base_delay: std::time::Duration) -> Self {
        Self {
            max_attempts,
            base_delay,
            max_delay: std::time::Duration::from_secs(60),
            jitter: true,
        }
    }
    
    pub async fn execute<F, T, E>(&self, mut operation: F) -> SecurityResult<T>
    where
        F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
        E: Into<SecurityError>,
    {
        let mut attempt = 0;
        let mut last_error = SecurityError::Internal;
        
        while attempt < self.max_attempts {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    let error = e.into();
                    last_error = error.clone();
                    
                    // Don't retry non-retryable errors
                    if !error.is_retryable() {
                        return Err(error);
                    }
                    
                    attempt += 1;
                    
                    if attempt < self.max_attempts {
                        let delay = self.calculate_delay(attempt);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
        
        Err(last_error)
    }
    
    fn calculate_delay(&self, attempt: u32) -> std::time::Duration {
        let exponential_delay = self.base_delay * 2_u32.pow(attempt - 1);
        let delay = std::cmp::min(exponential_delay, self.max_delay);
        
        if self.jitter {
            let jitter_range = delay.as_millis() / 10; // 10% jitter
            let jitter = fastrand::u64(0..=jitter_range as u64);
            delay + std::time::Duration::from_millis(jitter)
        } else {
            delay
        }
    }
}

/// Timeout wrapper for operations
pub async fn with_timeout<F, T>(
    duration: std::time::Duration,
    operation: F,
) -> SecurityResult<T>
where
    F: std::future::Future<Output = SecurityResult<T>>,
{
    match tokio::time::timeout(duration, operation).await {
        Ok(result) => result,
        Err(_) => Err(SecurityError::Timeout),
    }
}

/// Validation helpers that return SecurityError
pub mod validation {
    use super::*;
    use validator::{Validate, ValidationErrors};
    
    pub fn validate_input<T: Validate>(input: &T) -> SecurityResult<()> {
        input.validate()
            .map_err(|e| {
                tracing::debug!(
                    target = "security_audit",
                    validation_errors = ?e,
                    "Input validation failed"
                );
                SecurityError::InvalidInput
            })
    }
    
    pub fn validate_string_length(s: &str, min: usize, max: usize) -> SecurityResult<()> {
        if s.len() < min || s.len() > max {
            Err(SecurityError::InvalidInput)
        } else {
            Ok(())
        }
    }
    
    pub fn validate_email(email: &str) -> SecurityResult<()> {
        if email.contains('@') && email.len() <= 254 {
            Ok(())
        } else {
            Err(SecurityError::InvalidInput)
        }
    }
    
    pub fn validate_url(url: &str) -> SecurityResult<()> {
        if url.starts_with("https://") || url.starts_with("http://") {
            Ok(())
        } else {
            Err(SecurityError::InvalidInput)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;
    
    #[test]
    fn test_security_error_public_message() {
        let error = SecurityError::AuthenticationFailed;
        assert_eq!(error.public_message(), "Authentication failed");
        
        let error = SecurityError::Internal;
        assert_eq!(error.public_message(), "Internal error");
    }
    
    #[test]
    fn test_security_error_should_log() {
        assert!(SecurityError::AuthenticationFailed.should_log());
        assert!(SecurityError::CryptographicFailure.should_log());
        assert!(!SecurityError::InvalidInput.should_log());
    }
    
    #[test]
    fn test_security_error_is_retryable() {
        assert!(SecurityError::ServiceUnavailable.is_retryable());
        assert!(SecurityError::Timeout.is_retryable());
        assert!(!SecurityError::AuthenticationFailed.is_retryable());
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_open_state() {
        let circuit_breaker = CircuitBreaker::new(2, Duration::from_secs(1));
        
        // Simulate failures to open the circuit
        for _ in 0..3 {
            let result = circuit_breaker.call(async { 
                Err::<(), SecurityError>(SecurityError::Internal) 
            }).await;
            assert!(result.is_err());
        }
        
        // Circuit should be open now
        assert!(matches!(circuit_breaker.get_state(), CircuitState::Open));
        
        // Subsequent calls should fail fast
        let result = circuit_breaker.call(async { 
            Ok::<(), SecurityError>(()) 
        }).await;
        assert_eq!(result.unwrap_err().error_code(), "SERVICE_UNAVAILABLE");
    }
    
    #[tokio::test]
    async fn test_retry_policy() {
        let retry_policy = RetryPolicy::new(3, Duration::from_millis(10));
        let mut call_count = 0;
        
        let result = retry_policy.execute(|| {
            call_count += 1;
            Box::pin(async move {
                if call_count < 3 {
                    Err(SecurityError::ServiceUnavailable)
                } else {
                    Ok("success")
                }
            })
        }).await;
        
        assert_eq!(result.unwrap(), "success");
        assert_eq!(call_count, 3);
    }
    
    #[tokio::test]
    async fn test_timeout_wrapper() {
        // Test successful operation within timeout
        let result = with_timeout(
            Duration::from_millis(100),
            async { Ok::<_, SecurityError>("success") }
        ).await;
        assert_eq!(result.unwrap(), "success");
        
        // Test operation that times out
        let result = with_timeout(
            Duration::from_millis(10),
            async { 
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok::<_, SecurityError>("success")
            }
        ).await;
        assert_eq!(result.unwrap_err().error_code(), "TIMEOUT");
    }
    
    #[test]
    fn test_validation_helpers() {
        use validation::*;
        
        assert!(validate_string_length("test", 1, 10).is_ok());
        assert!(validate_string_length("", 1, 10).is_err());
        assert!(validate_string_length("toolongstring", 1, 5).is_err());
        
        assert!(validate_email("test@example.com").is_ok());
        assert!(validate_email("invalid-email").is_err());
        
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("ftp://example.com").is_err());
    }
}