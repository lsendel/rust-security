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
    #[must_use]
    pub const fn public_message(&self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "Authentication failed",
            Self::AuthorizationDenied => "Access denied",
            Self::RateLimitExceeded => "Rate limit exceeded",
            Self::InvalidInput => "Invalid request",
            Self::CryptographicFailure => "Security operation failed",
            Self::Configuration => "Service unavailable",
            Self::ServiceUnavailable => "Service temporarily unavailable",
            Self::Internal => "Internal error",
            Self::Timeout => "Request timeout",
            Self::NotFound => "Resource not found",
            Self::Conflict => "Resource conflict",
            Self::PayloadTooLarge => "Request payload too large",
        }
    }

    /// Check if this error should be logged for security monitoring
    #[must_use]
    pub const fn should_log(&self) -> bool {
        matches!(
            self,
            Self::AuthenticationFailed
                | Self::AuthorizationDenied
                | Self::CryptographicFailure
                | Self::Internal
                | Self::Configuration
        )
    }

    /// Get the severity level for logging
    #[must_use]
    pub const fn severity(&self) -> ErrorSeverity {
        match self {
            Self::Internal | Self::CryptographicFailure => ErrorSeverity::High,
            Self::AuthenticationFailed | Self::AuthorizationDenied => ErrorSeverity::Medium,
            Self::RateLimitExceeded | Self::InvalidInput => ErrorSeverity::Low,
            _ => ErrorSeverity::Low,
        }
    }

    /// Get error code for monitoring and alerting
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "AUTH_FAILED",
            Self::AuthorizationDenied => "ACCESS_DENIED",
            Self::RateLimitExceeded => "RATE_LIMITED",
            Self::InvalidInput => "INVALID_INPUT",
            Self::CryptographicFailure => "CRYPTO_FAILURE",
            Self::Configuration => "CONFIG_ERROR",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            Self::Internal => "INTERNAL_ERROR",
            Self::Timeout => "TIMEOUT",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict => "CONFLICT",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
        }
    }

    /// Check if the operation should be retried
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ServiceUnavailable | Self::Timeout | Self::Internal
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
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Custom result type for security operations
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Extensions for `SecurityResult` to add logging and sanitization
pub trait SecurityResultExt<T> {
    fn log_security_error(self) -> SecurityResult<T>;
    fn log_security_error_with_context(self, context: &str) -> SecurityResult<T>;
    fn sanitize_error(self) -> SecurityResult<T>;
    fn map_internal_error(self) -> SecurityResult<T>;
}

impl<T> SecurityResultExt<T> for SecurityResult<T> {
    fn log_security_error(self) -> Self {
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

    fn log_security_error_with_context(self, context: &str) -> Self {
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

    fn sanitize_error(self) -> Self {
        self.map_err(|e| {
            // Replace internal errors with generic ones to prevent information leakage
            match e {
                SecurityError::Internal | SecurityError::Configuration => SecurityError::Internal,
                other => other,
            }
        })
    }

    fn map_internal_error(self) -> Self {
        self.map_err(|_| SecurityError::Internal)
    }
}

/// HTTP response implementation for `SecurityError`
impl IntoResponse for SecurityError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            Self::AuthenticationFailed => (
                StatusCode::UNAUTHORIZED,
                self.error_code(),
                self.public_message(),
            ),
            Self::AuthorizationDenied => (
                StatusCode::FORBIDDEN,
                self.error_code(),
                self.public_message(),
            ),
            Self::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                self.error_code(),
                self.public_message(),
            ),
            Self::InvalidInput => (
                StatusCode::BAD_REQUEST,
                self.error_code(),
                self.public_message(),
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                self.error_code(),
                self.public_message(),
            ),
            Self::Conflict => (
                StatusCode::CONFLICT,
                self.error_code(),
                self.public_message(),
            ),
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                self.error_code(),
                self.public_message(),
            ),
            Self::Timeout => (
                StatusCode::REQUEST_TIMEOUT,
                self.error_code(),
                self.public_message(),
            ),
            Self::ServiceUnavailable => (
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
                "request_id": tracing::Span::current().id().map(|id| format!("{id:?}")),
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
            0 => Self::Closed,
            1 => Self::Open,
            2 => Self::HalfOpen,
            _ => Self::Closed,
        }
    }
}

impl From<rustls::Error> for SecurityError {
    fn from(_error: rustls::Error) -> Self {
        Self::CryptographicFailure
    }
}

impl CircuitBreaker {
    #[must_use]
    pub fn new(failure_threshold: u32, recovery_timeout: std::time::Duration) -> Self {
        Self {
            failure_threshold,
            recovery_timeout,
            current_failures: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            last_failure_time: std::sync::Arc::new(std::sync::Mutex::new(None)),
            state: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
                CircuitState::Closed as u8,
            )),
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
        self.state
            .store(new_state as u8, std::sync::atomic::Ordering::Relaxed);
    }

    fn on_success(&self) {
        self.current_failures
            .store(0, std::sync::atomic::Ordering::Relaxed);
        if matches!(self.get_state(), CircuitState::HalfOpen) {
            self.set_state(CircuitState::Closed);
        }
    }

    fn on_failure(&self) {
        let failures = self
            .current_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;

        if failures >= self.failure_threshold {
            self.set_state(CircuitState::Open);
            if let Ok(mut guard) = self.last_failure_time.lock() {
                *guard = Some(std::time::Instant::now());
            }
        }
    }

    fn should_attempt_reset(&self) -> bool {
        match self.last_failure_time.lock() {
            Ok(guard) => match *guard {
                Some(last_failure) => {
                    std::time::Instant::now().duration_since(last_failure) > self.recovery_timeout
                }
                None => false,
            },
            Err(_) => false,
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
    #[must_use]
    pub const fn new(max_attempts: u32, base_delay: std::time::Duration) -> Self {
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
pub async fn with_timeout<F, T>(duration: std::time::Duration, operation: F) -> SecurityResult<T>
where
    F: std::future::Future<Output = SecurityResult<T>>,
{
    match tokio::time::timeout(duration, operation).await {
        Ok(result) => result,
        Err(_) => Err(SecurityError::Timeout),
    }
}

/// Validation helpers that return `SecurityError`
pub mod validation {
    use super::{SecurityError, SecurityResult};
    use validator::Validate;

    pub fn validate_input<T: Validate>(input: &T) -> SecurityResult<()> {
        input.validate().map_err(|e| {
            tracing::debug!(
                target = "security_audit",
                validation_errors = ?e,
                "Input validation failed"
            );
            SecurityError::InvalidInput
        })
    }

    pub const fn validate_string_length(s: &str, min: usize, max: usize) -> SecurityResult<()> {
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
            let result = circuit_breaker
                .call(async { Err::<(), SecurityError>(SecurityError::Internal) })
                .await;
            assert!(result.is_err());
        }

        // Circuit should be open now
        assert!(matches!(circuit_breaker.get_state(), CircuitState::Open));

        // Subsequent calls should fail fast
        let result = circuit_breaker
            .call(async { Ok::<(), SecurityError>(()) })
            .await;
        assert_eq!(result.unwrap_err().error_code(), "SERVICE_UNAVAILABLE");
    }

    #[tokio::test]
    async fn test_retry_policy() {
        let retry_policy = RetryPolicy::new(3, Duration::from_millis(10));
        let mut call_count = 0;

        let result = retry_policy
            .execute(|| {
                call_count += 1;
                Box::pin(async move {
                    if call_count < 3 {
                        Err(SecurityError::ServiceUnavailable)
                    } else {
                        Ok("success")
                    }
                })
            })
            .await;

        assert_eq!(result.unwrap(), "success");
        assert_eq!(call_count, 3);
    }

    #[tokio::test]
    async fn test_timeout_wrapper() {
        // Test successful operation within timeout
        let result = with_timeout(Duration::from_millis(100), async {
            Ok::<_, SecurityError>("success")
        })
        .await;
        assert_eq!(result.unwrap(), "success");

        // Test operation that times out
        let result = with_timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<_, SecurityError>("success")
        })
        .await;
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
        assert!(validate_email(&"a".repeat(255)).is_err()); // Too long

        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://example.com").is_ok());
        assert!(validate_url("ftp://example.com").is_err());
        assert!(validate_url("invalid-url").is_err());
    }

    #[test]
    fn test_security_error_severity() {
        assert!(matches!(
            SecurityError::Internal.severity(),
            ErrorSeverity::High
        ));
        assert!(matches!(
            SecurityError::CryptographicFailure.severity(),
            ErrorSeverity::High
        ));
        assert!(matches!(
            SecurityError::AuthenticationFailed.severity(),
            ErrorSeverity::Medium
        ));
        assert!(matches!(
            SecurityError::AuthorizationDenied.severity(),
            ErrorSeverity::Medium
        ));
        assert!(matches!(
            SecurityError::RateLimitExceeded.severity(),
            ErrorSeverity::Low
        ));
        assert!(matches!(
            SecurityError::InvalidInput.severity(),
            ErrorSeverity::Low
        ));
        assert!(matches!(
            SecurityError::NotFound.severity(),
            ErrorSeverity::Low
        ));
    }

    #[test]
    fn test_security_error_error_code() {
        assert_eq!(
            SecurityError::AuthenticationFailed.error_code(),
            "AUTH_FAILED"
        );
        assert_eq!(
            SecurityError::AuthorizationDenied.error_code(),
            "ACCESS_DENIED"
        );
        assert_eq!(
            SecurityError::RateLimitExceeded.error_code(),
            "RATE_LIMITED"
        );
        assert_eq!(SecurityError::InvalidInput.error_code(), "INVALID_INPUT");
        assert_eq!(
            SecurityError::CryptographicFailure.error_code(),
            "CRYPTO_FAILURE"
        );
        assert_eq!(SecurityError::Configuration.error_code(), "CONFIG_ERROR");
        assert_eq!(
            SecurityError::ServiceUnavailable.error_code(),
            "SERVICE_UNAVAILABLE"
        );
        assert_eq!(SecurityError::Internal.error_code(), "INTERNAL_ERROR");
        assert_eq!(SecurityError::Timeout.error_code(), "TIMEOUT");
        assert_eq!(SecurityError::NotFound.error_code(), "NOT_FOUND");
        assert_eq!(SecurityError::Conflict.error_code(), "CONFLICT");
        assert_eq!(
            SecurityError::PayloadTooLarge.error_code(),
            "PAYLOAD_TOO_LARGE"
        );
    }

    #[test]
    fn test_error_severity_display() {
        assert_eq!(ErrorSeverity::Low.to_string(), "LOW");
        assert_eq!(ErrorSeverity::Medium.to_string(), "MEDIUM");
        assert_eq!(ErrorSeverity::High.to_string(), "HIGH");
        assert_eq!(ErrorSeverity::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn test_circuit_state_from_u8() {
        assert!(matches!(CircuitState::from(0), CircuitState::Closed));
        assert!(matches!(CircuitState::from(1), CircuitState::Open));
        assert!(matches!(CircuitState::from(2), CircuitState::HalfOpen));
        assert!(matches!(CircuitState::from(99), CircuitState::Closed)); // Default case
    }

    #[test]
    fn test_security_error_clone() {
        let error = SecurityError::AuthenticationFailed;
        let cloned = error.clone();
        assert_eq!(error.error_code(), cloned.error_code());
    }

    #[test]
    fn test_security_result_sanitize_error() {
        let result: SecurityResult<()> = Err(SecurityError::Configuration);
        let sanitized = result.sanitize_error();
        assert!(matches!(sanitized.unwrap_err(), SecurityError::Internal));

        let result: SecurityResult<()> = Err(SecurityError::Internal);
        let sanitized = result.sanitize_error();
        assert!(matches!(sanitized.unwrap_err(), SecurityError::Internal));

        let result: SecurityResult<()> = Err(SecurityError::AuthenticationFailed);
        let sanitized = result.sanitize_error();
        assert!(matches!(
            sanitized.unwrap_err(),
            SecurityError::AuthenticationFailed
        ));
    }

    #[test]
    fn test_security_result_map_internal_error() {
        let result: SecurityResult<()> = Err(SecurityError::AuthenticationFailed);
        let mapped = result.map_internal_error();
        assert!(matches!(mapped.unwrap_err(), SecurityError::Internal));
    }

    #[tokio::test]
    async fn test_security_result_log_security_error() {
        let result: SecurityResult<()> = Err(SecurityError::AuthenticationFailed);
        let logged = result.log_security_error();
        assert!(matches!(
            logged.unwrap_err(),
            SecurityError::AuthenticationFailed
        ));

        // Test with non-loggable error
        let result: SecurityResult<()> = Err(SecurityError::InvalidInput);
        let logged = result.log_security_error();
        assert!(matches!(logged.unwrap_err(), SecurityError::InvalidInput));
    }

    #[tokio::test]
    async fn test_security_result_log_security_error_with_context() {
        let result: SecurityResult<()> = Err(SecurityError::CryptographicFailure);
        let logged = result.log_security_error_with_context("JWT validation");
        assert!(matches!(
            logged.unwrap_err(),
            SecurityError::CryptographicFailure
        ));
    }

    #[test]
    fn test_rustls_error_conversion() {
        // Note: This would require creating an actual rustls::Error, which is complex
        // Instead we test the conversion exists
        use rustls::Error as RustlsError;
        let error = RustlsError::InappropriateMessage {
            expect_types: vec![],
            got_type: rustls::ContentType::Alert,
        };
        let security_error: SecurityError = error.into();
        assert!(matches!(
            security_error,
            SecurityError::CryptographicFailure
        ));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_recovery() {
        let circuit_breaker = CircuitBreaker::new(1, Duration::from_millis(10));

        // Trigger failure to open circuit
        let _result = circuit_breaker
            .call(async { Err::<(), SecurityError>(SecurityError::Internal) })
            .await;

        assert!(matches!(circuit_breaker.get_state(), CircuitState::Open));

        // Wait for recovery timeout
        tokio::time::sleep(Duration::from_millis(15)).await;

        // Next call should transition to half-open
        let _result = circuit_breaker
            .call(async { Ok::<(), SecurityError>(()) })
            .await;

        // After success, should be closed
        assert!(matches!(circuit_breaker.get_state(), CircuitState::Closed));
    }

    #[tokio::test]
    async fn test_circuit_breaker_success_reset() {
        let circuit_breaker = CircuitBreaker::new(3, Duration::from_secs(1));

        // Add some failures (but not enough to open)
        let _result = circuit_breaker
            .call(async { Err::<(), SecurityError>(SecurityError::Internal) })
            .await;
        let _result = circuit_breaker
            .call(async { Err::<(), SecurityError>(SecurityError::Internal) })
            .await;

        // Success should reset failure count
        let result = circuit_breaker
            .call(async { Ok::<(), SecurityError>(()) })
            .await;
        assert!(result.is_ok());

        // Circuit should still be closed
        assert!(matches!(circuit_breaker.get_state(), CircuitState::Closed));
    }

    #[tokio::test]
    async fn test_retry_policy_non_retryable_error() {
        let retry_policy = RetryPolicy::new(3, Duration::from_millis(10));
        let mut call_count = 0;

        let result: SecurityResult<()> = retry_policy
            .execute(|| {
                call_count += 1;
                Box::pin(async move { Err(SecurityError::AuthenticationFailed) })
            })
            .await;

        // Should not retry authentication failures
        assert!(matches!(
            result.unwrap_err(),
            SecurityError::AuthenticationFailed
        ));
        assert_eq!(call_count, 1);
    }

    #[tokio::test]
    async fn test_retry_policy_max_attempts() {
        let retry_policy = RetryPolicy::new(2, Duration::from_millis(1));
        let mut call_count = 0;

        let result: SecurityResult<()> = retry_policy
            .execute(|| {
                call_count += 1;
                Box::pin(async move { Err(SecurityError::ServiceUnavailable) })
            })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            SecurityError::ServiceUnavailable
        ));
        assert_eq!(call_count, 2);
    }

    #[test]
    fn test_retry_policy_calculate_delay() {
        let retry_policy = RetryPolicy::new(5, Duration::from_millis(100));

        let delay1 = retry_policy.calculate_delay(1);
        let delay2 = retry_policy.calculate_delay(2);
        let delay3 = retry_policy.calculate_delay(3);

        // Should be exponential with jitter
        assert!(delay1 >= Duration::from_millis(100));
        assert!(delay2 >= Duration::from_millis(200));
        assert!(delay3 >= Duration::from_millis(400));
    }

    #[test]
    fn test_retry_policy_without_jitter() {
        let retry_policy = RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            jitter: false,
        };

        let delay1 = retry_policy.calculate_delay(1);
        let delay2 = retry_policy.calculate_delay(2);

        assert_eq!(delay1, Duration::from_millis(100));
        assert_eq!(delay2, Duration::from_millis(200));
    }

    #[test]
    fn test_retry_policy_max_delay() {
        let retry_policy = RetryPolicy {
            max_attempts: 10,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
            jitter: false,
        };

        let delay = retry_policy.calculate_delay(10); // Would be very large without cap
        assert!(delay <= Duration::from_millis(500));
    }

    #[test]
    fn test_security_error_display() {
        assert_eq!(
            SecurityError::AuthenticationFailed.to_string(),
            "Authentication failed"
        );
        assert_eq!(
            SecurityError::AuthorizationDenied.to_string(),
            "Authorization denied"
        );
        assert_eq!(
            SecurityError::RateLimitExceeded.to_string(),
            "Rate limit exceeded"
        );
        assert_eq!(
            SecurityError::InvalidInput.to_string(),
            "Invalid input provided"
        );
        assert_eq!(
            SecurityError::CryptographicFailure.to_string(),
            "Cryptographic operation failed"
        );
        assert_eq!(
            SecurityError::Configuration.to_string(),
            "Configuration error"
        );
        assert_eq!(
            SecurityError::ServiceUnavailable.to_string(),
            "Service temporarily unavailable"
        );
        assert_eq!(SecurityError::Internal.to_string(), "Internal system error");
        assert_eq!(SecurityError::Timeout.to_string(), "Request timeout");
        assert_eq!(SecurityError::NotFound.to_string(), "Resource not found");
        assert_eq!(
            SecurityError::Conflict.to_string(),
            "Conflict with existing resource"
        );
        assert_eq!(
            SecurityError::PayloadTooLarge.to_string(),
            "Request payload too large"
        );
    }

    #[test]
    fn test_all_security_error_variants() {
        // Ensure all variants are covered
        let errors = vec![
            SecurityError::AuthenticationFailed,
            SecurityError::AuthorizationDenied,
            SecurityError::RateLimitExceeded,
            SecurityError::InvalidInput,
            SecurityError::CryptographicFailure,
            SecurityError::Configuration,
            SecurityError::ServiceUnavailable,
            SecurityError::Internal,
            SecurityError::Timeout,
            SecurityError::NotFound,
            SecurityError::Conflict,
            SecurityError::PayloadTooLarge,
        ];

        for error in errors {
            // Test that each error has proper methods
            assert!(!error.public_message().is_empty());
            assert!(!error.error_code().is_empty());

            // Test severity is not none/empty
            let _severity = error.severity();

            // Test retryable logic
            let _retryable = error.is_retryable();
        }
    }
}
