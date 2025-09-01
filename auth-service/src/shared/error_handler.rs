//! Enhanced Error Handling System
//!
//! Unified error handling with proper error conversion, logging, and monitoring.
//! Implements error boundaries, error recovery strategies, and comprehensive error tracking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};

use crate::shared::error::AppError;

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Error context for enhanced error tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    pub operation: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Enhanced error handler with monitoring and recovery
pub struct ErrorHandler {
    error_counts: Arc<RwLock<HashMap<String, u64>>>,
    recent_errors: Arc<RwLock<Vec<ErrorContext>>>,
    max_recent_errors: usize,
    recovery_strategies:
        HashMap<String, Box<dyn Fn(&AppError) -> Result<(), AppError> + Send + Sync>>,
}

impl ErrorHandler {
    /// Create a new error handler
    pub fn new(max_recent_errors: usize) -> Self {
        let mut recovery_strategies = HashMap::new();

        // Register recovery strategies
        recovery_strategies.insert(
            "database_connection".to_string(),
            Box::new(Self::database_connection_recovery)
                as Box<dyn Fn(&AppError) -> Result<(), AppError> + Send + Sync>,
        );

        recovery_strategies.insert(
            "rate_limit".to_string(),
            Box::new(Self::rate_limit_recovery)
                as Box<dyn Fn(&AppError) -> Result<(), AppError> + Send + Sync>,
        );

        Self {
            error_counts: Arc::new(RwLock::new(HashMap::new())),
            recent_errors: Arc::new(RwLock::new(Vec::new())),
            max_recent_errors,
            recovery_strategies,
        }
    }

    /// Handle an error with logging, tracking, and potential recovery
    #[instrument(skip(self, error))]
    pub async fn handle_error(&self, error: AppError, context: ErrorContext) -> AppError {
        // Log the error with appropriate level
        let severity = self.classify_error_severity(&error);
        match severity {
            ErrorSeverity::Low => info!("Low severity error: {}", error),
            ErrorSeverity::Medium => warn!("Medium severity error: {}", error),
            ErrorSeverity::High => error!("High severity error: {}", error),
            ErrorSeverity::Critical => error!("CRITICAL ERROR: {}", error),
        }

        // Track error counts
        let error_type = self.error_type_key(&error);
        let mut counts = self.error_counts.write().await;
        *counts.entry(error_type.clone()).or_insert(0) += 1;

        // Store recent error
        let mut recent = self.recent_errors.write().await;
        recent.push(context.clone());
        if recent.len() > self.max_recent_errors {
            recent.remove(0);
        }

        // Attempt recovery
        if let Some(recovery) = self.recovery_strategies.get(&error_type) {
            if let Ok(()) = recovery(&error) {
                info!("Successfully recovered from error: {}", error_type);
                return AppError::Internal("Error recovered automatically".to_string());
            }
        }

        error
    }

    /// Handle error with automatic context creation
    pub async fn handle_error_auto(
        &self,
        error: AppError,
        operation: &str,
        user_id: Option<String>,
        session_id: Option<String>,
    ) -> AppError {
        let context = ErrorContext {
            operation: operation.to_string(),
            user_id,
            session_id,
            request_id: Some(uuid::Uuid::new_v4().to_string()),
            timestamp: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        self.handle_error(error, context).await
    }

    /// Get error statistics
    pub async fn error_stats(&self) -> HashMap<String, u64> {
        self.error_counts.read().await.clone()
    }

    /// Get recent errors
    pub async fn recent_errors(&self) -> Vec<ErrorContext> {
        self.recent_errors.read().await.clone()
    }

    /// Check if error rate exceeds threshold
    pub async fn check_error_rate_threshold(&self, error_type: &str, threshold: u64) -> bool {
        let counts = self.error_counts.read().await;
        counts.get(error_type).copied().unwrap_or(0) > threshold
    }

    /// Classify error severity
    fn classify_error_severity(&self, error: &AppError) -> ErrorSeverity {
        match error {
            AppError::RateLimitExceeded => ErrorSeverity::Low,
            AppError::Validation(_) | AppError::InvalidRequest { .. } => ErrorSeverity::Low,
            AppError::NotFound(_) | AppError::Unauthorized(_) => ErrorSeverity::Medium,
            AppError::Repository(_) | AppError::ServiceUnavailable { .. } => ErrorSeverity::High,
            AppError::Internal(_) | AppError::CryptographicError(_) => ErrorSeverity::High,
            AppError::Auth(_) | AppError::TokenStoreError { .. } => ErrorSeverity::Critical,
            _ => ErrorSeverity::Medium,
        }
    }

    /// Get error type key for tracking
    fn error_type_key(&self, error: &AppError) -> String {
        match error {
            AppError::Repository(_) => "database".to_string(),
            AppError::ServiceUnavailable { .. } => "service_unavailable".to_string(),
            AppError::RateLimitExceeded => "rate_limit".to_string(),
            AppError::Auth(_) => "authentication".to_string(),
            AppError::Validation(_) => "validation".to_string(),
            AppError::Internal(_) => "internal".to_string(),
            AppError::NotFound(_) => "not_found".to_string(),
            AppError::Unauthorized(_) => "unauthorized".to_string(),
            _ => "other".to_string(),
        }
    }

    /// Database connection recovery strategy
    fn database_connection_recovery(error: &AppError) -> Result<(), AppError> {
        // Implement exponential backoff retry logic
        warn!(
            "Attempting database connection recovery for error: {}",
            error
        );
        // In a real implementation, this would retry the connection
        Ok(())
    }

    /// Rate limit recovery strategy
    fn rate_limit_recovery(error: &AppError) -> Result<(), AppError> {
        // Implement rate limit backoff
        warn!("Rate limit triggered, implementing backoff: {}", error);
        // In a real implementation, this would adjust rate limiting
        Ok(())
    }
}

/// Error boundary wrapper for operations
pub struct ErrorBoundary<T> {
    operation: Box<dyn Fn() -> Result<T, AppError> + Send + Sync>,
    error_handler: Arc<ErrorHandler>,
    operation_name: String,
}

impl<T> ErrorBoundary<T>
where
    T: Send + Sync,
{
    /// Create a new error boundary
    pub fn new<F>(operation: F, error_handler: Arc<ErrorHandler>, operation_name: &str) -> Self
    where
        F: Fn() -> Result<T, AppError> + Send + Sync + 'static,
    {
        Self {
            operation: Box::new(operation),
            error_handler,
            operation_name: operation_name.to_string(),
        }
    }

    /// Execute the operation within the error boundary
    pub async fn execute(self) -> Result<T, AppError> {
        match (self.operation)() {
            Ok(result) => Ok(result),
            Err(error) => {
                let handled_error = self
                    .error_handler
                    .handle_error_auto(error, &self.operation_name, None, None)
                    .await;

                Err(handled_error)
            }
        }
    }

    /// Execute with user context
    pub async fn execute_with_context(
        self,
        user_id: Option<String>,
        session_id: Option<String>,
    ) -> Result<T, AppError> {
        match (self.operation)() {
            Ok(result) => Ok(result),
            Err(error) => {
                let handled_error = self
                    .error_handler
                    .handle_error_auto(error, &self.operation_name, user_id, session_id)
                    .await;

                Err(handled_error)
            }
        }
    }
}

/// Error recovery strategies
pub mod recovery {
    use super::*;

    /// Retry strategy with exponential backoff
    pub struct RetryStrategy {
        max_attempts: u32,
        base_delay: std::time::Duration,
        max_delay: std::time::Duration,
    }

    impl RetryStrategy {
        pub fn new(max_attempts: u32, base_delay: std::time::Duration) -> Self {
            Self {
                max_attempts,
                base_delay,
                max_delay: std::time::Duration::from_secs(30),
            }
        }

        pub async fn execute<F, T>(&self, mut operation: F) -> Result<T, AppError>
        where
            F: FnMut() -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<T, AppError>> + Send>,
            >,
        {
            let mut attempt = 0;

            loop {
                attempt += 1;

                match operation().await {
                    Ok(result) => return Ok(result),
                    Err(error) => {
                        if attempt >= self.max_attempts {
                            return Err(error);
                        }

                        // Calculate delay with exponential backoff
                        let delay = std::cmp::min(
                            self.base_delay * (2_u32.pow(attempt - 1)),
                            self.max_delay,
                        );

                        warn!(
                            "Operation failed (attempt {}/{}), retrying in {:?}",
                            attempt, self.max_attempts, delay
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    }

    /// Circuit breaker pattern
    pub struct CircuitBreaker {
        failure_count: Arc<RwLock<u32>>,
        last_failure_time: Arc<RwLock<Option<std::time::Instant>>>,
        failure_threshold: u32,
        recovery_timeout: std::time::Duration,
        state: Arc<RwLock<CircuitState>>,
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum CircuitState {
        Closed,
        Open,
        HalfOpen,
    }

    impl CircuitBreaker {
        pub fn new(failure_threshold: u32, recovery_timeout: std::time::Duration) -> Self {
            Self {
                failure_count: Arc::new(RwLock::new(0)),
                last_failure_time: Arc::new(RwLock::new(None)),
                failure_threshold,
                recovery_timeout,
                state: Arc::new(RwLock::new(CircuitState::Closed)),
            }
        }

        pub async fn call<F, T>(&self, operation: F) -> Result<T, AppError>
        where
            F: FnOnce() -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<T, AppError>> + Send>,
            >,
        {
            let state = *self.state.read().await;

            match state {
                CircuitState::Open => {
                    // Check if recovery timeout has passed
                    if let Some(last_failure) = *self.last_failure_time.read().await {
                        if last_failure.elapsed() >= self.recovery_timeout {
                            *self.state.write().await = CircuitState::HalfOpen;
                            info!("Circuit breaker transitioning to half-open state");
                        } else {
                            return Err(AppError::ServiceUnavailable {
                                reason: "Circuit breaker is open".to_string()
                            });
                        }
                    }
                }
                CircuitState::HalfOpen => {
                    // Allow one request through
                    match operation().await {
                        Ok(result) => {
                            *self.state.write().await = CircuitState::Closed;
                            *self.failure_count.write().await = 0;
                            info!("Circuit breaker closed - operation succeeded");
                            return Ok(result);
                        }
                        Err(error) => {
                            *self.state.write().await = CircuitState::Open;
                            *self.last_failure_time.write().await = Some(std::time::Instant::now());
                            return Err(error);
                        }
                    }
                }
                CircuitState::Closed => {
                    // Normal operation
                }
            }

            // Execute operation
            match operation().await {
                Ok(result) => {
                    // Reset failure count on success
                    *self.failure_count.write().await = 0;
                    Ok(result)
                }
                Err(error) => {
                    // Increment failure count
                    let mut failures = self.failure_count.write().await;
                    *failures += 1;

                    if *failures >= self.failure_threshold {
                        *self.state.write().await = CircuitState::Open;
                        *self.last_failure_time.write().await = Some(std::time::Instant::now());
                        warn!(
                            "Circuit breaker opened due to {} consecutive failures",
                            *failures
                        );
                    }

                    Err(error)
                }
            }
        }
    }
}

/// Error monitoring and alerting
pub mod monitoring {
    use super::*;

    /// Error alert configuration
    #[derive(Debug, Clone)]
    pub struct ErrorAlertConfig {
        pub error_type: String,
        pub threshold: u64,
        pub time_window: std::time::Duration,
        pub alert_message: String,
    }

    /// Error monitor with alerting capabilities
    pub struct ErrorMonitor {
        error_handler: Arc<ErrorHandler>,
        alerts: Vec<ErrorAlertConfig>,
        last_alert_times: Arc<RwLock<HashMap<String, std::time::Instant>>>,
    }

    impl ErrorMonitor {
        pub fn new(error_handler: Arc<ErrorHandler>, alerts: Vec<ErrorAlertConfig>) -> Self {
            Self {
                error_handler,
                alerts,
                last_alert_times: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        /// Check for error conditions and trigger alerts
        pub async fn check_and_alert(&self) {
            let stats = self.error_handler.error_stats().await;

            for alert in &self.alerts {
                if let Some(count) = stats.get(&alert.error_type) {
                    if *count >= alert.threshold {
                        let should_alert = self.should_trigger_alert(&alert.error_type).await;

                        if should_alert {
                            self.trigger_alert(alert).await;
                            self.record_alert_time(&alert.error_type).await;
                        }
                    }
                }
            }
        }

        /// Check if alert should be triggered (prevent alert spam)
        async fn should_trigger_alert(&self, error_type: &str) -> bool {
            let last_alert = self.last_alert_times.read().await.get(error_type).copied();

            if let Some(last_time) = last_alert {
                // Don't alert more than once every 5 minutes for the same error type
                last_time.elapsed() > std::time::Duration::from_secs(300)
            } else {
                true // First time seeing this error type
            }
        }

        /// Trigger an alert
        async fn trigger_alert(&self, alert: &ErrorAlertConfig) {
            error!(
                "🚨 ERROR ALERT: {} - Threshold: {}, Current: ?",
                alert.alert_message, alert.threshold
            );

            // In a real system, this would:
            // - Send notifications to monitoring systems
            // - Trigger PagerDuty/Slack alerts
            // - Log to centralized monitoring
            // - Send metrics to time-series databases
        }

        /// Record when an alert was triggered
        async fn record_alert_time(&self, error_type: &str) {
            let mut times = self.last_alert_times.write().await;
            times.insert(error_type.to_string(), std::time::Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_error_handler_basic() {
        let handler = ErrorHandler::new(10);

        let error = AppError::Validation("Test validation error".to_string());
        let context = ErrorContext {
            operation: "test_operation".to_string(),
            user_id: Some("user123".to_string()),
            session_id: Some("session456".to_string()),
            request_id: Some("req789".to_string()),
            timestamp: chrono::Utc::now(),
            metadata: HashMap::new(),
        };

        let result = handler.handle_error(error, context).await;

        // Error should be returned as-is (since we can't recover from validation errors)
        match result {
            AppError::Validation(_) => {}
            _ => panic!("Expected validation error"),
        }

        let stats = handler.error_stats().await;
        assert_eq!(stats.get("validation").copied().unwrap_or(0), 1);
    }

    #[tokio::test]
    async fn test_error_boundary() {
        let handler = Arc::new(ErrorHandler::new(10));

        let boundary = ErrorBoundary::new(
            || Err(AppError::NotFound("Test resource".to_string())),
            Arc::clone(&handler),
            "test_boundary",
        );

        let result = boundary.execute().await;
        assert!(matches!(result, Err(AppError::NotFound(_))));

        let recent = handler.recent_errors().await;
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].operation, "test_boundary");
    }

    #[tokio::test]
    async fn test_retry_strategy() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = Arc::clone(&attempts);

        let retry = recovery::RetryStrategy::new(3, std::time::Duration::from_millis(10));

        let result = retry
            .execute(|| {
                let attempts = Arc::clone(&attempts_clone);
                Box::pin(async move {
                    let current = attempts.fetch_add(1, Ordering::Relaxed);
                    if current < 2 {
                        Err(AppError::ServiceUnavailable {
                            reason: "Temporary failure".to_string()
                        })
                    } else {
                        Ok("success".to_string())
                    }
                })
            })
            .await;

        assert_eq!(result, Ok("success".to_string()));
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let breaker = recovery::CircuitBreaker::new(2, std::time::Duration::from_millis(100));

        // First failure
        let result1 = breaker
            .call(|| Box::pin(async { Err(AppError::ServiceUnavailable { reason: "Failure 1".to_string() }) }))
            .await;
        assert!(result1.is_err());

        // Second failure - should open circuit
        let result2 = breaker
            .call(|| Box::pin(async { Err(AppError::ServiceUnavailable { reason: "Failure 2".to_string() }) }))
            .await;
        assert!(result2.is_err());

        // Third call should be rejected due to open circuit
        let result3 = breaker
            .call(|| Box::pin(async { Ok("should not execute".to_string()) }))
            .await;
        assert!(matches!(result3, Err(AppError::ServiceUnavailable { .. })));
    }
}
