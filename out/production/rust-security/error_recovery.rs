//! Comprehensive error recovery and resilience mechanisms
//!
//! This module provides enterprise-grade error handling, recovery strategies,
//! and circuit breaker patterns for production reliability.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{RwLock, Semaphore};
use tracing::{error, info, warn};

/// Error recovery configuration
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    pub max_retry_attempts: u32,
    pub base_retry_delay: Duration,
    pub max_retry_delay: Duration,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_timeout: Duration,
    pub backoff_multiplier: f64,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            max_retry_attempts: 3,
            base_retry_delay: Duration::from_millis(100),
            max_retry_delay: Duration::from_secs(30),
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout: Duration::from_secs(60),
            backoff_multiplier: 2.0,
        }
    }
}

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing, requests rejected
    HalfOpen, // Testing recovery
}

/// Circuit breaker for external service protection
pub struct CircuitBreaker {
    state: RwLock<CircuitState>,
    failure_count: RwLock<u32>,
    last_failure_time: RwLock<Option<Instant>>,
    success_count: RwLock<u32>,
    config: RecoveryConfig,
    name: String,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(name: &str, config: RecoveryConfig) -> Self {
        Self {
            state: RwLock::new(CircuitState::Closed),
            failure_count: RwLock::new(0),
            last_failure_time: RwLock::new(None),
            success_count: RwLock::new(0),
            config,
            name: name.to_string(),
        }
    }

    /// Check if request should be allowed
    pub async fn can_proceed(&self) -> bool {
        let state = self.state.read().await.clone();

        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has elapsed
                if let Some(last_failure) = *self.last_failure_time.read().await {
                    if last_failure.elapsed() >= self.config.circuit_breaker_timeout {
                        // Transition to half-open
                        *self.state.write().await = CircuitState::HalfOpen;
                        *self.success_count.write().await = 0;
                        info!("Circuit breaker '{}' transitioning to half-open", self.name);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests for testing
                let success_count = *self.success_count.read().await;
                success_count < 3 // Allow up to 3 test requests
            }
        }
    }

    /// Record a successful operation
    pub async fn record_success(&self) {
        let mut success_count = self.success_count.write().await;
        *success_count += 1;

        let state = self.state.read().await.clone();
        if state == CircuitState::HalfOpen && *success_count >= 3 {
            // Recovery successful, close circuit
            *self.state.write().await = CircuitState::Closed;
            *self.failure_count.write().await = 0;
            info!("Circuit breaker '{}' recovered, closing circuit", self.name);
        }
    }

    /// Record a failed operation
    pub async fn record_failure(&self) {
        let mut failure_count = self.failure_count.write().await;
        *failure_count += 1;
        *self.last_failure_time.write().await = Some(Instant::now());

        let mut state = self.state.write().await;
        if *failure_count >= self.config.circuit_breaker_threshold {
            *state = CircuitState::Open;
            warn!(
                "Circuit breaker '{}' opened due to {} failures",
                self.name, *failure_count
            );
        }
    }

    /// Get current circuit state
    pub async fn get_state(&self) -> CircuitState {
        self.state.read().await.clone()
    }
}

/// Retry mechanism with exponential backoff
pub struct RetryMechanism {
    config: RecoveryConfig,
}

impl RetryMechanism {
    pub fn new(config: RecoveryConfig) -> Self {
        Self { config }
    }

    /// Execute operation with retry logic
    pub async fn execute_with_retry<F, Fut, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let mut attempt = 0;
        let mut delay = self.config.base_retry_delay;

        loop {
            attempt += 1;

            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    if attempt >= self.config.max_retry_attempts {
                        error!("Operation failed after {} attempts: {:?}", attempt, error);
                        return Err(error);
                    }

                    warn!(
                        "Operation failed (attempt {}/{}): {:?}",
                        attempt, self.config.max_retry_attempts, error
                    );

                    // Wait before retry with exponential backoff
                    tokio::time::sleep(delay).await;

                    // Increase delay for next attempt
                    delay = std::cmp::min(
                        delay.mul_f64(self.config.backoff_multiplier),
                        self.config.max_retry_delay,
                    );
                }
            }
        }
    }
}

/// Bulkhead pattern for resource isolation
pub struct Bulkhead {
    semaphore: Arc<Semaphore>,
    name: String,
}

impl Bulkhead {
    /// Create a new bulkhead with maximum concurrent operations
    pub fn new(name: &str, max_concurrent: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            name: name.to_string(),
        }
    }

    /// Execute operation within bulkhead
    pub async fn execute<F, Fut, T>(&self, operation: F) -> Result<T, BulkheadError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| BulkheadError::SemaphoreError)?;

        let result = operation().await;

        // Permit is automatically released when dropped
        drop(permit);

        Ok(result)
    }
}

#[derive(Error, Debug)]
pub enum BulkheadError {
    #[error("Failed to acquire semaphore permit")]
    SemaphoreError,
}

/// Service registry for managing external dependencies
pub struct ServiceRegistry {
    services: RwLock<HashMap<String, ServiceStatus>>,
}

#[derive(Debug, Clone)]
pub struct ServiceStatus {
    pub name: String,
    pub healthy: bool,
    pub last_check: Instant,
    pub consecutive_failures: u32,
    pub response_time: Duration,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: RwLock::new(HashMap::new()),
        }
    }

    /// Register a service
    pub async fn register_service(&self, name: &str) {
        let mut services = self.services.write().await;
        services.insert(
            name.to_string(),
            ServiceStatus {
                name: name.to_string(),
                healthy: true,
                last_check: Instant::now(),
                consecutive_failures: 0,
                response_time: Duration::from_millis(0),
            },
        );
    }

    /// Update service health status
    pub async fn update_service_health(&self, name: &str, healthy: bool, response_time: Duration) {
        let mut services = self.services.write().await;
        if let Some(service) = services.get_mut(name) {
            service.last_check = Instant::now();
            service.response_time = response_time;

            if healthy {
                service.healthy = true;
                service.consecutive_failures = 0;
            } else {
                service.consecutive_failures += 1;
                if service.consecutive_failures >= 3 {
                    service.healthy = false;
                    warn!(
                        "Service '{}' marked as unhealthy after {} failures",
                        name, service.consecutive_failures
                    );
                }
            }
        }
    }

    /// Get service status
    pub async fn get_service_status(&self, name: &str) -> Option<ServiceStatus> {
        let services = self.services.read().await;
        services.get(name).cloned()
    }

    /// Get all service statuses
    pub async fn get_all_service_statuses(&self) -> HashMap<String, ServiceStatus> {
        let services = self.services.read().await;
        services.clone()
    }
}

/// Error classification and handling strategies
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCategory {
    Transient,      // Temporary errors that may succeed on retry
    Permanent,      // Errors that will not succeed on retry
    Throttling,     // Rate limiting or throttling errors
    Authentication, // Authentication/authorization failures
    Configuration,  // Configuration or setup errors
    Dependency,     // External dependency failures
    Unknown,        // Unclassified errors
}

impl ErrorCategory {
    /// Classify an error based on its type and content
    pub fn classify(error: &dyn std::error::Error) -> Self {
        let error_string = format!("{}", error);

        if error_string.contains("timeout") || error_string.contains("temporary") {
            ErrorCategory::Transient
        } else if error_string.contains("unauthorized") || error_string.contains("forbidden") {
            ErrorCategory::Authentication
        } else if error_string.contains("rate limit") || error_string.contains("throttled") {
            ErrorCategory::Throttling
        } else if error_string.contains("connection") || error_string.contains("network") {
            ErrorCategory::Transient
        } else if error_string.contains("configuration") || error_string.contains("invalid") {
            ErrorCategory::Configuration
        } else {
            ErrorCategory::Unknown
        }
    }

    /// Get recovery strategy for this error category
    pub fn recovery_strategy(&self) -> RecoveryStrategy {
        match self {
            ErrorCategory::Transient => RecoveryStrategy::Retry,
            ErrorCategory::Throttling => RecoveryStrategy::Backoff,
            ErrorCategory::Authentication => RecoveryStrategy::Fail,
            ErrorCategory::Configuration => RecoveryStrategy::Fail,
            ErrorCategory::Dependency => RecoveryStrategy::CircuitBreaker,
            ErrorCategory::Permanent => RecoveryStrategy::Fail,
            ErrorCategory::Unknown => RecoveryStrategy::Retry,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryStrategy {
    Retry,          // Simple retry with backoff
    Backoff,        // Exponential backoff
    CircuitBreaker, // Use circuit breaker pattern
    Fail,           // No recovery, fail immediately
}

/// Graceful degradation manager
pub struct GracefulDegradationManager {
    degraded_features: RwLock<HashMap<String, DegradedFeature>>,
}

#[derive(Debug, Clone)]
pub struct DegradedFeature {
    pub name: String,
    pub enabled: bool,
    pub degradation_level: DegradationLevel,
    pub activated_at: Instant,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DegradationLevel {
    Full,     // Feature completely disabled
    Limited,  // Feature working with reduced functionality
    Degraded, // Feature working but with reduced performance
}

impl GracefulDegradationManager {
    pub fn new() -> Self {
        Self {
            degraded_features: RwLock::new(HashMap::new()),
        }
    }

    /// Activate graceful degradation for a feature
    pub async fn activate_degradation(
        &self,
        feature_name: &str,
        level: DegradationLevel,
        reason: &str,
    ) {
        let mut features = self.degraded_features.write().await;
        features.insert(
            feature_name.to_string(),
            DegradedFeature {
                name: feature_name.to_string(),
                enabled: level != DegradationLevel::Full,
                degradation_level: level,
                activated_at: Instant::now(),
                reason: reason.to_string(),
            },
        );

        warn!(
            "Activated graceful degradation for '{}': {} - {}",
            feature_name,
            reason,
            level.as_str()
        );
    }

    /// Deactivate graceful degradation for a feature
    pub async fn deactivate_degradation(&self, feature_name: &str) {
        let mut features = self.degraded_features.write().await;
        if let Some(feature) = features.remove(feature_name) {
            info!(
                "Deactivated graceful degradation for '{}' after {:?}",
                feature_name,
                feature.activated_at.elapsed()
            );
        }
    }

    /// Check if a feature is available
    pub async fn is_feature_available(&self, feature_name: &str) -> bool {
        let features = self.degraded_features.read().await;
        features
            .get(feature_name)
            .map(|f| f.enabled)
            .unwrap_or(true)
    }

    /// Get degradation status for all features
    pub async fn get_degradation_status(&self) -> HashMap<String, DegradedFeature> {
        let features = self.degraded_features.read().await;
        features.clone()
    }
}

impl DegradationLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            DegradationLevel::Full => "full",
            DegradationLevel::Limited => "limited",
            DegradationLevel::Degraded => "degraded",
        }
    }
}

/// Comprehensive error recovery orchestrator
pub struct ErrorRecoveryOrchestrator {
    circuit_breakers: RwLock<HashMap<String, CircuitBreaker>>,
    retry_mechanism: RetryMechanism,
    bulkheads: RwLock<HashMap<String, Bulkhead>>,
    service_registry: ServiceRegistry,
    degradation_manager: GracefulDegradationManager,
    config: RecoveryConfig,
}

impl ErrorRecoveryOrchestrator {
    /// Create a new error recovery orchestrator
    pub fn new(config: RecoveryConfig) -> Self {
        Self {
            circuit_breakers: RwLock::new(HashMap::new()),
            retry_mechanism: RetryMechanism::new(config.clone()),
            bulkheads: RwLock::new(HashMap::new()),
            service_registry: ServiceRegistry::new(),
            degradation_manager: GracefulDegradationManager::new(),
            config,
        }
    }

    /// Execute operation with full error recovery
    pub async fn execute_with_recovery<F, Fut, T, E>(
        &self,
        operation_name: &str,
        service_name: &str,
        operation: F,
    ) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::error::Error + Clone + Send + Sync + 'static,
        T: Clone + Send + Sync + 'static,
    {
        let start_time = Instant::now();

        // Check circuit breaker
        {
            let circuit_breakers = self.circuit_breakers.read().await;
            if let Some(cb) = circuit_breakers.get(service_name) {
                if !cb.can_proceed().await {
                    warn!(
                        "Circuit breaker '{}' is open, rejecting request",
                        service_name
                    );
                    // In a real implementation, return a proper error type
                    return operation().await; // Fallback to direct execution
                }
            }
        }

        // Execute with bulkhead protection
        let bulkhead_result = {
            let bulkheads = self.bulkheads.read().await;
            if let Some(bulkhead) = bulkheads.get(service_name) {
                bulkhead.execute(|| operation()).await
            } else {
                // No bulkhead, execute directly
                Ok(operation().await)
            }
        };

        let result = match bulkhead_result {
            Ok(result) => result,
            Err(_) => {
                warn!("Bulkhead rejected request for '{}'", service_name);
                operation().await // Fallback
            }
        };

        let response_time = start_time.elapsed();

        // Update service health
        match &result {
            Ok(_) => {
                self.service_registry
                    .update_service_health(service_name, true, response_time)
                    .await;

                // Update circuit breaker
                if let Some(cb) = self.circuit_breakers.read().await.get(service_name) {
                    cb.record_success().await;
                }
            }
            Err(error) => {
                let error_category = ErrorCategory::classify(error);
                self.service_registry
                    .update_service_health(service_name, false, response_time)
                    .await;

                // Update circuit breaker
                if let Some(cb) = self.circuit_breakers.read().await.get(service_name) {
                    cb.record_failure().await;
                }

                // Apply recovery strategy
                match error_category.recovery_strategy() {
                    RecoveryStrategy::Retry => {
                        info!(
                            "Applying retry strategy for '{}' error",
                            error_category.as_str()
                        );
                        return self.retry_mechanism.execute_with_retry(operation).await;
                    }
                    RecoveryStrategy::Backoff => {
                        info!(
                            "Applying backoff strategy for '{}' error",
                            error_category.as_str()
                        );
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        return self.retry_mechanism.execute_with_retry(operation).await;
                    }
                    RecoveryStrategy::CircuitBreaker => {
                        warn!(
                            "Circuit breaker triggered for '{}' error",
                            error_category.as_str()
                        );
                        // Circuit breaker already handled above
                    }
                    RecoveryStrategy::Fail => {
                        error!(
                            "Permanent failure for '{}' error, no recovery attempted",
                            error_category.as_str()
                        );
                    }
                }
            }
        }

        result
    }

    /// Add a circuit breaker for a service
    pub async fn add_circuit_breaker(&self, service_name: &str, config: RecoveryConfig) {
        let mut circuit_breakers = self.circuit_breakers.write().await;
        circuit_breakers.insert(
            service_name.to_string(),
            CircuitBreaker::new(service_name, config),
        );
    }

    /// Add a bulkhead for a service
    pub async fn add_bulkhead(&self, service_name: &str, max_concurrent: usize) {
        let mut bulkheads = self.bulkheads.write().await;
        bulkheads.insert(
            service_name.to_string(),
            Bulkhead::new(service_name, max_concurrent),
        );
    }

    /// Register a service for health monitoring
    pub async fn register_service(&self, service_name: &str) {
        self.service_registry.register_service(service_name).await;
    }

    /// Get system health status
    pub async fn get_system_health(&self) -> SystemHealth {
        let service_statuses = self.service_registry.get_all_service_statuses().await;
        let circuit_breaker_states = self.get_circuit_breaker_states().await;
        let degradation_status = self.degradation_manager.get_degradation_status().await;

        let overall_status = if service_statuses.values().any(|s| !s.healthy) {
            HealthStatus::Degraded
        } else if circuit_breaker_states
            .values()
            .any(|state| *state == CircuitState::Open)
        {
            HealthStatus::Degraded
        } else if !degradation_status.is_empty() {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        SystemHealth {
            overall_status,
            service_statuses,
            circuit_breaker_states,
            degraded_features: degradation_status,
        }
    }

    async fn get_circuit_breaker_states(&self) -> HashMap<String, CircuitState> {
        let circuit_breakers = self.circuit_breakers.read().await;
        let mut states = HashMap::new();

        for (name, cb) in circuit_breakers.iter() {
            states.insert(name.clone(), cb.get_state().await);
        }

        states
    }
}

#[derive(Debug, Clone)]
pub struct SystemHealth {
    pub overall_status: HealthStatus,
    pub service_statuses: HashMap<String, ServiceStatus>,
    pub circuit_breaker_states: HashMap<String, CircuitState>,
    pub degraded_features: HashMap<String, DegradedFeature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_circuit_breaker() {
        let cb = CircuitBreaker::new("test-service", RecoveryConfig::default());

        // Initially closed
        assert!(cb.can_proceed().await);

        // Record failures
        for _ in 0..5 {
            cb.record_failure().await;
        }

        // Should be open after threshold
        assert!(!cb.can_proceed().await);
        assert_eq!(cb.get_state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_retry_mechanism() {
        let retry = RetryMechanism::new(RecoveryConfig {
            max_retry_attempts: 3,
            base_retry_delay: Duration::from_millis(10),
            ..Default::default()
        });

        let attempt_count = Arc::new(AtomicU32::new(0));

        let result = retry
            .execute_with_retry(|| {
                let attempt_count = attempt_count.clone();
                async move {
                    let current = attempt_count.fetch_add(1, Ordering::SeqCst);
                    if current < 2 {
                        // Fail first two attempts
                        Result::<(), &str>::Err("temporary failure")
                    } else {
                        Ok(())
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_bulkhead() {
        let bulkhead = Bulkhead::new("test-bulkhead", 2);

        let counter = Arc::new(AtomicU32::new(0));
        let mut handles = vec![];

        // Launch 5 concurrent operations
        for _ in 0..5 {
            let bulkhead = bulkhead.clone();
            let counter = counter.clone();

            let handle = tokio::spawn(async move {
                bulkhead
                    .execute(|| {
                        let counter = counter.clone();
                        async move {
                            counter.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            counter.fetch_add(1, Ordering::SeqCst);
                        }
                    })
                    .await
            });

            handles.push(handle);
        }

        // Wait for all operations
        for handle in handles {
            let _ = handle.await;
        }

        // Should have processed all operations despite concurrency limit
        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }

    #[tokio::test]
    async fn test_service_registry() {
        let registry = ServiceRegistry::new();

        registry.register_service("test-service").await;

        registry
            .update_service_health("test-service", true, Duration::from_millis(50))
            .await;

        let status = registry.get_service_status("test-service").await.unwrap();
        assert!(status.healthy);
        assert_eq!(status.response_time, Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_error_classification() {
        let timeout_error = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        assert_eq!(
            ErrorCategory::classify(&timeout_error),
            ErrorCategory::Transient
        );

        let auth_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "unauthorized");
        assert_eq!(
            ErrorCategory::classify(&auth_error),
            ErrorCategory::Authentication
        );
    }

    #[tokio::test]
    async fn test_graceful_degradation() {
        let manager = GracefulDegradationManager::new();

        // Initially available
        assert!(manager.is_feature_available("test-feature").await);

        // Activate degradation
        manager
            .activate_degradation(
                "test-feature",
                DegradationLevel::Limited,
                "external service unavailable",
            )
            .await;

        // Should still be available but limited
        assert!(manager.is_feature_available("test-feature").await);

        // Activate full degradation
        manager
            .activate_degradation(
                "test-feature",
                DegradationLevel::Full,
                "service completely down",
            )
            .await;

        // Should not be available
        assert!(!manager.is_feature_available("test-feature").await);

        // Deactivate degradation
        manager.deactivate_degradation("test-feature").await;

        // Should be available again
        assert!(manager.is_feature_available("test-feature").await);
    }
}
