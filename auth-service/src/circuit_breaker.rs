// Circuit breaker implementation
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time::{sleep, timeout};

// TODO: Refactor to use crate::common_config::{TimeoutConfig, RetryConfig}

#[derive(Error, Debug)]
pub enum CircuitBreakerError {
    #[error("Circuit breaker is open")]
    Open,
    #[error("Operation timeout after {timeout:?}")]
    Timeout { timeout: Duration },
    #[error("Too many requests")]
    TooManyRequests,
    #[error("Operation failed: {0}")]
    OperationFailed(String),
}

impl From<CircuitBreakerError> for crate::shared::error::AppError {
    fn from(err: CircuitBreakerError) -> Self {
        match err {
            CircuitBreakerError::Open => Self::ServiceUnavailable {
                reason: "Circuit breaker is open".to_string(),
            },
            CircuitBreakerError::Timeout { timeout } => Self::ServiceUnavailable {
                reason: format!("Operation timeout after {timeout:?}"),
            },
            CircuitBreakerError::TooManyRequests => Self::RateLimitExceeded,
            CircuitBreakerError::OperationFailed(msg) => Self::ServiceUnavailable {
                reason: format!("Operation failed: {msg}"),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing, rejecting requests
    HalfOpen, // Testing if service recovered
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub recovery_timeout: Duration,
    pub request_timeout: Duration,
    pub half_open_max_calls: u32,
    pub minimum_request_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(10),
            half_open_max_calls: 3,
            minimum_request_threshold: 10,
        }
    }
}

#[derive(Debug)]
struct CircuitBreakerState {
    failure_count: AtomicU32,
    success_count: AtomicU32,
    request_count: AtomicU64,
    next_attempt: Mutex<Instant>,
    half_open_calls: AtomicU32,
    state: Mutex<CircuitState>,
}

#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    name: String,
    config: CircuitBreakerConfig,
    state: Arc<CircuitBreakerState>,
}

impl CircuitBreaker {
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            name: name.into(),
            config,
            state: Arc::new(CircuitBreakerState {
                failure_count: AtomicU32::new(0),
                success_count: AtomicU32::new(0),
                request_count: AtomicU64::new(0),
                next_attempt: Mutex::new(Instant::now()),
                half_open_calls: AtomicU32::new(0),
                state: Mutex::new(CircuitState::Closed),
            }),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn state(&self) -> CircuitState {
        self.state
            .state
            .lock()
            .map(|state| *state)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to acquire circuit breaker state lock: {}", e);
                CircuitState::Open // Fail safe to open state
            })
    }

    #[must_use]
    pub fn stats(&self) -> CircuitBreakerStats {
        CircuitBreakerStats {
            state: self.state(),
            failure_count: self.state.failure_count.load(Ordering::Relaxed),
            success_count: self.state.success_count.load(Ordering::Relaxed),
            request_count: self.state.request_count.load(Ordering::Relaxed),
            half_open_calls: self.state.half_open_calls.load(Ordering::Relaxed),
        }
    }

    pub async fn call<F, R, E>(&self, operation: F) -> Result<R, CircuitBreakerError>
    where
        F: std::future::Future<Output = Result<R, E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        // Check if we can make the call
        match self.can_execute() {
            Ok(()) => {}
            Err(e) => return Err(e),
        }

        self.state.request_count.fetch_add(1, Ordering::Relaxed);

        // Execute with timeout
        let result = timeout(self.config.request_timeout, operation).await;

        match result {
            Ok(Ok(response)) => {
                self.on_success();
                Ok(response)
            }
            Ok(Err(e)) => {
                self.on_failure();
                Err(CircuitBreakerError::OperationFailed(e.to_string()))
            }
            Err(_) => {
                self.on_failure();
                Err(CircuitBreakerError::Timeout {
                    timeout: self.config.request_timeout,
                })
            }
        }
    }

    fn can_execute(&self) -> Result<(), CircuitBreakerError> {
        let current_state = self.state();

        match current_state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if we should transition to half-open
                let next_attempt = self
                    .state
                    .next_attempt
                    .lock()
                    .map(|guard| *guard)
                    .unwrap_or_else(|e| {
                        tracing::error!("Failed to acquire next_attempt lock: {}", e);
                        Instant::now() + Duration::from_secs(60) // Default to 1 minute from now
                    });
                if Instant::now() >= next_attempt {
                    self.transition_to_half_open();
                    Ok(())
                } else {
                    Err(CircuitBreakerError::Open)
                }
            }
            CircuitState::HalfOpen => {
                // Limit concurrent calls in half-open state
                let current_calls = self.state.half_open_calls.load(Ordering::Relaxed);
                if current_calls < self.config.half_open_max_calls {
                    self.state.half_open_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                } else {
                    Err(CircuitBreakerError::TooManyRequests)
                }
            }
        }
    }

    fn on_success(&self) {
        let current_state = self.state();

        match current_state {
            CircuitState::Closed => {
                self.state.success_count.fetch_add(1, Ordering::Relaxed);
                // Reset failure count on success
                self.state.failure_count.store(0, Ordering::Relaxed);
            }
            CircuitState::HalfOpen => {
                self.state.success_count.fetch_add(1, Ordering::Relaxed);
                self.state.half_open_calls.fetch_sub(1, Ordering::Relaxed);

                // If we've had enough successful calls, close the circuit
                let success_count = self.state.success_count.load(Ordering::Relaxed);
                if success_count >= self.config.half_open_max_calls {
                    self.transition_to_closed();
                }
            }
            CircuitState::Open => {
                // This shouldn't happen, but handle gracefully
                tracing::warn!(
                    circuit_breaker = %self.name,
                    "Received success in Open state"
                );
            }
        }

        tracing::debug!(
            circuit_breaker = %self.name,
            state = ?current_state,
            "Circuit breaker success"
        );
    }

    fn on_failure(&self) {
        let current_state = self.state();

        match current_state {
            CircuitState::Closed => {
                let failure_count = self.state.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                let request_count = self.state.request_count.load(Ordering::Relaxed);

                // Only open circuit if we have enough requests and failures
                if request_count >= u64::from(self.config.minimum_request_threshold)
                    && failure_count >= self.config.failure_threshold
                {
                    self.transition_to_open();
                }
            }
            CircuitState::HalfOpen => {
                self.state.half_open_calls.fetch_sub(1, Ordering::Relaxed);
                // Any failure in half-open immediately opens the circuit
                self.transition_to_open();
            }
            CircuitState::Open => {
                // Already open, just increment failure count
                self.state.failure_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        tracing::warn!(
            circuit_breaker = %self.name,
            state = ?current_state,
            failure_count = self.state.failure_count.load(Ordering::Relaxed),
            "Circuit breaker failure"
        );
    }

    fn transition_to_open(&self) {
        if let Ok(mut state) = self.state.state.lock() {
            if *state != CircuitState::Open {
                *state = CircuitState::Open;
                if let Ok(mut next_attempt) = self.state.next_attempt.lock() {
                    *next_attempt = Instant::now() + self.config.recovery_timeout;
                } else {
                    tracing::error!(
                        "Failed to acquire next_attempt lock during transition to open"
                    );
                }

                tracing::warn!(
                    circuit_breaker = %self.name,
                    recovery_timeout = ?self.config.recovery_timeout,
                    "Circuit breaker opened"
                );
            }
        } else {
            tracing::error!("Failed to acquire state lock during transition to open");
        }
    }

    fn transition_to_half_open(&self) {
        if let Ok(mut state) = self.state.state.lock() {
            if *state == CircuitState::Open {
                *state = CircuitState::HalfOpen;
                self.state.half_open_calls.store(0, Ordering::Relaxed);
                self.state.success_count.store(0, Ordering::Relaxed);

                tracing::info!(
                    circuit_breaker = %self.name,
                    "Circuit breaker transitioned to half-open"
                );
            }
        } else {
            tracing::error!("Failed to acquire state lock during transition to half-open");
        }
    }

    fn transition_to_closed(&self) {
        if let Ok(mut state) = self.state.state.lock() {
            if *state != CircuitState::Closed {
                *state = CircuitState::Closed;
                self.state.failure_count.store(0, Ordering::Relaxed);
                self.state.success_count.store(0, Ordering::Relaxed);
                self.state.half_open_calls.store(0, Ordering::Relaxed);

                tracing::info!(
                    circuit_breaker = %self.name,
                    "Circuit breaker closed"
                );
            }
        } else {
            tracing::error!("Failed to acquire state lock during transition to closed");
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub request_count: u64,
    pub half_open_calls: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TimeoutConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
        }
    }
}

// Retry configuration with exponential backoff
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

pub struct RetryBackoff {
    config: RetryConfig,
    attempt: u32,
}

impl RetryBackoff {
    #[must_use]
    pub const fn new(config: RetryConfig) -> Self {
        Self { config, attempt: 0 }
    }

    pub async fn next_delay(&mut self) -> Option<Duration> {
        if self.attempt >= self.config.max_retries {
            return None;
        }

        let mut delay = Duration::from_millis(
            (self.config.base_delay.as_millis() as f64
                * self.config.backoff_multiplier.powi(self.attempt as i32)) as u64,
        );

        // Cap at max_delay
        if delay > self.config.max_delay {
            delay = self.config.max_delay;
        }

        // Add jitter to avoid thundering herd
        if self.config.jitter {
            use rand::rngs::OsRng;
            use rand::RngCore;
            let mut bytes = [0u8; 8];
            OsRng.fill_bytes(&mut bytes);
            let random_f64 = f64::from_be_bytes(bytes) / (u64::MAX as f64);
            let delay_millis_u64 = delay.as_millis().min(u128::from(u64::MAX)) as u64;
            let jitter_ms = (delay_millis_u64 as f64 * 0.1 * random_f64) as u64;
            delay = Duration::from_millis(delay_millis_u64 + jitter_ms);
        }

        self.attempt += 1;

        if delay > Duration::ZERO {
            sleep(delay).await;
        }

        Some(delay)
    }

    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_circuit_breaker_closed_state() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            minimum_request_threshold: 1,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // Successful call should keep circuit closed
        let result = cb.call(async { Ok::<_, std::io::Error>(42) }).await;
        assert!(result.is_ok());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            minimum_request_threshold: 1,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // First failure
        let _ = cb
            .call(async { Err::<(), _>(std::io::Error::other("fail")) })
            .await;
        assert_eq!(cb.state(), CircuitState::Closed);

        // Second failure should open circuit
        let _ = cb
            .call(async { Err::<(), _>(std::io::Error::other("fail")) })
            .await;
        assert_eq!(cb.state(), CircuitState::Open);

        // Next call should be rejected
        let result = cb.call(async { Ok::<_, std::io::Error>(42) }).await;
        assert!(matches!(result, Err(CircuitBreakerError::Open)));
    }

    #[tokio::test]
    async fn test_circuit_breaker_timeout() {
        let config = CircuitBreakerConfig {
            request_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // Call that takes longer than timeout
        let result = cb
            .call(async {
                sleep(Duration::from_millis(200)).await;
                Ok::<_, std::io::Error>(42)
            })
            .await;

        assert!(matches!(result, Err(CircuitBreakerError::Timeout { .. })));
    }

    #[tokio::test]
    async fn test_retry_backoff() {
        let config = RetryConfig {
            max_retries: 3,
            base_delay: Duration::from_millis(10),
            jitter: false,
            ..Default::default()
        };

        let mut backoff = RetryBackoff::new(config);

        // First retry
        let delay1 = backoff.next_delay().await;
        assert!(delay1.is_some());
        assert_eq!(backoff.attempt(), 1);

        // Second retry should have longer delay
        let delay2 = backoff.next_delay().await;
        assert!(delay2.is_some());
        assert_eq!(backoff.attempt(), 2);

        // Third retry
        let delay3 = backoff.next_delay().await;
        assert!(delay3.is_some());
        assert_eq!(backoff.attempt(), 3);

        // Fourth attempt should be None (max retries reached}
        let delay4 = backoff.next_delay().await;
        assert!(delay4.is_none());
    }
}
