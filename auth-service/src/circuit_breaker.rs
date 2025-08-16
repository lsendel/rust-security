use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: usize,
    pub success_threshold: usize,
    pub timeout: Duration,
    pub reset_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(60),
            reset_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitState>>,
    failure_count: AtomicUsize,
    success_count: AtomicUsize,
    last_failure_time: AtomicU64,
    next_attempt: AtomicU64,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: AtomicUsize::new(0),
            success_count: AtomicUsize::new(0),
            last_failure_time: AtomicU64::new(0),
            next_attempt: AtomicU64::new(0),
        }
    }

    pub async fn call<F, T, E>(&self, operation: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        // Check if circuit is open and if we should attempt
        if !self.can_attempt().await {
            return Err(CircuitBreakerError::CircuitOpen);
        }

        // Execute the operation
        match operation.await {
            Ok(result) => {
                self.on_success().await;
                Ok(result)
            }
            Err(error) => {
                self.on_failure().await;
                Err(CircuitBreakerError::OperationFailed(error))
            }
        }
    }

    async fn can_attempt(&self) -> bool {
        let state = self.state.read().await;
        match *state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true,
            CircuitState::Open => {
                let now = Instant::now().elapsed().as_secs();
                let next_attempt = self.next_attempt.load(Ordering::Relaxed);
                now >= next_attempt
            }
        }
    }

    async fn on_success(&self) {
        let mut state = self.state.write().await;
        match *state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::Relaxed);
            }
            CircuitState::HalfOpen => {
                let success_count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if success_count >= self.config.success_threshold {
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::Relaxed);
                    self.success_count.store(0, Ordering::Relaxed);
                    tracing::info!("Circuit breaker closed after successful recovery");
                }
            }
            CircuitState::Open => {
                // Transition to half-open on first success after timeout
                *state = CircuitState::HalfOpen;
                self.success_count.store(1, Ordering::Relaxed);
                tracing::info!("Circuit breaker transitioned to half-open");
            }
        }
    }

    async fn on_failure(&self) {
        let mut state = self.state.write().await;
        let failure_count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;

        match *state {
            CircuitState::Closed => {
                if failure_count >= self.config.failure_threshold {
                    *state = CircuitState::Open;
                    let now = Instant::now().elapsed().as_secs();
                    self.last_failure_time.store(now, Ordering::Relaxed);
                    self.next_attempt.store(now + self.config.reset_timeout.as_secs(), Ordering::Relaxed);
                    tracing::warn!(
                        failure_count = failure_count,
                        threshold = self.config.failure_threshold,
                        "Circuit breaker opened due to failures"
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Go back to open state on failure during half-open
                *state = CircuitState::Open;
                let now = Instant::now().elapsed().as_secs();
                self.last_failure_time.store(now, Ordering::Relaxed);
                self.next_attempt.store(now + self.config.reset_timeout.as_secs(), Ordering::Relaxed);
                self.success_count.store(0, Ordering::Relaxed);
                tracing::warn!("Circuit breaker reopened after failure during half-open state");
            }
            CircuitState::Open => {
                // Update next attempt time
                let now = Instant::now().elapsed().as_secs();
                self.next_attempt.store(now + self.config.reset_timeout.as_secs(), Ordering::Relaxed);
            }
        }
    }

    pub async fn state(&self) -> CircuitState {
        let state = self.state.read().await;
        match *state {
            CircuitState::Open => {
                // Check if we should transition to half-open
                let now = Instant::now().elapsed().as_secs();
                let next_attempt = self.next_attempt.load(Ordering::Relaxed);
                if now >= next_attempt {
                    drop(state);
                    let mut state = self.state.write().await;
                    if matches!(*state, CircuitState::Open) {
                        *state = CircuitState::HalfOpen;
                        self.success_count.store(0, Ordering::Relaxed);
                        tracing::info!("Circuit breaker transitioned to half-open due to timeout");
                    }
                    state.clone()
                } else {
                    state.clone()
                }
            }
            _ => state.clone(),
        }
    }

    pub fn failure_count(&self) -> usize {
        self.failure_count.load(Ordering::Relaxed)
    }

    pub fn success_count(&self) -> usize {
        self.success_count.load(Ordering::Relaxed)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerError<E> {
    #[error("Circuit breaker is open")]
    CircuitOpen,
    #[error("Operation failed: {0}")]
    OperationFailed(E),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_circuit_breaker_closed_state() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(1),
            reset_timeout: Duration::from_secs(1),
        };
        let cb = CircuitBreaker::new(config);

        // Successful operations should keep circuit closed
        for _ in 0..5 {
            let result = cb.call(async { Ok::<_, &str>("success") }).await;
            assert!(result.is_ok());
            assert_eq!(cb.state().await, CircuitState::Closed);
        }
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(1),
            reset_timeout: Duration::from_secs(1),
        };
        let cb = CircuitBreaker::new(config);

        // First two failures should keep circuit closed
        for _ in 0..2 {
            let result = cb.call(async { Err::<&str, _>("failure") }).await;
            assert!(result.is_err());
            assert_eq!(cb.state().await, CircuitState::Closed);
        }

        // Third failure should open the circuit
        let result = cb.call(async { Err::<&str, _>("failure") }).await;
        assert!(result.is_err());
        let st = cb.state().await;
        assert!(matches!(st, CircuitState::Open | CircuitState::HalfOpen));

        // Further calls should be rejected immediately
        let result = cb.call(async { Ok::<_, &str>("success") }).await;
        assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen)));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(200),
            reset_timeout: Duration::from_millis(300),
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..2 {
            let _ = cb.call(async { Err::<&str, _>("failure") }).await;
        }
        let st_after_open = cb.state().await;
        assert!(matches!(st_after_open, CircuitState::Open | CircuitState::HalfOpen));

        // Wait for reset timeout
        sleep(Duration::from_millis(500)).await;

        // Perform required successes and verify the circuit closes
        let res1 = cb.call(async { Ok::<_, &str>("success") }).await;
        assert!(res1.is_ok());
        let res2 = cb.call(async { Ok::<_, &str>("success") }).await;
        assert!(res2.is_ok());
        assert_eq!(cb.state().await, CircuitState::Closed);
    }
}
