// Advanced Circuit Breaker Implementation
// Comprehensive resilience patterns with adaptive thresholds

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing fast
    HalfOpen, // Testing recovery
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open circuit
    pub failure_threshold: u32,
    /// Success threshold to close circuit from half-open
    pub success_threshold: u32,
    /// Timeout before attempting recovery
    pub recovery_timeout: Duration,
    /// Maximum calls allowed in half-open state
    pub half_open_max_calls: u32,
    /// Failure rate threshold (0.0 to 1.0)
    pub failure_rate_threshold: f64,
    /// Minimum calls before calculating failure rate
    pub min_calls_for_rate: u32,
    /// Slow call threshold
    pub slow_call_threshold: Duration,
    /// Slow call rate threshold (0.0 to 1.0)
    pub slow_call_rate_threshold: f64,
    /// Window size for metrics calculation
    pub window_size: Duration,
    /// Enable adaptive thresholds
    pub adaptive_enabled: bool,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            recovery_timeout: Duration::from_secs(30),
            half_open_max_calls: 10,
            failure_rate_threshold: 0.5, // 50%
            min_calls_for_rate: 10,
            slow_call_threshold: Duration::from_secs(5),
            slow_call_rate_threshold: 0.5, // 50%
            window_size: Duration::from_secs(60),
            adaptive_enabled: true,
        }
    }
}

/// Call result for circuit breaker
#[derive(Debug, Clone)]
pub struct CallResult {
    pub success: bool,
    pub duration: Duration,
    pub error: Option<String>,
}

impl CallResult {
    pub fn success(duration: Duration) -> Self {
        Self {
            success: true,
            duration,
            error: None,
        }
    }

    pub fn failure(duration: Duration, error: String) -> Self {
        Self {
            success: false,
            duration,
            error: Some(error),
        }
    }

    pub fn is_slow(&self, threshold: Duration) -> bool {
        self.duration > threshold
    }
}

/// Circuit breaker metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitMetrics {
    pub state: CircuitState,
    pub total_calls: u64,
    pub successful_calls: u64,
    pub failed_calls: u64,
    pub slow_calls: u64,
    pub failure_rate: f64,
    pub slow_call_rate: f64,
    pub last_failure_time: Option<SystemTime>,
    #[serde(skip, default = "std::time::Instant::now")]
    pub state_transition_time: Instant,
    pub half_open_calls: u32,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

impl Default for CircuitMetrics {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            total_calls: 0,
            successful_calls: 0,
            failed_calls: 0,
            slow_calls: 0,
            failure_rate: 0.0,
            slow_call_rate: 0.0,
            last_failure_time: None,
            state_transition_time: Instant::now(),
            half_open_calls: 0,
            consecutive_failures: 0,
            consecutive_successes: 0,
        }
    }
}

/// Circuit breaker errors
#[derive(Debug, Error)]
pub enum CircuitBreakerError {
    #[error("Circuit breaker is open - failing fast")]
    CircuitOpen,
    #[error("Circuit breaker half-open call limit exceeded")]
    HalfOpenLimitExceeded,
    #[error("Call execution failed: {0}")]
    CallFailed(String),
}

/// Advanced circuit breaker with adaptive thresholds
pub struct AdvancedCircuitBreaker {
    name: String,
    config: CircuitBreakerConfig,
    metrics: Arc<RwLock<CircuitMetrics>>,
    call_history: Arc<RwLock<Vec<(Instant, CallResult)>>>,
    adaptive_config: Arc<RwLock<CircuitBreakerConfig>>,
}

impl AdvancedCircuitBreaker {
    /// Create new circuit breaker
    pub fn new(name: String, config: CircuitBreakerConfig) -> Self {
        Self {
            name,
            adaptive_config: Arc::new(RwLock::new(config.clone())),
            config,
            metrics: Arc::new(RwLock::new(CircuitMetrics::default())),
            call_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Execute a call through the circuit breaker
    pub async fn call<F, Fut, T>(&self, operation: F) -> Result<T, CircuitBreakerError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, String>>,
    {
        // Check if call is allowed
        self.check_call_allowed().await?;

        let start_time = Instant::now();
        let _result = operation().await;
        let duration = start_time.elapsed();

        // Record the call result
        let call_result = match result {
            Ok(value) => {
                self.record_success(duration).await;
                Ok(value)
            }
            Err(error) => {
                self.record_failure(duration, error.clone()).await;
                Err(CircuitBreakerError::CallFailed(error))
            }
        };

        // Update adaptive configuration if enabled
        if self.config.adaptive_enabled {
            self.update_adaptive_config().await;
        }

        call_result
    }

    /// Check if a call is allowed based on current state
    async fn check_call_allowed(&self) -> Result<(), CircuitBreakerError> {
        let mut metrics = self.metrics.write().await;
        
        match metrics.state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if recovery timeout has passed
                let now = Instant::now();
                if now.saturating_duration_since(metrics.state_transition_time) >= self.config.recovery_timeout {
                    // Transition to half-open
                    metrics.state = CircuitState::HalfOpen;
                    metrics.state_transition_time = now;
                    metrics.half_open_calls = 0;
                    info!("Circuit breaker '{}' transitioning to half-open", self.name);
                    Ok(())
                } else {
                    Err(CircuitBreakerError::CircuitOpen)
                }
            }
            CircuitState::HalfOpen => {
                if metrics.half_open_calls >= self.config.half_open_max_calls {
                    Err(CircuitBreakerError::HalfOpenLimitExceeded)
                } else {
                    metrics.half_open_calls += 1;
                    Ok(())
                }
            }
        }
    }

    /// Record a successful call
    async fn record_success(&self, duration: Duration) {
        let call_result = CallResult::success(duration);
        self.record_call_result(call_result).await;

        let mut metrics = self.metrics.write().await;
        metrics.total_calls += 1;
        metrics.successful_calls += 1;
        metrics.consecutive_successes += 1;
        metrics.consecutive_failures = 0;

        if duration > self.config.slow_call_threshold {
            metrics.slow_calls += 1;
        }

        // State transitions based on success
        match metrics.state {
            CircuitState::HalfOpen => {
                if metrics.consecutive_successes >= self.config.success_threshold {
                    metrics.state = CircuitState::Closed;
                    metrics.state_transition_time = Instant::now();
                    metrics.half_open_calls = 0;
                    info!("Circuit breaker '{}' closed after successful recovery", self.name);
                }
            }
            _ => {}
        }

        self.update_rates(&mut metrics).await;
    }

    /// Record a failed call
    async fn record_failure(&self, duration: Duration, error: String) {
        let call_result = CallResult::failure(duration, error);
        self.record_call_result(call_result).await;

        let mut metrics = self.metrics.write().await;
        metrics.total_calls += 1;
        metrics.failed_calls += 1;
        metrics.consecutive_failures += 1;
        metrics.consecutive_successes = 0;
        metrics.last_failure_time = Some(SystemTime::now());

        if duration > self.config.slow_call_threshold {
            metrics.slow_calls += 1;
        }

        // Check if circuit should open
        let should_open = match metrics.state {
            CircuitState::Closed => {
                // Open based on consecutive failures or failure rate
                metrics.consecutive_failures >= self.config.failure_threshold ||
                (metrics.total_calls >= self.config.min_calls_for_rate as u64 &&
                 self.calculate_failure_rate(&metrics) >= self.config.failure_rate_threshold)
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open state opens the circuit
                true
            }
            CircuitState::Open => false,
        };

        if should_open && metrics.state != CircuitState::Open {
            metrics.state = CircuitState::Open;
            metrics.state_transition_time = Instant::now();
            metrics.half_open_calls = 0;
            warn!("Circuit breaker '{}' opened due to failures", self.name);
        }

        self.update_rates(&mut metrics).await;
    }

    /// Record call result in history
    async fn record_call_result(&self, result: CallResult) {
        let mut history = self.call_history.write().await;
        let now = Instant::now();
        
        history.push((now, result));
        
        // Clean old entries outside the window
        let cutoff = now - self.config.window_size;
        history.retain(|(timestamp, _)| *timestamp > cutoff);
    }

    /// Update failure and slow call rates
    async fn update_rates(&self, metrics: &mut CircuitMetrics) {
        if metrics.total_calls > 0 {
            metrics.failure_rate = metrics.failed_calls as f64 / metrics.total_calls as f64;
            metrics.slow_call_rate = metrics.slow_calls as f64 / metrics.total_calls as f64;
        }
    }

    /// Calculate current failure rate from recent history
    fn calculate_failure_rate(&self, metrics: &CircuitMetrics) -> f64 {
        if metrics.total_calls == 0 {
            return 0.0;
        }
        metrics.failed_calls as f64 / metrics.total_calls as f64
    }

    /// Update adaptive configuration based on recent performance
    async fn update_adaptive_config(&self) {
        let history = self.call_history.read().await;
        if history.len() < 20 {
            return; // Need sufficient data
        }

        let recent_failures = history.iter()
            .filter(|(_, result)| !result.success)
            .count();
        
        let failure_rate = recent_failures as f64 / history.len() as f64;
        
        let mut adaptive_config = self.adaptive_config.write().await;
        
        // Adjust thresholds based on recent performance
        if failure_rate > 0.3 {
            // High failure rate - make circuit breaker more sensitive
            adaptive_config.failure_threshold = adaptive_config.failure_threshold.saturating_sub(1).max(2);
            adaptive_config.failure_rate_threshold = (adaptive_config.failure_rate_threshold * 0.9).max(0.2);
        } else if failure_rate < 0.05 {
            // Low failure rate - make circuit breaker less sensitive
            adaptive_config.failure_threshold = (adaptive_config.failure_threshold + 1).min(10);
            adaptive_config.failure_rate_threshold = (adaptive_config.failure_rate_threshold * 1.1).min(0.8);
        }

        debug!("Adaptive circuit breaker '{}' updated: failure_threshold={}, failure_rate_threshold={:.2}", 
               self.name, adaptive_config.failure_threshold, adaptive_config.failure_rate_threshold);
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> CircuitMetrics {
        self.metrics.read().await.clone()
    }

    /// Get circuit breaker health status
    pub async fn get_health_status(&self) -> CircuitHealthStatus {
        let metrics = self.metrics.read().await;
        let history = self.call_history.read().await;
        
        let recent_calls = history.len();
        let recent_failures = history.iter().filter(|(_, result)| !result.success).count();
        let recent_slow_calls = history.iter()
            .filter(|(_, result)| result.is_slow(self.config.slow_call_threshold))
            .count();

        let health_score = if recent_calls > 0 {
            let success_rate = (recent_calls - recent_failures) as f64 / recent_calls as f64;
            let speed_score = (recent_calls - recent_slow_calls) as f64 / recent_calls as f64;
            (success_rate + speed_score) / 2.0
        } else {
            1.0 // No recent calls, assume healthy
        };

        CircuitHealthStatus {
            name: self.name.clone(),
            state: metrics.state.clone(),
            health_score,
            recent_calls,
            recent_failures,
            recent_slow_calls,
            uptime_percentage: if metrics.total_calls > 0 {
                metrics.successful_calls as f64 / metrics.total_calls as f64 * 100.0
            } else {
                100.0
            },
            last_failure: metrics.last_failure_time,
        }
    }

    /// Reset circuit breaker to closed state
    pub async fn reset(&self) {
        let mut metrics = self.metrics.write().await;
        *metrics = CircuitMetrics::default();
        
        let mut history = self.call_history.write().await;
        history.clear();
        
        info!("Circuit breaker '{}' reset to closed state", self.name);
    }

    /// Force circuit breaker to open state
    pub async fn force_open(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.state = CircuitState::Open;
        metrics.state_transition_time = Instant::now();
        
        warn!("Circuit breaker '{}' forced to open state", self.name);
    }

    /// Force circuit breaker to closed state
    pub async fn force_close(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.state = CircuitState::Closed;
        metrics.state_transition_time = Instant::now();
        metrics.consecutive_failures = 0;
        
        info!("Circuit breaker '{}' forced to closed state", self.name);
    }
}

/// Circuit breaker health status
#[derive(Debug, Serialize)]
pub struct CircuitHealthStatus {
    pub name: String,
    pub state: CircuitState,
    pub health_score: f64, // 0.0 to 1.0
    pub recent_calls: usize,
    pub recent_failures: usize,
    pub recent_slow_calls: usize,
    pub uptime_percentage: f64,
    pub last_failure: Option<SystemTime>,
}

/// Circuit breaker registry for managing multiple circuit breakers
pub struct CircuitBreakerRegistry {
    breakers: Arc<RwLock<HashMap<String, Arc<AdvancedCircuitBreaker>>>>,
}

impl CircuitBreakerRegistry {
    pub fn new() -> Self {
        Self {
            breakers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new circuit breaker
    pub async fn register(&self, name: String, config: CircuitBreakerConfig) -> Arc<AdvancedCircuitBreaker> {
        let breaker = Arc::new(AdvancedCircuitBreaker::new(name.clone(), config));
        let mut breakers = self.breakers.write().await;
        breakers.insert(name, breaker.clone());
        breaker
    }

    /// Get a circuit breaker by name
    pub async fn get(&self, name: &str) -> Option<Arc<AdvancedCircuitBreaker>> {
        let breakers = self.breakers.read().await;
        breakers.get(name).cloned()
    }

    /// Get all circuit breaker health statuses
    pub async fn get_all_health_statuses(&self) -> Vec<CircuitHealthStatus> {
        let breakers = self.breakers.read().await;
        let mut statuses = Vec::new();
        
        for breaker in breakers.values() {
            statuses.push(breaker.get_health_status().await);
        }
        
        statuses
    }

    /// Get overall system health based on all circuit breakers
    pub async fn get_system_health(&self) -> SystemHealthStatus {
        let statuses = self.get_all_health_statuses().await;
        
        if statuses.is_empty() {
            return SystemHealthStatus {
                overall_health: 1.0,
                healthy_circuits: 0,
                degraded_circuits: 0,
                failed_circuits: 0,
                total_circuits: 0,
            };
        }

        let healthy = statuses.iter().filter(|s| s.health_score > 0.8 && s.state == CircuitState::Closed).count();
        let degraded = statuses.iter().filter(|s| s.health_score > 0.5 && s.health_score <= 0.8).count();
        let failed = statuses.iter().filter(|s| s.health_score <= 0.5 || s.state == CircuitState::Open).count();
        
        let overall_health = statuses.iter().map(|s| s.health_score).sum::<f64>() / statuses.len() as f64;

        SystemHealthStatus {
            overall_health,
            healthy_circuits: healthy,
            degraded_circuits: degraded,
            failed_circuits: failed,
            total_circuits: statuses.len(),
        }
    }
}

/// System-wide health status
#[derive(Debug, Serialize)]
pub struct SystemHealthStatus {
    pub overall_health: f64,
    pub healthy_circuits: usize,
    pub degraded_circuits: usize,
    pub failed_circuits: usize,
    pub total_circuits: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_circuit_breaker_closed_state() {
        let config = CircuitBreakerConfig::default();
        let breaker = AdvancedCircuitBreaker::new("test".to_string(), config);

        // Successful call should work
        let result = breaker.call(|| async { Ok::<i32, String>(42) }).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);

        let metrics = breaker.get_metrics().await;
        assert_eq!(metrics.state, CircuitState::Closed);
        assert_eq!(metrics.successful_calls, 1);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let mut config = CircuitBreakerConfig::default();
        config.failure_threshold = 2; // Open after 2 failures
        
        let breaker = AdvancedCircuitBreaker::new("test".to_string(), config);

        // First failure
        let result = breaker.call(|| async { Err::<i32, String>("error".to_string()) }).await;
        assert!(result.is_err());

        // Second failure should open the circuit
        let result = breaker.call(|| async { Err::<i32, String>("error".to_string()) }).await;
        assert!(result.is_err());

        let metrics = breaker.get_metrics().await;
        assert_eq!(metrics.state, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_recovery() {
        let mut config = CircuitBreakerConfig::default();
        config.failure_threshold = 1;
        config.recovery_timeout = Duration::from_millis(100);
        config.success_threshold = 1;
        
        let breaker = AdvancedCircuitBreaker::new("test".to_string(), config);

        // Cause failure to open circuit
        let _ = breaker.call(|| async { Err::<i32, String>("error".to_string()) }).await;
        
        let metrics = breaker.get_metrics().await;
        assert_eq!(metrics.state, CircuitState::Open);

        // Wait for recovery timeout
        sleep(Duration::from_millis(150)).await;

        // Next call should transition to half-open
        let result = breaker.call(|| async { Ok::<i32, String>(42) }).await;
        assert!(result.is_ok());

        let metrics = breaker.get_metrics().await;
        assert_eq!(metrics.state, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_registry() {
        let registry = CircuitBreakerRegistry::new();
        
        let config = CircuitBreakerConfig::default();
        let breaker = registry.register("test-service".to_string(), config).await;
        
        // Test successful call
        let result = breaker.call(|| async { Ok::<String, String>("success".to_string()) }).await;
        assert!(result.is_ok());

        // Get breaker from registry
        let retrieved = registry.get("test-service").await;
        assert!(retrieved.is_some());

        // Check system health
        let health = registry.get_system_health().await;
        assert_eq!(health.total_circuits, 1);
        assert_eq!(health.healthy_circuits, 1);
    }

    #[tokio::test]
    async fn test_slow_call_detection() {
        let mut config = CircuitBreakerConfig::default();
        config.slow_call_threshold = Duration::from_millis(50);
        
        let breaker = AdvancedCircuitBreaker::new("test".to_string(), config);

        // Slow but successful call
        let result = breaker.call(|| async {
            sleep(Duration::from_millis(100)).await;
            Ok::<i32, String>(42)
        }).await;
        
        assert!(result.is_ok());
        
        let metrics = breaker.get_metrics().await;
        assert_eq!(metrics.slow_calls, 1);
        assert!(metrics.slow_call_rate > 0.0);
    }
}
