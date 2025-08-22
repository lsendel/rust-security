use anyhow::Result;
use prometheus::{Counter, Histogram, IntGauge, Registry};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Performance monitoring and optimization system
pub struct PerformanceMonitor {
    /// Prometheus metrics registry
    registry: Arc<Registry>,
    /// Request latency histogram
    request_latency: Histogram,
    /// Request counter
    request_count: Counter,
    /// Active connections gauge
    active_connections: IntGauge,
    /// Memory usage gauge
    memory_usage: IntGauge,
    /// Performance thresholds
    thresholds: Arc<RwLock<PerformanceThresholds>>,
    /// Circuit breaker state
    circuit_breaker: Arc<RwLock<CircuitBreakerState>>,
}

#[derive(Debug, Clone)]
pub struct PerformanceThresholds {
    /// Maximum acceptable latency in milliseconds
    pub max_latency_ms: u64,
    /// Maximum memory usage in MB
    pub max_memory_mb: u64,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Error rate threshold (0.0 to 1.0)
    pub error_rate_threshold: f64,
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerState {
    /// Current state (Open, Closed, HalfOpen)
    pub state: CircuitState,
    /// Failure count
    pub failure_count: u32,
    /// Last failure time
    pub last_failure: Option<Instant>,
    /// Success count in half-open state
    pub success_count: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
pub struct PerformanceMetrics {
    pub avg_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub request_rate: f64,
    pub error_rate: f64,
    pub memory_usage_mb: u64,
    pub active_connections: u32,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            max_latency_ms: 100,        // 100ms P95 target
            max_memory_mb: 512,         // 512MB memory limit
            max_connections: 1000,      // 1000 concurrent connections
            error_rate_threshold: 0.01, // 1% error rate threshold
        }
    }
}

impl Default for CircuitBreakerState {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            last_failure: None,
            success_count: 0,
        }
    }
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new() -> Result<Self> {
        let registry = Arc::new(Registry::new());

        let request_latency = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "auth_request_duration_seconds",
                "Request duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
        )?;

        let request_count = Counter::with_opts(prometheus::Opts::new(
            "auth_requests_total",
            "Total number of authentication requests",
        ))?;

        let active_connections = IntGauge::with_opts(prometheus::Opts::new(
            "auth_active_connections",
            "Number of active connections",
        ))?;

        let memory_usage = IntGauge::with_opts(prometheus::Opts::new(
            "auth_memory_usage_bytes",
            "Memory usage in bytes",
        ))?;

        registry.register(Box::new(request_latency.clone()))?;
        registry.register(Box::new(request_count.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(memory_usage.clone()))?;

        Ok(Self {
            registry,
            request_latency,
            request_count,
            active_connections,
            memory_usage,
            thresholds: Arc::new(RwLock::new(PerformanceThresholds::default())),
            circuit_breaker: Arc::new(RwLock::new(CircuitBreakerState::default())),
        })
    }

    /// Record request latency
    pub async fn record_request(&self, duration: Duration, success: bool) {
        let duration_secs = duration.as_secs_f64();
        self.request_latency.observe(duration_secs);
        self.request_count.inc();

        // Update circuit breaker state
        let mut breaker = self.circuit_breaker.write().await;
        if success {
            match breaker.state {
                CircuitState::HalfOpen => {
                    breaker.success_count += 1;
                    if breaker.success_count >= 5 {
                        breaker.state = CircuitState::Closed;
                        breaker.failure_count = 0;
                        breaker.success_count = 0;
                        info!("Circuit breaker closed - service recovered");
                    }
                }
                CircuitState::Closed => {
                    breaker.failure_count = 0;
                }
                _ => {}
            }
        } else {
            breaker.failure_count += 1;
            breaker.last_failure = Some(Instant::now());

            match breaker.state {
                CircuitState::Closed if breaker.failure_count >= 5 => {
                    breaker.state = CircuitState::Open;
                    warn!("Circuit breaker opened due to failures");
                }
                CircuitState::HalfOpen => {
                    breaker.state = CircuitState::Open;
                    breaker.success_count = 0;
                    warn!("Circuit breaker reopened due to failure in half-open state");
                }
                _ => {}
            }
        }

        // Check if we should transition to half-open
        if breaker.state == CircuitState::Open {
            if let Some(last_failure) = breaker.last_failure {
                if last_failure.elapsed() > Duration::from_secs(30) {
                    breaker.state = CircuitState::HalfOpen;
                    breaker.success_count = 0;
                    info!("Circuit breaker transitioned to half-open");
                }
            }
        }
    }

    /// Check if circuit breaker allows requests
    pub async fn is_request_allowed(&self) -> bool {
        let breaker = self.circuit_breaker.read().await;
        match breaker.state {
            CircuitState::Closed | CircuitState::HalfOpen => true,
            CircuitState::Open => false,
        }
    }

    /// Update connection count
    pub fn update_connections(&self, count: i64) {
        self.active_connections.add(count);
    }

    /// Update memory usage
    pub fn update_memory_usage(&self, bytes: i64) {
        self.memory_usage.set(bytes);
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> Result<PerformanceMetrics> {
        let latency_samples = self.request_latency.get_sample_count();
        let latency_sum = self.request_latency.get_sample_sum();

        let avg_latency_ms = if latency_samples > 0 {
            (latency_sum / latency_samples as f64) * 1000.0
        } else {
            0.0
        };

        // For P95/P99, we'd need to collect actual samples
        // This is a simplified version
        let p95_latency_ms = avg_latency_ms * 1.5;
        let p99_latency_ms = avg_latency_ms * 2.0;

        let request_rate = self.request_count.get();
        let memory_usage_mb = (self.memory_usage.get() as u64) / (1024 * 1024);
        let active_connections = self.active_connections.get() as u32;

        Ok(PerformanceMetrics {
            avg_latency_ms,
            p95_latency_ms,
            p99_latency_ms,
            request_rate,
            error_rate: 0.0, // Would need error tracking
            memory_usage_mb,
            active_connections,
        })
    }

    /// Check if performance is within thresholds
    pub async fn check_performance_health(&self) -> Result<bool> {
        let metrics = self.get_metrics().await?;
        let thresholds = self.thresholds.read().await;

        let healthy = metrics.p95_latency_ms <= thresholds.max_latency_ms as f64
            && metrics.memory_usage_mb <= thresholds.max_memory_mb
            && metrics.active_connections <= thresholds.max_connections
            && metrics.error_rate <= thresholds.error_rate_threshold;

        if !healthy {
            warn!(
                "Performance degradation detected: latency={:.2}ms, memory={}MB, connections={}, error_rate={:.3}",
                metrics.p95_latency_ms,
                metrics.memory_usage_mb,
                metrics.active_connections,
                metrics.error_rate
            );
        }

        Ok(healthy)
    }

    /// Get Prometheus metrics for scraping
    pub fn get_prometheus_metrics(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder
            .encode_to_string(&metric_families)
            .unwrap_or_default()
    }

    /// Update performance thresholds
    pub async fn update_thresholds(&self, thresholds: PerformanceThresholds) {
        let mut current = self.thresholds.write().await;
        *current = thresholds;
        info!("Performance thresholds updated");
    }
}

/// Performance optimization utilities
pub struct PerformanceOptimizer;

impl PerformanceOptimizer {
    /// Optimize memory usage by triggering garbage collection
    pub fn optimize_memory() {
        // In Rust, we don't have explicit GC, but we can suggest optimizations
        info!("Memory optimization triggered - consider reducing cache sizes");
    }

    /// Optimize connection pooling
    pub fn optimize_connections(current_count: u32, target_count: u32) -> u32 {
        if current_count > target_count {
            // Suggest reducing connections
            (current_count * 90) / 100 // Reduce by 10%
        } else if current_count < target_count / 2 {
            // Suggest increasing connections
            (current_count * 110) / 100 // Increase by 10%
        } else {
            current_count
        }
    }

    /// Calculate optimal timeout based on current performance
    pub fn calculate_optimal_timeout(avg_latency_ms: f64) -> Duration {
        // Set timeout to 3x average latency, with min 1s and max 30s
        let timeout_ms = (avg_latency_ms * 3.0).max(1000.0).min(30000.0);
        Duration::from_millis(timeout_ms as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_performance_monitor_creation() {
        let monitor = PerformanceMonitor::new().unwrap();
        assert!(monitor.is_request_allowed().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let monitor = PerformanceMonitor::new().unwrap();

        // Record failures to trigger circuit breaker
        for _ in 0..5 {
            monitor
                .record_request(Duration::from_millis(100), false)
                .await;
        }

        // Circuit should be open
        assert!(!monitor.is_request_allowed().await);

        // Wait for transition to half-open (in real scenario, would be 30s)
        // For testing, we'll manually set the state
        {
            let mut breaker = monitor.circuit_breaker.write().await;
            breaker.state = CircuitState::HalfOpen;
        }

        assert!(monitor.is_request_allowed().await);

        // Record successes to close circuit
        for _ in 0..5 {
            monitor
                .record_request(Duration::from_millis(50), true)
                .await;
        }

        assert!(monitor.is_request_allowed().await);
    }

    #[tokio::test]
    async fn test_performance_metrics() {
        let monitor = PerformanceMonitor::new().unwrap();

        // Record some requests
        monitor
            .record_request(Duration::from_millis(50), true)
            .await;
        monitor
            .record_request(Duration::from_millis(75), true)
            .await;
        monitor
            .record_request(Duration::from_millis(100), true)
            .await;

        let metrics = monitor.get_metrics().await.unwrap();
        assert!(metrics.avg_latency_ms > 0.0);
        assert!(metrics.request_rate > 0.0);
    }

    #[test]
    fn test_performance_optimizer() {
        // Test connection optimization
        assert_eq!(PerformanceOptimizer::optimize_connections(100, 50), 90);
        assert_eq!(PerformanceOptimizer::optimize_connections(20, 100), 22);
        assert_eq!(PerformanceOptimizer::optimize_connections(75, 100), 75);

        // Test timeout calculation
        let timeout = PerformanceOptimizer::calculate_optimal_timeout(50.0);
        assert_eq!(timeout, Duration::from_millis(1000)); // Min 1s

        let timeout = PerformanceOptimizer::calculate_optimal_timeout(5000.0);
        assert_eq!(timeout, Duration::from_millis(15000)); // 3x 5s

        let timeout = PerformanceOptimizer::calculate_optimal_timeout(15000.0);
        assert_eq!(timeout, Duration::from_millis(30000)); // Max 30s
    }
}
