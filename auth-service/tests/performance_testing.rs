//! Performance Testing Framework
//!
//! This module provides comprehensive performance testing capabilities including:
//! - Load testing with configurable concurrency
//! - Performance regression detection
//! - Memory usage monitoring
//! - Throughput and latency measurements
//! - Statistical analysis of performance metrics

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::timeout;

/// Performance test configuration
#[derive(Debug, Clone)]
pub struct PerformanceTestConfig {
    /// Number of concurrent operations
    pub concurrency: usize,
    /// Total number of operations to perform
    pub total_operations: usize,
    /// Test duration limit
    pub duration_limit: Duration,
    /// Warm-up duration before measurements
    pub warm_up_duration: Duration,
    /// Memory monitoring enabled
    pub monitor_memory: bool,
    /// CPU monitoring enabled
    pub monitor_cpu: bool,
}

impl Default for PerformanceTestConfig {
    fn default() -> Self {
        Self {
            concurrency: 10,
            total_operations: 1000,
            duration_limit: Duration::from_secs(300), // 5 minutes
            warm_up_duration: Duration::from_secs(5),
            monitor_memory: true,
            monitor_cpu: false,
        }
    }
}

/// Performance metrics collected during testing
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Total operations completed
    pub operations_completed: usize,
    /// Total test duration
    pub total_duration: Duration,
    /// Operations per second
    pub throughput: f64,
    /// Average latency per operation
    pub avg_latency: Duration,
    /// 95th percentile latency
    pub p95_latency: Duration,
    /// 99th percentile latency
    pub p99_latency: Duration,
    /// Minimum latency
    pub min_latency: Duration,
    /// Maximum latency
    pub max_latency: Duration,
    /// Memory usage in bytes (if monitored)
    pub memory_usage: Option<u64>,
    /// CPU usage percentage (if monitored)
    pub cpu_usage: Option<f64>,
    /// Error count
    pub error_count: usize,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            operations_completed: 0,
            total_duration: Duration::default(),
            throughput: 0.0,
            avg_latency: Duration::default(),
            p95_latency: Duration::default(),
            p99_latency: Duration::default(),
            min_latency: Duration::default(),
            max_latency: Duration::default(),
            memory_usage: None,
            cpu_usage: None,
            error_count: 0,
        }
    }
}

/// Load test runner for executing performance tests
pub struct LoadTestRunner<T> {
    config: PerformanceTestConfig,
    operation: Arc<dyn Fn() -> T + Send + Sync>,
}

impl<T> LoadTestRunner<T>
where
    T: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>
        + Send
        + 'static,
{
    /// Create a new load test runner
    pub fn new<F>(config: PerformanceTestConfig, operation: F) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        Self {
            config,
            operation: Arc::new(operation),
        }
    }

    /// Execute the load test
    pub async fn execute(
        &self,
    ) -> Result<PerformanceMetrics, Box<dyn std::error::Error + Send + Sync>> {
        println!(
            "🚀 Starting performance test with {} concurrent operations",
            self.config.concurrency
        );

        // Warm-up phase
        println!("🔥 Warming up for {:?}", self.config.warm_up_duration);
        tokio::time::sleep(self.config.warm_up_duration).await;

        // Execute load test
        let start_time = Instant::now();
        let mut handles = Vec::new();
        let metrics = Arc::new(RwLock::new(PerformanceMetrics::default()));
        let operation_count = Arc::new(RwLock::new(0usize));

        // Spawn worker tasks
        for worker_id in 0..self.config.concurrency {
            let operation = Arc::clone(&self.operation);
            let metrics_clone = Arc::clone(&metrics);
            let op_count_clone = Arc::clone(&operation_count);
            let config = self.config.clone();

            let handle = tokio::spawn(async move {
                let mut latencies = Vec::new();
                let mut errors = 0;

                loop {
                    // Check if we've reached the operation limit
                    {
                        let current_count = *op_count_clone.read().await;
                        if current_count >= config.total_operations {
                            break;
                        }
                    }

                    let op_start = Instant::now();
                    let result = timeout(Duration::from_secs(30), operation()).await;

                    match result {
                        Ok(Ok(_)) => {
                            let latency = op_start.elapsed();
                            latencies.push(latency);

                            // Increment operation count
                            {
                                let mut count = op_count_clone.write().await;
                                *count += 1;
                            }
                        }
                        _ => {
                            errors += 1;
                        }
                    }

                    // Small delay to prevent overwhelming the system
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }

                // Update metrics for this worker
                let mut metrics = metrics_clone.write().await;
                metrics.operations_completed += latencies.len();
                metrics.error_count += errors;

                if !latencies.is_empty() {
                    // Calculate latency statistics
                    latencies.sort();
                    let total_latency: Duration = latencies.iter().sum();
                    metrics.avg_latency = total_latency / latencies.len() as u32;
                    metrics.min_latency = *latencies.first().unwrap();
                    metrics.max_latency = *latencies.last().unwrap();

                    let p95_index = (latencies.len() as f64 * 0.95) as usize;
                    let p99_index = (latencies.len() as f64 * 0.99) as usize;

                    metrics.p95_latency = latencies
                        .get(p95_index)
                        .copied()
                        .unwrap_or(metrics.max_latency);
                    metrics.p99_latency = latencies
                        .get(p99_index)
                        .copied()
                        .unwrap_or(metrics.max_latency);
                }

                println!(
                    "Worker {} completed: {} operations, {} errors",
                    worker_id,
                    latencies.len(),
                    errors
                );
            });

            handles.push(handle);
        }

        // Wait for all workers to complete or timeout
        let test_result = timeout(self.config.duration_limit, async {
            for handle in handles {
                let _ = handle.await;
            }
        })
        .await;

        let total_duration = start_time.elapsed();

        // Finalize metrics
        let mut final_metrics = metrics.write().await.clone();
        final_metrics.total_duration = total_duration;
        final_metrics.throughput =
            final_metrics.operations_completed as f64 / total_duration.as_secs_f64();

        // Memory monitoring
        if self.config.monitor_memory {
            if let Ok(usage) = get_memory_usage() {
                final_metrics.memory_usage = Some(usage);
            }
        }

        // CPU monitoring
        if self.config.monitor_cpu {
            if let Ok(usage) = get_cpu_usage() {
                final_metrics.cpu_usage = Some(usage);
            }
        }

        match test_result {
            Ok(_) => println!("✅ Load test completed successfully"),
            Err(_) => println!(
                "⚠️  Load test timed out after {:?}",
                self.config.duration_limit
            ),
        }

        println!("📊 Performance Results:");
        println!(
            "  Operations completed: {}",
            final_metrics.operations_completed
        );
        println!("  Total duration: {:?}", final_metrics.total_duration);
        println!("  Throughput: {:.2} ops/sec", final_metrics.throughput);
        println!("  Average latency: {:?}", final_metrics.avg_latency);
        println!("  95th percentile: {:?}", final_metrics.p95_latency);
        println!("  99th percentile: {:?}", final_metrics.p99_latency);
        println!("  Errors: {}", final_metrics.error_count);

        Ok(final_metrics)
    }
}

/// Performance regression detector
pub struct PerformanceRegressionDetector {
    baseline_metrics: HashMap<String, PerformanceMetrics>,
    regression_threshold: f64, // Percentage threshold for regression detection
}

impl PerformanceRegressionDetector {
    /// Create a new regression detector
    pub fn new(regression_threshold: f64) -> Self {
        Self {
            baseline_metrics: HashMap::new(),
            regression_threshold,
        }
    }

    /// Set baseline metrics for a test
    pub fn set_baseline(&mut self, test_name: &str, metrics: PerformanceMetrics) {
        self.baseline_metrics.insert(test_name.to_string(), metrics);
    }

    /// Check for performance regression
    pub fn check_regression(
        &self,
        test_name: &str,
        current_metrics: &PerformanceMetrics,
    ) -> RegressionResult {
        if let Some(baseline) = self.baseline_metrics.get(test_name) {
            let throughput_regression =
                (baseline.throughput - current_metrics.throughput) / baseline.throughput * 100.0;
            let latency_regression = (current_metrics.avg_latency.as_millis() as f64
                - baseline.avg_latency.as_millis() as f64)
                / baseline.avg_latency.as_millis() as f64
                * 100.0;

            let has_regression = throughput_regression > self.regression_threshold
                || latency_regression > self.regression_threshold;

            RegressionResult {
                has_regression,
                throughput_regression,
                latency_regression,
                baseline_throughput: baseline.throughput,
                current_throughput: current_metrics.throughput,
                baseline_latency: baseline.avg_latency,
                current_latency: current_metrics.avg_latency,
            }
        } else {
            RegressionResult::default()
        }
    }
}

/// Result of regression analysis
#[derive(Debug, Clone)]
pub struct RegressionResult {
    pub has_regression: bool,
    pub throughput_regression: f64,
    pub latency_regression: f64,
    pub baseline_throughput: f64,
    pub current_throughput: f64,
    pub baseline_latency: Duration,
    pub current_latency: Duration,
}

impl Default for RegressionResult {
    fn default() -> Self {
        Self {
            has_regression: false,
            throughput_regression: 0.0,
            latency_regression: 0.0,
            baseline_throughput: 0.0,
            current_throughput: 0.0,
            baseline_latency: Duration::default(),
            current_latency: Duration::default(),
        }
    }
}

/// Memory usage monitoring (simplified)
fn get_memory_usage() -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    // Simplified memory monitoring - in a real implementation,
    // you would use platform-specific APIs or external crates
    Ok(0) // Placeholder
}

/// CPU usage monitoring (basic implementation)
fn get_cpu_usage() -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    // Simplified CPU usage - in a real implementation, you'd track
    // process CPU time over intervals
    Ok(0.0) // Placeholder
}

/// Performance test utilities
pub mod utils {
    use super::*;
    use std::fmt;

    /// Format duration in human-readable format
    pub fn format_duration(duration: Duration) -> String {
        if duration.as_millis() < 1000 {
            format!("{}ms", duration.as_millis())
        } else if duration.as_secs() < 60 {
            format!("{:.2}s", duration.as_secs_f64())
        } else if duration.as_secs() < 3600 {
            format!("{}m {}s", duration.as_secs() / 60, duration.as_secs() % 60)
        } else {
            format!(
                "{}h {}m",
                duration.as_secs() / 3600,
                (duration.as_secs() % 3600) / 60
            )
        }
    }

    /// Format throughput in human-readable format
    pub fn format_throughput(ops_per_sec: f64) -> String {
        if ops_per_sec < 1000.0 {
            format!("{:.1} ops/sec", ops_per_sec)
        } else if ops_per_sec < 1_000_000.0 {
            format!("{:.1}K ops/sec", ops_per_sec / 1000.0)
        } else {
            format!("{:.1}M ops/sec", ops_per_sec / 1_000_000.0)
        }
    }

    /// Generate performance test report
    pub fn generate_report(
        test_name: &str,
        config: &PerformanceTestConfig,
        metrics: &PerformanceMetrics,
    ) -> String {
        format!(
            r#"# Performance Test Report: {}

## Configuration
- Concurrency: {}
- Total Operations: {}
- Duration Limit: {}
- Memory Monitoring: {}
- CPU Monitoring: {}

## Results
- Operations Completed: {}
- Total Duration: {}
- Throughput: {}
- Average Latency: {}
- 95th Percentile Latency: {}
- 99th Percentile Latency: {}
- Min Latency: {}
- Max Latency: {}
- Errors: {}

## System Metrics
{}
{}
"#,
            test_name,
            config.concurrency,
            config.total_operations,
            format_duration(config.duration_limit),
            if config.monitor_memory {
                "✅ Enabled"
            } else {
                "❌ Disabled"
            },
            if config.monitor_cpu {
                "✅ Enabled"
            } else {
                "❌ Disabled"
            },
            metrics.operations_completed,
            format_duration(metrics.total_duration),
            format_throughput(metrics.throughput),
            format_duration(metrics.avg_latency),
            format_duration(metrics.p95_latency),
            format_duration(metrics.p99_latency),
            format_duration(metrics.min_latency),
            format_duration(metrics.max_latency),
            metrics.error_count,
            metrics.memory_usage.map_or(
                "Memory Usage: Not monitored".to_string(),
                |usage| format!("Memory Usage: {} MB", usage / 1_000_000)
            ),
            metrics
                .cpu_usage
                .map_or("CPU Usage: Not monitored".to_string(), |usage| format!(
                    "CPU Usage: {:.1}%",
                    usage
                ))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_load_test_basic() {
        let counter = Arc::new(AtomicUsize::new(0));

        let config = PerformanceTestConfig {
            concurrency: 2,
            total_operations: 10,
            duration_limit: Duration::from_secs(10),
            warm_up_duration: Duration::from_millis(100),
            monitor_memory: false,
            monitor_cpu: false,
        };

        let counter_clone = Arc::clone(&counter);
        let runner = LoadTestRunner::new(config, move || {
            let counter = Arc::clone(&counter_clone);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(())
            }
        });

        let metrics = runner.execute().await.unwrap();

        assert!(metrics.operations_completed >= 10);
        assert!(metrics.throughput > 0.0);
        assert!(metrics.error_count == 0);
    }

    #[tokio::test]
    async fn test_regression_detector() {
        let mut detector = PerformanceRegressionDetector::new(10.0); // 10% threshold

        let baseline = PerformanceMetrics {
            operations_completed: 1000,
            total_duration: Duration::from_secs(10),
            throughput: 100.0,
            avg_latency: Duration::from_millis(100),
            ..Default::default()
        };

        detector.set_baseline("test_operation", baseline.clone());

        // Test with no regression
        let current = PerformanceMetrics {
            operations_completed: 1000,
            total_duration: Duration::from_secs(10),
            throughput: 95.0, // 5% decrease (within threshold)
            avg_latency: Duration::from_millis(105), // 5% increase (within threshold)
            ..Default::default()
        };

        let result = detector.check_regression("test_operation", &current);
        assert!(!result.has_regression);

        // Test with regression
        let current_regression = PerformanceMetrics {
            operations_completed: 1000,
            total_duration: Duration::from_secs(10),
            throughput: 85.0, // 15% decrease (above threshold)
            avg_latency: Duration::from_millis(120), // 20% increase (above threshold)
            ..Default::default()
        };

        let result_regression = detector.check_regression("test_operation", &current_regression);
        assert!(result_regression.has_regression);
    }

    #[test]
    fn test_performance_formatting() {
        assert_eq!(utils::format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(utils::format_duration(Duration::from_secs(30)), "30.00s");
        assert_eq!(utils::format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(utils::format_duration(Duration::from_secs(3660)), "1h 1m");

        assert_eq!(utils::format_throughput(500.0), "500.0 ops/sec");
        assert_eq!(utils::format_throughput(1500.0), "1.5K ops/sec");
        assert_eq!(utils::format_throughput(1_500_000.0), "1.5M ops/sec");
    }
}
