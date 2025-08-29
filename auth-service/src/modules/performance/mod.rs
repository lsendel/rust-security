//! Performance Optimization Module
//!
//! This module provides comprehensive performance optimization features including:
//! - Performance profiling and benchmarking
//! - Memory optimization and leak detection
//! - Concurrent processing improvements
//! - Database query optimization
//! - Caching strategies
//! - Algorithm optimizations
//! - Resource management improvements

pub mod profiler;
pub mod memory;
pub mod caching;
pub mod database;
pub mod concurrency;
pub mod algorithms;
pub mod monitoring;

// Re-export main performance types
pub use profiler::{PerformanceProfiler, BenchmarkResult, PerformanceMetrics};
pub use memory::{MemoryOptimizer, MemoryStats, LeakDetector};
pub use caching::{CacheManager, CacheConfig, CacheStats};
pub use database::{QueryOptimizer, ConnectionPool, DatabaseMetrics};
pub use concurrency::{ConcurrencyOptimizer, ThreadPool, AsyncExecutor};
pub use algorithms::{AlgorithmOptimizer, OptimizationResult};
pub use monitoring::{PerformanceMonitor, PerformanceAlert, ResourceStats};

/// Performance optimization traits
pub mod traits {
    use async_trait::async_trait;
    use std::fmt::Debug;

    /// Performance optimization service trait
    #[async_trait]
    pub trait PerformanceOptimizer: Send + Sync + Debug {
        /// Optimize system performance
        async fn optimize(&mut self) -> Result<OptimizationResult, Box<dyn std::error::Error + Send + Sync>>;

        /// Get current performance metrics
        async fn metrics(&self) -> Result<PerformanceMetrics, Box<dyn std::error::Error + Send + Sync>>;

        /// Check performance health
        async fn health_check(&self) -> PerformanceHealth;

        /// Reset performance counters
        async fn reset(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    }

    /// Performance health status
    #[derive(Debug, Clone, PartialEq)]
    pub enum PerformanceHealth {
        Optimal,
        Good,
        Degraded(String),
        Critical(String),
    }

    /// Performance metrics
    #[derive(Debug, Clone)]
    pub struct PerformanceMetrics {
        pub response_time_ms: f64,
        pub throughput_ops_per_sec: f64,
        pub memory_usage_mb: f64,
        pub cpu_usage_percent: f64,
        pub error_rate_percent: f64,
        pub active_connections: u64,
        pub cache_hit_rate_percent: f64,
        pub timestamp: chrono::DateTime<chrono::Utc>,
    }

    /// Optimization result
    #[derive(Debug, Clone)]
    pub struct OptimizationResult {
        pub optimizations_applied: Vec<String>,
        pub performance_improvement_percent: f64,
        pub recommendations: Vec<String>,
        pub timestamp: chrono::DateTime<chrono::Utc>,
    }
}

/// Performance constants and thresholds
pub mod constants {
    use std::time::Duration;

    /// Performance thresholds
    pub const MAX_RESPONSE_TIME_MS: u64 = 1000; // 1 second
    pub const MAX_MEMORY_USAGE_MB: u64 = 1024; // 1GB
    pub const MAX_CPU_USAGE_PERCENT: u8 = 80;
    pub const MIN_CACHE_HIT_RATE_PERCENT: u8 = 70;
    pub const MAX_ERROR_RATE_PERCENT: f64 = 5.0;

    /// Optimization intervals
    pub const PROFILING_INTERVAL_SECS: u64 = 60;
    pub const OPTIMIZATION_INTERVAL_SECS: u64 = 300; // 5 minutes
    pub const METRICS_COLLECTION_INTERVAL_SECS: u64 = 30;

    /// Resource limits
    pub const MAX_CONNECTIONS: u32 = 1000;
    pub const MAX_THREADS: u32 = 50;
    pub const MAX_CACHE_SIZE_MB: u64 = 512;
    pub const MAX_QUERY_TIMEOUT_SECS: u64 = 30;

    /// Performance targets
    pub const TARGET_RESPONSE_TIME_MS: u64 = 100;
    pub const TARGET_THROUGHPUT_OPS_PER_SEC: u64 = 1000;
    pub const TARGET_CACHE_HIT_RATE_PERCENT: u8 = 90;
}

/// Performance utilities and helpers
pub mod utils {
    use super::constants::*;
    use super::traits::*;
    use chrono::{DateTime, Utc};
    use std::time::{Duration, Instant};

    /// Measure execution time with high precision
    pub fn measure_execution_time<F, R>(f: F) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        (result, duration)
    }

    /// Measure async execution time
    pub async fn measure_async_execution_time<F, Fut, R>(f: F) -> (R, Duration)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        let start = Instant::now();
        let result = f().await;
        let duration = start.elapsed();
        (result, duration)
    }

    /// Performance assertion helpers
    pub mod assertions {
        use super::*;

        /// Assert that execution time is within acceptable limits
        pub fn assert_performance_within_limit(duration: Duration, limit_ms: u64) -> bool {
            duration.as_millis() <= limit_ms as u128
        }

        /// Assert that execution time meets target performance
        pub fn assert_meets_performance_target(duration: Duration, target_ms: u64) -> bool {
            duration.as_millis() <= target_ms as u128
        }

        /// Assert that throughput meets requirements
        pub fn assert_throughput_requirement(ops_per_sec: u64, min_ops_per_sec: u64) -> bool {
            ops_per_sec >= min_ops_per_sec
        }

        /// Assert that memory usage is within limits
        pub fn assert_memory_within_limit(usage_mb: u64, max_mb: u64) -> bool {
            usage_mb <= max_mb
        }

        /// Assert that cache hit rate meets requirements
        pub fn assert_cache_hit_rate(hit_rate_percent: f64, min_percent: u8) -> bool {
            hit_rate_percent >= min_percent as f64
        }

        /// Assert that error rate is within acceptable limits
        pub fn assert_error_rate_acceptable(error_rate_percent: f64, max_percent: f64) -> bool {
            error_rate_percent <= max_percent
        }
    }

    /// Performance calculation helpers
    pub mod calculations {
        use super::*;

        /// Calculate throughput (operations per second)
        pub fn calculate_throughput(operations: u64, duration: Duration) -> f64 {
            operations as f64 / duration.as_secs_f64()
        }

        /// Calculate latency (milliseconds)
        pub fn calculate_latency(duration: Duration) -> f64 {
            duration.as_millis() as f64
        }

        /// Calculate cache hit rate percentage
        pub fn calculate_cache_hit_rate(hits: u64, total_requests: u64) -> f64 {
            if total_requests == 0 {
                0.0
            } else {
                (hits as f64 / total_requests as f64) * 100.0
            }
        }

        /// Calculate error rate percentage
        pub fn calculate_error_rate(errors: u64, total_operations: u64) -> f64 {
            if total_operations == 0 {
                0.0
            } else {
                (errors as f64 / total_operations as f64) * 100.0
            }
        }

        /// Calculate memory usage percentage
        pub fn calculate_memory_usage_percentage(used_mb: u64, total_mb: u64) -> f64 {
            if total_mb == 0 {
                0.0
            } else {
                (used_mb as f64 / total_mb as f64) * 100.0
            }
        }

        /// Calculate performance improvement percentage
        pub fn calculate_improvement_percent(before: Duration, after: Duration) -> f64 {
            if before.as_millis() == 0 {
                0.0
            } else {
                ((before.as_millis() as f64 - after.as_millis() as f64) / before.as_millis() as f64) * 100.0
            }
        }
    }

    /// Performance monitoring helpers
    pub mod monitoring {
        use super::*;
        use std::collections::VecDeque;

        /// Sliding window for performance metrics
        pub struct SlidingWindow<T> {
            window: VecDeque<T>,
            max_size: usize,
        }

        impl<T> SlidingWindow<T> {
            pub fn new(max_size: usize) -> Self {
                Self {
                    window: VecDeque::with_capacity(max_size),
                    max_size,
                }
            }

            pub fn push(&mut self, value: T) {
                if self.window.len() >= self.max_size {
                    self.window.pop_front();
                }
                self.window.push_back(value);
            }

            pub fn average<F>(&self, extractor: F) -> Option<f64>
            where
                F: Fn(&T) -> f64,
            {
                if self.window.is_empty() {
                    return None;
                }

                let sum: f64 = self.window.iter().map(&extractor).sum();
                Some(sum / self.window.len() as f64)
            }

            pub fn latest(&self) -> Option<&T> {
                self.window.back()
            }

            pub fn len(&self) -> usize {
                self.window.len()
            }

            pub fn clear(&mut self) {
                self.window.clear();
            }
        }

        /// Performance trend analysis
        pub struct TrendAnalyzer {
            response_times: SlidingWindow<f64>,
            throughput_values: SlidingWindow<f64>,
            error_rates: SlidingWindow<f64>,
        }

        impl TrendAnalyzer {
            pub fn new(window_size: usize) -> Self {
                Self {
                    response_times: SlidingWindow::new(window_size),
                    throughput_values: SlidingWindow::new(window_size),
                    error_rates: SlidingWindow::new(window_size),
                }
            }

            pub fn record_metrics(&mut self, metrics: &PerformanceMetrics) {
                self.response_times.push(metrics.response_time_ms);
                self.throughput_values.push(metrics.throughput_ops_per_sec);
                self.error_rates.push(metrics.error_rate_percent);
            }

            pub fn analyze_trends(&self) -> TrendAnalysis {
                TrendAnalysis {
                    avg_response_time: self.response_times.average(|&x| x),
                    avg_throughput: self.throughput_values.average(|&x| x),
                    avg_error_rate: self.error_rates.average(|&x| x),
                    response_time_trend: self.analyze_trend(&self.response_times),
                    throughput_trend: self.analyze_trend(&self.throughput_values),
                    error_rate_trend: self.analyze_trend(&self.error_rates),
                }
            }

            fn analyze_trend(&self, window: &SlidingWindow<f64>) -> TrendDirection {
                if window.len() < 2 {
                    return TrendDirection::Stable;
                }

                let first_half_avg = window.window.iter().take(window.len() / 2).sum::<f64>() / (window.len() / 2) as f64;
                let second_half_avg = window.window.iter().skip(window.len() / 2).sum::<f64>() / (window.len() - window.len() / 2) as f64;

                let threshold = 0.05; // 5% change threshold
                let change_percent = (second_half_avg - first_half_avg) / first_half_avg;

                if change_percent > threshold {
                    TrendDirection::Increasing
                } else if change_percent < -threshold {
                    TrendDirection::Decreasing
                } else {
                    TrendDirection::Stable
                }
            }
        }

        /// Trend analysis result
        #[derive(Debug, Clone)]
        pub struct TrendAnalysis {
            pub avg_response_time: Option<f64>,
            pub avg_throughput: Option<f64>,
            pub avg_error_rate: Option<f64>,
            pub response_time_trend: TrendDirection,
            pub throughput_trend: TrendDirection,
            pub error_rate_trend: TrendDirection,
        }

        /// Trend direction
        #[derive(Debug, Clone, PartialEq)]
        pub enum TrendDirection {
            Increasing,
            Decreasing,
            Stable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measure_execution_time() {
        let (result, duration) = utils::measure_execution_time(|| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            42
        });

        assert_eq!(result, 42);
        assert!(duration.as_millis() >= 10);
    }

    #[test]
    fn test_performance_assertions() {
        use utils::assertions::*;

        assert!(assert_performance_within_limit(std::time::Duration::from_millis(50), 100));
        assert!(!assert_performance_within_limit(std::time::Duration::from_millis(150), 100));
    }

    #[test]
    fn test_performance_calculations() {
        use utils::calculations::*;

        let throughput = calculate_throughput(100, std::time::Duration::from_secs(10));
        assert!((throughput - 10.0).abs() < f64::EPSILON);

        let latency = calculate_latency(std::time::Duration::from_millis(50));
        assert!((latency - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sliding_window() {
        use utils::monitoring::SlidingWindow;

        let mut window = SlidingWindow::new(3);

        window.push(1.0);
        window.push(2.0);
        window.push(3.0);
        window.push(4.0); // Should remove 1.0

        assert_eq!(window.len(), 3);
        assert_eq!(window.average(|&x| x), Some(3.0)); // (2+3+4)/3
    }
}
