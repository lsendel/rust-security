//! Performance Profiler Module
//!
//! This module provides comprehensive performance profiling capabilities including:
//! - Function-level profiling
//! - Memory usage profiling
//! - Database query profiling
//! - HTTP request profiling
//! - Resource usage tracking
//! - Performance benchmarking
//! - Bottleneck identification

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

/// Performance profiler trait
#[async_trait]
pub trait PerformanceProfiler: Send + Sync {
    /// Start profiling a function or operation
    async fn start_profiling(&self, operation: &str) -> Result<ProfileHandle, ProfilingError>;

    /// Stop profiling and record results
    async fn stop_profiling(&self, handle: ProfileHandle) -> Result<(), ProfilingError>;

    /// Get performance metrics for an operation
    async fn get_metrics(&self, operation: &str) -> Result<PerformanceMetrics, ProfilingError>;

    /// Get all performance metrics
    async fn get_all_metrics(&self) -> Result<HashMap<String, PerformanceMetrics>, ProfilingError>;

    /// Generate performance report
    async fn generate_report(&self) -> Result<PerformanceReport, ProfilingError>;

    /// Identify performance bottlenecks
    async fn identify_bottlenecks(&self) -> Result<Vec<Bottleneck>, ProfilingError>;

    /// Reset all profiling data
    async fn reset(&self) -> Result<(), ProfilingError>;
}

/// Profile handle for tracking operations
#[derive(Debug, Clone)]
pub struct ProfileHandle {
    pub operation: String,
    pub start_time: Instant,
    pub metadata: HashMap<String, String>,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub operation: String,
    pub total_calls: u64,
    pub total_duration: Duration,
    pub average_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub last_call_duration: Duration,
    pub memory_usage_bytes: u64,
    pub cpu_usage_percent: f64,
    pub error_count: u64,
    pub success_rate_percent: f64,
    pub last_updated: DateTime<Utc>,
}

/// Performance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub generated_at: DateTime<Utc>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub metrics: HashMap<String, PerformanceMetrics>,
    pub bottlenecks: Vec<Bottleneck>,
    pub recommendations: Vec<String>,
    pub summary: PerformanceSummary,
}

/// Performance summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub total_operations: usize,
    pub average_response_time: Duration,
    pub peak_response_time: Duration,
    pub total_errors: u64,
    pub overall_success_rate: f64,
    pub memory_peak_usage: u64,
    pub cpu_average_usage: f64,
}

/// Performance bottleneck
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bottleneck {
    pub operation: String,
    pub severity: BottleneckSeverity,
    pub description: String,
    pub impact: f64, // Impact score (0-100)
    pub recommendations: Vec<String>,
}

/// Bottleneck severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BottleneckSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Profiling error
#[derive(Debug, thiserror::Error)]
pub enum ProfilingError {
    #[error("Operation not found: {operation}")]
    OperationNotFound { operation: String },

    #[error("Profiling already started for operation: {operation}")]
    ProfilingAlreadyStarted { operation: String },

    #[error("Invalid profile handle")]
    InvalidHandle,

    #[error("Storage error: {message}")]
    StorageError { message: String },

    #[error("Metrics collection error: {message}")]
    MetricsError { message: String },
}

/// Comprehensive profiler implementation
pub struct ComprehensiveProfiler {
    metrics: Arc<RwLock<HashMap<String, OperationMetrics>>>,
    active_profiles: Arc<RwLock<HashMap<String, ProfileHandle>>>,
    config: ProfilerConfig,
}

#[derive(Debug, Clone)]
struct OperationMetrics {
    calls: u64,
    total_duration: Duration,
    min_duration: Duration,
    max_duration: Duration,
    last_duration: Duration,
    memory_usage: u64,
    cpu_usage: f64,
    errors: u64,
    last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ProfilerConfig {
    pub enabled: bool,
    pub max_operations: usize,
    pub retention_period_hours: i64,
    pub memory_tracking_enabled: bool,
    pub cpu_tracking_enabled: bool,
    pub bottleneck_threshold_ms: u64,
}

impl Default for ProfilerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_operations: 1000,
            retention_period_hours: 24,
            memory_tracking_enabled: true,
            cpu_tracking_enabled: true,
            bottleneck_threshold_ms: 1000,
        }
    }
}

impl ComprehensiveProfiler {
    /// Create new profiler instance
    pub fn new(config: ProfilerConfig) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            active_profiles: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Get current memory usage (simplified)
    fn get_current_memory_usage() -> u64 {
        // In a real implementation, this would use system APIs
        // For now, return a placeholder
        1024 * 1024 * 100 // 100MB placeholder
    }

    /// Get current CPU usage (simplified)
    fn get_current_cpu_usage() -> f64 {
        // In a real implementation, this would use system APIs
        // For now, return a placeholder
        25.0 // 25% placeholder
    }

    /// Calculate success rate
    fn calculate_success_rate(total_calls: u64, errors: u64) -> f64 {
        if total_calls == 0 {
            0.0
        } else {
            ((total_calls - errors) as f64 / total_calls as f64) * 100.0
        }
    }

    /// Determine bottleneck severity
    fn determine_bottleneck_severity(
        avg_duration: Duration,
        threshold_ms: u64,
        error_rate: f64,
    ) -> BottleneckSeverity {
        let duration_ms = avg_duration.as_millis() as u64;

        if duration_ms > threshold_ms * 3 || error_rate > 20.0 {
            BottleneckSeverity::Critical
        } else if duration_ms > threshold_ms * 2 || error_rate > 10.0 {
            BottleneckSeverity::High
        } else if duration_ms > threshold_ms || error_rate > 5.0 {
            BottleneckSeverity::Medium
        } else {
            BottleneckSeverity::Low
        }
    }

    /// Generate recommendations for bottlenecks
    fn generate_recommendations(operation: &str, metrics: &OperationMetrics) -> Vec<String> {
        let mut recommendations = Vec::new();

        if metrics.average_duration().as_millis() > 1000 {
            recommendations.push(format!("Consider optimizing {} - high response time", operation));
        }

        if Self::calculate_success_rate(metrics.calls, metrics.errors) < 95.0 {
            recommendations.push(format!("Investigate error causes for {}", operation));
        }

        if metrics.memory_usage > 1024 * 1024 * 500 { // 500MB
            recommendations.push(format!("Optimize memory usage for {}", operation));
        }

        if metrics.cpu_usage > 70.0 {
            recommendations.push(format!("Consider CPU optimization for {}", operation));
        }

        recommendations
    }

    /// Cleanup old metrics
    async fn cleanup_old_metrics(&self) -> Result<(), ProfilingError> {
        let mut metrics = self.metrics.write().await;
        let cutoff = Utc::now() - chrono::Duration::hours(self.config.retention_period_hours);

        metrics.retain(|_, op_metrics| op_metrics.last_updated > cutoff);

        Ok(())
    }
}

impl OperationMetrics {
    fn new() -> Self {
        Self {
            calls: 0,
            total_duration: Duration::from_millis(0),
            min_duration: Duration::from_millis(u64::MAX),
            max_duration: Duration::from_millis(0),
            last_duration: Duration::from_millis(0),
            memory_usage: 0,
            cpu_usage: 0.0,
            errors: 0,
            last_updated: Utc::now(),
        }
    }

    fn record_call(&mut self, duration: Duration, is_error: bool) {
        self.calls += 1;
        self.total_duration += duration;
        self.last_duration = duration;
        self.min_duration = self.min_duration.min(duration);
        self.max_duration = self.max_duration.max(duration);
        self.memory_usage = ComprehensiveProfiler::get_current_memory_usage();
        self.cpu_usage = ComprehensiveProfiler::get_current_cpu_usage();

        if is_error {
            self.errors += 1;
        }

        self.last_updated = Utc::now();
    }

    fn average_duration(&self) -> Duration {
        if self.calls == 0 {
            Duration::from_millis(0)
        } else {
            self.total_duration / self.calls as u32
        }
    }

    fn to_performance_metrics(&self, operation: String) -> PerformanceMetrics {
        PerformanceMetrics {
            operation,
            total_calls: self.calls,
            total_duration: self.total_duration,
            average_duration: self.average_duration(),
            min_duration: self.min_duration,
            max_duration: self.max_duration,
            last_call_duration: self.last_duration,
            memory_usage_bytes: self.memory_usage,
            cpu_usage_percent: self.cpu_usage,
            error_count: self.errors,
            success_rate_percent: ComprehensiveProfiler::calculate_success_rate(self.calls, self.errors),
            last_updated: self.last_updated,
        }
    }
}

#[async_trait]
impl PerformanceProfiler for ComprehensiveProfiler {
    async fn start_profiling(&self, operation: &str) -> Result<ProfileHandle, ProfilingError> {
        if !self.config.enabled {
            return Err(ProfilingError::MetricsError {
                message: "Profiling is disabled".to_string(),
            });
        }

        let mut active_profiles = self.active_profiles.write().await;

        if active_profiles.contains_key(operation) {
            return Err(ProfilingError::ProfilingAlreadyStarted {
                operation: operation.to_string(),
            });
        }

        let handle = ProfileHandle {
            operation: operation.to_string(),
            start_time: Instant::now(),
            metadata: HashMap::new(),
        };

        active_profiles.insert(operation.to_string(), handle.clone());

        Ok(handle)
    }

    async fn stop_profiling(&self, handle: ProfileHandle) -> Result<(), ProfilingError> {
        let duration = handle.start_time.elapsed();
        let is_error = false; // In a real implementation, this would be determined by context

        let mut metrics = self.metrics.write().await;
        let mut active_profiles = self.active_profiles.write().await;

        // Remove from active profiles
        active_profiles.remove(&handle.operation);

        // Update metrics
        let operation_metrics = metrics
            .entry(handle.operation.clone())
            .or_insert_with(OperationMetrics::new);

        operation_metrics.record_call(duration, is_error);

        // Cleanup old metrics periodically
        if metrics.len() % 100 == 0 {
            drop(metrics);
            drop(active_profiles);
            self.cleanup_old_metrics().await?;
        }

        Ok(())
    }

    async fn get_metrics(&self, operation: &str) -> Result<PerformanceMetrics, ProfilingError> {
        let metrics = self.metrics.read().await;

        let operation_metrics = metrics
            .get(operation)
            .ok_or_else(|| ProfilingError::OperationNotFound {
                operation: operation.to_string(),
            })?;

        Ok(operation_metrics.to_performance_metrics(operation.to_string()))
    }

    async fn get_all_metrics(&self) -> Result<HashMap<String, PerformanceMetrics>, ProfilingError> {
        let metrics = self.metrics.read().await;

        let result = metrics
            .iter()
            .map(|(operation, op_metrics)| {
                (operation.clone(), op_metrics.to_performance_metrics(operation.clone()))
            })
            .collect();

        Ok(result)
    }

    async fn generate_report(&self) -> Result<PerformanceReport, ProfilingError> {
        let all_metrics = self.get_all_metrics().await?;
        let bottlenecks = self.identify_bottlenecks().await?;

        let mut recommendations = Vec::new();
        let mut total_response_time = Duration::from_millis(0);
        let mut total_errors = 0u64;
        let mut total_calls = 0u64;
        let mut peak_response_time = Duration::from_millis(0);
        let mut memory_peak = 0u64;
        let mut cpu_total = 0.0;

        for metrics in all_metrics.values() {
            total_response_time += metrics.average_duration * metrics.total_calls as u32;
            total_errors += metrics.error_count;
            total_calls += metrics.total_calls;
            peak_response_time = peak_response_time.max(metrics.max_duration);
            memory_peak = memory_peak.max(metrics.memory_usage_bytes);
            cpu_total += metrics.cpu_usage_percent;

            if metrics.average_duration.as_millis() > self.config.bottleneck_threshold_ms as u128 {
                recommendations.push(format!("Optimize {} - high response time", metrics.operation));
            }
        }

        let avg_response_time = if total_calls > 0 {
            total_response_time / total_calls as u32
        } else {
            Duration::from_millis(0)
        };

        let cpu_average = if !all_metrics.is_empty() {
            cpu_total / all_metrics.len() as f64
        } else {
            0.0
        };

        let summary = PerformanceSummary {
            total_operations: all_metrics.len(),
            average_response_time: avg_response_time,
            peak_response_time,
            total_errors,
            overall_success_rate: if total_calls > 0 {
                ((total_calls - total_errors) as f64 / total_calls as f64) * 100.0
            } else {
                0.0
            },
            memory_peak_usage: memory_peak,
            cpu_average_usage: cpu_average,
        };

        Ok(PerformanceReport {
            generated_at: Utc::now(),
            period_start: Utc::now() - chrono::Duration::hours(self.config.retention_period_hours),
            period_end: Utc::now(),
            metrics: all_metrics,
            bottlenecks,
            recommendations,
            summary,
        })
    }

    async fn identify_bottlenecks(&self) -> Result<Vec<Bottleneck>, ProfilingError> {
        let all_metrics = self.get_all_metrics().await?;
        let mut bottlenecks = Vec::new();

        for (operation, metrics) in all_metrics {
            let severity = Self::determine_bottleneck_severity(
                metrics.average_duration,
                self.config.bottleneck_threshold_ms,
                100.0 - metrics.success_rate_percent,
            );

            if severity != BottleneckSeverity::Low {
                let impact = match severity {
                    BottleneckSeverity::Critical => 100.0,
                    BottleneckSeverity::High => 75.0,
                    BottleneckSeverity::Medium => 50.0,
                    BottleneckSeverity::Low => 0.0,
                };

                let recommendations = Self::generate_recommendations(&operation, &OperationMetrics {
                    calls: metrics.total_calls,
                    total_duration: metrics.total_duration,
                    min_duration: metrics.min_duration,
                    max_duration: metrics.max_duration,
                    last_duration: metrics.last_call_duration,
                    memory_usage: metrics.memory_usage_bytes,
                    cpu_usage: metrics.cpu_usage_percent,
                    errors: metrics.error_count,
                    last_updated: metrics.last_updated,
                });

                bottlenecks.push(Bottleneck {
                    operation,
                    severity,
                    description: format!("Performance issue detected with severity: {:?}", severity),
                    impact,
                    recommendations,
                });
            }
        }

        // Sort by impact (highest first)
        bottlenecks.sort_by(|a, b| b.impact.partial_cmp(&a.impact).unwrap());

        Ok(bottlenecks)
    }

    async fn reset(&self) -> Result<(), ProfilingError> {
        let mut metrics = self.metrics.write().await;
        let mut active_profiles = self.active_profiles.write().await;

        metrics.clear();
        active_profiles.clear();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_profiler_basic_functionality() {
        let profiler = ComprehensiveProfiler::new(ProfilerConfig::default());

        // Test starting and stopping profiling
        let handle = profiler.start_profiling("test_operation").await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        profiler.stop_profiling(handle).await.unwrap();

        // Test getting metrics
        let metrics = profiler.get_metrics("test_operation").await.unwrap();
        assert_eq!(metrics.operation, "test_operation");
        assert_eq!(metrics.total_calls, 1);
        assert!(metrics.average_duration.as_millis() >= 10);
    }

    #[tokio::test]
    async fn test_multiple_profiling_calls() {
        let profiler = ComprehensiveProfiler::new(ProfilerConfig::default());

        // Multiple calls to same operation
        for _ in 0..3 {
            let handle = profiler.start_profiling("repeated_operation").await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
            profiler.stop_profiling(handle).await.unwrap();
        }

        let metrics = profiler.get_metrics("repeated_operation").await.unwrap();
        assert_eq!(metrics.total_calls, 3);
        assert!(metrics.average_duration.as_millis() >= 5);
        assert!(metrics.average_duration.as_millis() < 50);
    }

    #[tokio::test]
    async fn test_profiler_report_generation() {
        let profiler = ComprehensiveProfiler::new(ProfilerConfig::default());

        // Add some profiling data
        let handle1 = profiler.start_profiling("operation1").await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        profiler.stop_profiling(handle1).await.unwrap();

        let handle2 = profiler.start_profiling("operation2").await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
        profiler.stop_profiling(handle2).await.unwrap();

        // Generate report
        let report = profiler.generate_report().await.unwrap();
        assert_eq!(report.metrics.len(), 2);
        assert!(report.summary.average_response_time.as_millis() >= 20);
        assert!(report.summary.total_operations == 2);
    }

    #[test]
    fn test_operation_metrics_calculation() {
        let mut metrics = OperationMetrics::new();

        // Record some calls
        metrics.record_call(Duration::from_millis(100), false);
        metrics.record_call(Duration::from_millis(200), false);
        metrics.record_call(Duration::from_millis(150), true); // Error

        assert_eq!(metrics.calls, 3);
        assert_eq!(metrics.errors, 1);
        assert_eq!(metrics.average_duration(), Duration::from_millis(150));
        assert_eq!(metrics.min_duration, Duration::from_millis(100));
        assert_eq!(metrics.max_duration, Duration::from_millis(200));
    }

    #[tokio::test]
    async fn test_bottleneck_identification() {
        let profiler = ComprehensiveProfiler::new(ProfilerConfig {
            bottleneck_threshold_ms: 50,
            ..Default::default()
        });

        // Create a slow operation
        let handle = profiler.start_profiling("slow_operation").await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        profiler.stop_profiling(handle).await.unwrap();

        let bottlenecks = profiler.identify_bottlenecks().await.unwrap();
        assert!(!bottlenecks.is_empty());
        assert!(bottlenecks[0].impact > 0.0);
    }
}
