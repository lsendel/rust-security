//! Performance Monitoring and Profiling
//!
//! Provides performance monitoring, profiling, and optimization tracking
//! for the authentication service.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::shared::error::AppError;

/// Performance metrics for operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationMetrics {
    pub operation_name: String,
    pub count: u64,
    pub total_duration: Duration,
    pub average_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub p95_duration: Duration,
    pub p99_duration: Duration,
    pub error_count: u64,
    pub last_executed: chrono::DateTime<chrono::Utc>,
}

/// Performance profile for a specific operation
#[derive(Debug, Clone)]
pub struct PerformanceProfile {
    pub operation_name: String,
    pub samples: Vec<Duration>,
    pub error_samples: Vec<Duration>,
    pub start_time: Instant,
    pub max_samples: usize,
}

impl PerformanceProfile {
    pub fn new(operation_name: impl Into<String>, max_samples: usize) -> Self {
        Self {
            operation_name: operation_name.into(),
            samples: Vec::with_capacity(max_samples),
            error_samples: Vec::with_capacity(max_samples),
            start_time: Instant::now(),
            max_samples,
        }
    }

    pub fn record_sample(&mut self, duration: Duration, success: bool) {
        if success {
            if self.samples.len() >= self.max_samples {
                self.samples.remove(0);
            }
            self.samples.push(duration);
        } else {
            if self.error_samples.len() >= self.max_samples {
                self.error_samples.remove(0);
            }
            self.error_samples.push(duration);
        }
    }

    pub fn get_metrics(&self) -> OperationMetrics {
        if self.samples.is_empty() {
            return OperationMetrics {
                operation_name: self.operation_name.clone(),
                count: 0,
                total_duration: Duration::ZERO,
                average_duration: Duration::ZERO,
                min_duration: Duration::ZERO,
                max_duration: Duration::ZERO,
                p95_duration: Duration::ZERO,
                p99_duration: Duration::ZERO,
                error_count: self.error_samples.len() as u64,
                last_executed: chrono::Utc::now(),
            };
        }

        let mut sorted_samples = self.samples.clone();
        sorted_samples.sort();

        let total: Duration = self.samples.iter().sum();
        let count = self.samples.len() as u64;
        let average = total / count as u32;

        let min = *sorted_samples.first().unwrap();
        let max = *sorted_samples.last().unwrap();

        let p95_index = ((sorted_samples.len() as f64 * 0.95) as usize).min(sorted_samples.len() - 1);
        let p99_index = ((sorted_samples.len() as f64 * 0.99) as usize).min(sorted_samples.len() - 1);

        let p95_duration = sorted_samples[p95_index];
        let p99_duration = sorted_samples[p99_index];

        OperationMetrics {
            operation_name: self.operation_name.clone(),
            count,
            total_duration: total,
            average_duration: average,
            min_duration: min,
            max_duration: max,
            p95_duration,
            p99_duration,
            error_count: self.error_samples.len() as u64,
            last_executed: chrono::Utc::now(),
        }
    }

    pub fn reset(&mut self) {
        self.samples.clear();
        self.error_samples.clear();
        self.start_time = Instant::now();
    }
}

/// Performance monitor service
#[derive(Clone)]
pub struct PerformanceMonitor {
    profiles: Arc<RwLock<HashMap<String, PerformanceProfile>>>,
    max_samples_per_operation: usize,
    slow_operation_threshold: Duration,
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(max_samples_per_operation: usize, slow_operation_threshold: Duration) -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            max_samples_per_operation,
            slow_operation_threshold,
        }
    }

    /// Record a performance sample for an operation
    pub async fn record_operation(
        &self,
        operation_name: &str,
        duration: Duration,
        success: bool,
    ) {
        let mut profiles = self.profiles.write().await;

        let profile = profiles.entry(operation_name.to_string()).or_insert_with(|| {
            PerformanceProfile::new(operation_name, self.max_samples_per_operation)
        });

        profile.record_sample(duration, success);

        // Log slow operations
        if duration > self.slow_operation_threshold {
            if success {
                warn!(
                    "Slow operation detected: {} took {}ms",
                    operation_name,
                    duration.as_millis()
                );
            } else {
                warn!(
                    "Slow failed operation: {} took {}ms",
                    operation_name,
                    duration.as_millis()
                );
            }
        }

        debug!(
            "Operation recorded: {} (success: {}, duration: {}ms)",
            operation_name,
            success,
            duration.as_millis()
        );
    }

    /// Get performance metrics for an operation
    pub async fn get_operation_metrics(&self, operation_name: &str) -> Option<OperationMetrics> {
        let profiles = self.profiles.read().await;
        profiles.get(operation_name).map(|profile| profile.get_metrics())
    }

    /// Get performance metrics for all operations
    pub async fn get_all_metrics(&self) -> HashMap<String, OperationMetrics> {
        let profiles = self.profiles.read().await;
        profiles
            .iter()
            .map(|(name, profile)| (name.clone(), profile.get_metrics()))
            .collect()
    }

    /// Get slow operations (above threshold)
    pub async fn get_slow_operations(&self) -> Vec<OperationMetrics> {
        let all_metrics = self.get_all_metrics().await;
        all_metrics
            .into_iter()
            .filter(|(_, metrics)| metrics.p95_duration > self.slow_operation_threshold)
            .map(|(_, metrics)| metrics)
            .collect()
    }

    /// Get operations with high error rates
    pub async fn get_high_error_operations(&self, error_rate_threshold: f64) -> Vec<OperationMetrics> {
        let all_metrics = self.get_all_metrics().await;
        all_metrics
            .into_iter()
            .filter(|(_, metrics)| {
                if metrics.count == 0 {
                    false
                } else {
                    (metrics.error_count as f64 / metrics.count as f64) > error_rate_threshold
                }
            })
            .map(|(_, metrics)| metrics)
            .collect()
    }

    /// Reset performance data for an operation
    pub async fn reset_operation(&self, operation_name: &str) {
        let mut profiles = self.profiles.write().await;
        if let Some(profile) = profiles.get_mut(operation_name) {
            profile.reset();
            info!("Reset performance data for operation: {}", operation_name);
        }
    }

    /// Reset all performance data
    pub async fn reset_all(&self) {
        let mut profiles = self.profiles.write().await;
        profiles.clear();
        info!("Reset all performance data");
    }

    /// Get performance summary
    pub async fn get_summary(&self) -> PerformanceSummary {
        let all_metrics = self.get_all_metrics().await;
        let slow_operations = self.get_slow_operations().await;
        let high_error_operations = self.get_high_error_operations(0.1).await; // 10% error rate threshold

        let total_operations = all_metrics.len();
        let total_samples: u64 = all_metrics.values().map(|m| m.count).sum();
        let total_errors: u64 = all_metrics.values().map(|m| m.error_count).sum();

        PerformanceSummary {
            total_operations,
            total_samples,
            total_errors,
            slow_operations_count: slow_operations.len(),
            high_error_operations_count: high_error_operations.len(),
            average_response_time: if total_samples > 0 {
                let total_duration: Duration = all_metrics.values().map(|m| m.total_duration).sum();
                total_duration / total_samples as u32
            } else {
                Duration::ZERO
            },
        }
    }

    /// Export performance data for analysis
    pub async fn export_data(&self) -> Result<String, AppError> {
        let all_metrics = self.get_all_metrics().await;
        let summary = self.get_summary().await;

        let export_data = PerformanceExport {
            summary,
            operations: all_metrics,
            exported_at: chrono::Utc::now(),
        };

        serde_json::to_string_pretty(&export_data)
            .map_err(|e| AppError::Internal(format!("Failed to export performance data: {}", e)))
    }
}

/// Performance summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub total_operations: usize,
    pub total_samples: u64,
    pub total_errors: u64,
    pub slow_operations_count: usize,
    pub high_error_operations_count: usize,
    pub average_response_time: Duration,
}

/// Performance data export structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceExport {
    pub summary: PerformanceSummary,
    pub operations: HashMap<String, OperationMetrics>,
    pub exported_at: chrono::DateTime<chrono::Utc>,
}

/// Performance monitoring middleware
pub struct PerformanceMonitoringMiddleware {
    monitor: PerformanceMonitor,
}

impl PerformanceMonitoringMiddleware {
    pub fn new(monitor: PerformanceMonitor) -> Self {
        Self { monitor }
    }

    pub fn monitor(&self) -> &PerformanceMonitor {
        &self.monitor
    }
}

/// Performance alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAlertConfig {
    pub slow_operation_threshold: Duration,
    pub error_rate_threshold: f64,
    pub p95_threshold: Duration,
    pub alert_cooldown: Duration,
}

/// Performance alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAlert {
    pub alert_type: PerformanceAlertType,
    pub operation_name: String,
    pub message: String,
    pub severity: AlertSeverity,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub metrics: OperationMetrics,
}

/// Types of performance alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PerformanceAlertType {
    SlowOperation,
    HighErrorRate,
    PerformanceRegression,
    ServiceDegradation,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Performance alert manager
pub struct PerformanceAlertManager {
    config: PerformanceAlertConfig,
    active_alerts: Arc<RwLock<HashMap<String, PerformanceAlert>>>,
}

impl PerformanceAlertManager {
    pub fn new(config: PerformanceAlertConfig) -> Self {
        Self {
            config,
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn check_and_alert(&self, metrics: &OperationMetrics) -> Vec<PerformanceAlert> {
        let mut alerts = Vec::new();

        // Check for slow operations
        if metrics.p95_duration > self.config.p95_threshold {
            let alert = PerformanceAlert {
                alert_type: PerformanceAlertType::SlowOperation,
                operation_name: metrics.operation_name.clone(),
                message: format!(
                    "Operation {} is running slow (P95: {}ms > {}ms)",
                    metrics.operation_name,
                    metrics.p95_duration.as_millis(),
                    self.config.p95_threshold.as_millis()
                ),
                severity: AlertSeverity::Medium,
                timestamp: chrono::Utc::now(),
                metrics: metrics.clone(),
            };
            alerts.push(alert);
        }

        // Check for high error rates
        if metrics.count > 0 {
            let error_rate = metrics.error_count as f64 / metrics.count as f64;
            if error_rate > self.config.error_rate_threshold {
                let alert = PerformanceAlert {
                    alert_type: PerformanceAlertType::HighErrorRate,
                    operation_name: metrics.operation_name.clone(),
                    message: format!(
                        "Operation {} has high error rate ({:.1}% > {:.1}%)",
                        metrics.operation_name,
                        error_rate * 100.0,
                        self.config.error_rate_threshold * 100.0
                    ),
                    severity: if error_rate > 0.5 { AlertSeverity::Critical } else { AlertSeverity::High },
                    timestamp: chrono::Utc::now(),
                    metrics: metrics.clone(),
                };
                alerts.push(alert);
            }
        }

        // Store active alerts
        let mut active_alerts = self.active_alerts.write().await;
        for alert in &alerts {
            let alert_key = format!("{}:{:?}", alert.operation_name, alert.alert_type);
            active_alerts.insert(alert_key, alert.clone());
        }

        alerts
    }

    pub async fn get_active_alerts(&self) -> Vec<PerformanceAlert> {
        let active_alerts = self.active_alerts.read().await;
        active_alerts.values().cloned().collect()
    }

    pub async fn clear_alert(&self, operation_name: &str, alert_type: &PerformanceAlertType) {
        let mut active_alerts = self.active_alerts.write().await;
        let alert_key = format!("{}:{:?}", operation_name, alert_type);
        active_alerts.remove(&alert_key);
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new(1000, Duration::from_millis(100))
    }
}

impl Default for PerformanceAlertConfig {
    fn default() -> Self {
        Self {
            slow_operation_threshold: Duration::from_millis(100),
            error_rate_threshold: 0.1, // 10%
            p95_threshold: Duration::from_millis(500),
            alert_cooldown: Duration::from_secs(300), // 5 minutes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_performance_monitoring() {
        let monitor = PerformanceMonitor::new(100, Duration::from_millis(50));

        // Record some operations
        monitor.record_operation("test_op", Duration::from_millis(10), true).await;
        monitor.record_operation("test_op", Duration::from_millis(20), true).await;
        monitor.record_operation("test_op", Duration::from_millis(30), false).await;

        // Get metrics
        let metrics = monitor.get_operation_metrics("test_op").await.unwrap();

        assert_eq!(metrics.operation_name, "test_op");
        assert_eq!(metrics.count, 2); // Only successful operations
        assert_eq!(metrics.error_count, 1);
        assert_eq!(metrics.average_duration, Duration::from_millis(15));
    }

    #[tokio::test]
    async fn test_slow_operations() {
        let monitor = PerformanceMonitor::new(100, Duration::from_millis(10));

        // Record slow operations
        monitor.record_operation("slow_op", Duration::from_millis(100), true).await;
        monitor.record_operation("fast_op", Duration::from_millis(5), true).await;

        let slow_ops = monitor.get_slow_operations().await;
        assert_eq!(slow_ops.len(), 1);
        assert_eq!(slow_ops[0].operation_name, "slow_op");
    }

    #[test]
    fn test_performance_profile() {
        let mut profile = PerformanceProfile::new("test", 10);

        profile.record_sample(Duration::from_millis(10), true);
        profile.record_sample(Duration::from_millis(20), true);
        profile.record_sample(Duration::from_millis(30), false);

        let metrics = profile.get_metrics();

        assert_eq!(metrics.count, 2);
        assert_eq!(metrics.error_count, 1);
        assert_eq!(metrics.average_duration, Duration::from_millis(15));
        assert_eq!(metrics.min_duration, Duration::from_millis(10));
        assert_eq!(metrics.max_duration, Duration::from_millis(20));
    }

    #[tokio::test]
    async fn test_performance_alerts() {
        let config = PerformanceAlertConfig {
            p95_threshold: Duration::from_millis(50),
            error_rate_threshold: 0.5,
            ..Default::default()
        };

        let alert_manager = PerformanceAlertManager::new(config);

        let metrics = OperationMetrics {
            operation_name: "slow_op".to_string(),
            count: 100,
            total_duration: Duration::from_millis(10000),
            average_duration: Duration::from_millis(100),
            min_duration: Duration::from_millis(10),
            max_duration: Duration::from_millis(200),
            p95_duration: Duration::from_millis(150), // Above threshold
            p99_duration: Duration::from_millis(180),
            error_count: 60, // 60% error rate, above threshold
            last_executed: chrono::Utc::now(),
        };

        let alerts = alert_manager.check_and_alert(&metrics).await;

        assert_eq!(alerts.len(), 2); // Both slow and high error rate alerts
        assert!(matches!(alerts[0].alert_type, PerformanceAlertType::SlowOperation));
        assert!(matches!(alerts[1].alert_type, PerformanceAlertType::HighErrorRate));
    }
}
