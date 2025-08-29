//! Performance regression detection and alerting system
//!
//! This module implements automated performance monitoring, regression detection,
//! and alerting for production systems to maintain SLO compliance.

use crate::metrics::PerformanceRegressionDetector;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Performance alert configuration
#[derive(Debug, Clone)]
pub struct PerformanceAlertConfig {
    pub regression_threshold_percentage: f64,
    pub monitoring_window_minutes: u64,
    pub alert_cooldown_minutes: u64,
    pub slo_targets: SLOTargets,
}

#[derive(Debug, Clone)]
pub struct SLOTargets {
    pub auth_latency_p95_ms: f64,
    pub authz_latency_p95_ms: f64,
    pub error_budget_percentage: f64,
    pub throughput_requests_per_second: f64,
}

impl Default for PerformanceAlertConfig {
    fn default() -> Self {
        Self {
            regression_threshold_percentage: 20.0, // 20% degradation threshold
            monitoring_window_minutes: 60,         // 1 hour monitoring window
            alert_cooldown_minutes: 30,            // 30 minutes between alerts
            slo_targets: SLOTargets {
                auth_latency_p95_ms: 100.0,
                authz_latency_p95_ms: 50.0,
                error_budget_percentage: 0.1, // 0.1% error budget
                throughput_requests_per_second: 1000.0,
            },
        }
    }
}

/// Performance alert types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PerformanceAlertType {
    LatencyRegression,
    ErrorRateIncrease,
    ThroughputDrop,
    MemoryUsageSpike,
    SLOViolation,
}

/// Performance alert
#[derive(Debug, Clone)]
pub struct PerformanceAlert {
    pub alert_type: PerformanceAlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub details: HashMap<String, String>,
    pub detected_at: Instant,
    pub metric_name: String,
    pub current_value: f64,
    pub threshold_value: f64,
    pub slo_target: Option<f64>,
}

/// Alert severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Performance monitoring system
pub struct PerformanceMonitor {
    config: PerformanceAlertConfig,
    detectors: RwLock<HashMap<String, PerformanceRegressionDetector>>,
    active_alerts: RwLock<HashMap<String, PerformanceAlert>>,
    last_alert_times: RwLock<HashMap<String, Instant>>,
    slo_violations: RwLock<HashMap<String, SLOViolation>>,
}

#[derive(Debug, Clone)]
pub struct SLOViolation {
    pub slo_type: SLOType,
    pub current_value: f64,
    pub target_value: f64,
    pub violation_percentage: f64,
    pub started_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SLOType {
    AuthLatency,
    AuthzLatency,
    ErrorBudget,
    Throughput,
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(config: PerformanceAlertConfig) -> Self {
        Self {
            config,
            detectors: RwLock::new(HashMap::new()),
            active_alerts: RwLock::new(HashMap::new()),
            last_alert_times: RwLock::new(HashMap::new()),
            slo_violations: RwLock::new(HashMap::new()),
        }
    }

    /// Initialize performance monitoring for a metric
    pub async fn initialize_metric(&self, metric_name: &str, baseline_data: Option<Vec<f64>>) {
        let mut detectors = self.detectors.write().await;
        let detector =
            PerformanceRegressionDetector::new(self.config.regression_threshold_percentage);

        if let Some(baseline) = baseline_data {
            detector.set_baseline(baseline);
        }

        detectors.insert(metric_name.to_string(), detector);
        info!(
            "Initialized performance monitoring for metric: {}",
            metric_name
        );
    }

    /// Record a performance measurement
    pub async fn record_measurement(&self, metric_name: &str, value: f64, timestamp: Instant) {
        // Update regression detector
        if let Some(detector) = self.detectors.write().await.get_mut(metric_name) {
            detector.record_latency(value);
        }

        // Check for immediate SLO violations
        self.check_slo_violations(metric_name, value, timestamp)
            .await;

        // Check for performance regressions
        self.check_performance_regressions(metric_name).await;
    }

    /// Check for SLO violations
    async fn check_slo_violations(&self, metric_name: &str, value: f64, timestamp: Instant) {
        let slo_type = self.metric_to_slo_type(metric_name);
        let target = self.get_slo_target(slo_type);

        if let Some(target_value) = target {
            let is_violation = match slo_type {
                SLOType::AuthLatency | SLOType::AuthzLatency => value > target_value,
                SLOType::ErrorBudget => value > target_value,
                SLOType::Throughput => value < target_value,
            };

            if is_violation {
                let violation_percentage = if matches!(slo_type, SLOType::Throughput) {
                    ((target_value - value) / target_value) * 100.0
                } else {
                    ((value - target_value) / target_value) * 100.0
                };

                self.record_slo_violation(
                    metric_name,
                    slo_type,
                    value,
                    target_value,
                    violation_percentage,
                    timestamp,
                )
                .await;
            }
        }
    }

    /// Record an SLO violation
    async fn record_slo_violation(
        &self,
        metric_name: &str,
        slo_type: SLOType,
        current_value: f64,
        target_value: f64,
        violation_percentage: f64,
        timestamp: Instant,
    ) {
        let mut violations = self.slo_violations.write().await;

        let violation_key = format!("{}_{}", metric_name, slo_type.as_str());

        if let Some(existing) = violations.get_mut(&violation_key) {
            // Update existing violation
            existing.current_value = current_value;
            existing.violation_percentage = violation_percentage;
        } else {
            // New violation
            let violation = SLOViolation {
                slo_type: slo_type.clone(),
                current_value,
                target_value,
                violation_percentage,
                started_at: timestamp,
            };

            violations.insert(violation_key.clone(), violation);

            // Create alert
            let alert = PerformanceAlert {
                alert_type: PerformanceAlertType::SLOViolation,
                severity: if violation_percentage > 50.0 {
                    AlertSeverity::Critical
                } else {
                    AlertSeverity::Warning
                },
                message: format!(
                    "SLO violation detected for {}: {:.2}{} vs target {:.2}",
                    metric_name,
                    current_value,
                    self.get_unit_for_slo_type(&slo_type),
                    target_value
                ),
                details: {
                    let mut details = HashMap::new();
                    details.insert("slo_type".to_string(), slo_type.as_str().to_string());
                    details.insert(
                        "violation_percentage".to_string(),
                        format!("{:.2}", violation_percentage),
                    );
                    details.insert("metric_name".to_string(), metric_name.to_string());
                    details
                },
                detected_at: timestamp,
                metric_name: metric_name.to_string(),
                current_value,
                threshold_value: target_value,
                slo_target: Some(target_value),
            };

            self.create_alert(&violation_key, alert).await;
        }
    }

    /// Check for performance regressions
    async fn check_performance_regressions(&self, metric_name: &str) {
        let detectors = self.detectors.read().await;

        if let Some(detector) = detectors.get(metric_name) {
            if let Some(regression_percentage) = detector.check_regression() {
                let alert_key = format!("{}_regression", metric_name);

                // Check if we should create an alert (respect cooldown)
                if self.should_create_alert(&alert_key).await {
                    let alert = PerformanceAlert {
                        alert_type: PerformanceAlertType::LatencyRegression,
                        severity: if regression_percentage > 30.0 {
                            AlertSeverity::Critical
                        } else {
                            AlertSeverity::Warning
                        },
                        message: format!(
                            "Performance regression detected for {}: {:.1}% degradation",
                            metric_name, regression_percentage
                        ),
                        details: {
                            let mut details = HashMap::new();
                            details.insert(
                                "regression_percentage".to_string(),
                                format!("{:.1}", regression_percentage),
                            );
                            details.insert(
                                "threshold".to_string(),
                                format!("{}%", self.config.regression_threshold_percentage),
                            );
                            details
                        },
                        detected_at: Instant::now(),
                        metric_name: metric_name.to_string(),
                        current_value: regression_percentage,
                        threshold_value: self.config.regression_threshold_percentage,
                        slo_target: None,
                    };

                    self.create_alert(&alert_key, alert).await;
                }
            }
        }
    }

    /// Create a performance alert
    async fn create_alert(&self, alert_key: &str, alert: PerformanceAlert) {
        let mut active_alerts = self.active_alerts.write().await;
        let mut last_alert_times = self.last_alert_times.write().await;

        active_alerts.insert(alert_key.to_string(), alert.clone());
        last_alert_times.insert(alert_key.to_string(), Instant::now());

        // Log alert based on severity
        match alert.severity {
            AlertSeverity::Critical => {
                error!("🚨 CRITICAL PERFORMANCE ALERT: {}", alert.message);
            }
            AlertSeverity::Warning => {
                warn!("⚠️  PERFORMANCE WARNING: {}", alert.message);
            }
            AlertSeverity::Info => {
                info!("ℹ️  PERFORMANCE INFO: {}", alert.message);
            }
        }

        // In a real system, this would also:
        // - Send alerts to monitoring systems (PagerDuty, Slack, etc.)
        // - Create incident tickets
        // - Trigger automated remediation actions
    }

    /// Check if we should create an alert (respect cooldown period)
    async fn should_create_alert(&self, alert_key: &str) -> bool {
        let last_alert_times = self.last_alert_times.read().await;
        let cooldown_duration = Duration::from_secs(self.config.alert_cooldown_minutes * 60);

        if let Some(last_alert_time) = last_alert_times.get(alert_key) {
            last_alert_time.elapsed() >= cooldown_duration
        } else {
            true // No previous alert, can create new one
        }
    }

    /// Get active alerts
    pub async fn get_active_alerts(&self) -> HashMap<String, PerformanceAlert> {
        self.active_alerts.read().await.clone()
    }

    /// Get SLO violations
    pub async fn get_slo_violations(&self) -> HashMap<String, SLOViolation> {
        self.slo_violations.read().await.clone()
    }

    /// Clear resolved alerts
    pub async fn clear_resolved_alerts(&self) {
        let mut active_alerts = self.active_alerts.write().await;
        let mut slo_violations = self.slo_violations.write().await;

        // Remove alerts older than the monitoring window
        let cutoff_time =
            Instant::now() - Duration::from_secs(self.config.monitoring_window_minutes * 60);

        active_alerts.retain(|_, alert| alert.detected_at > cutoff_time);

        slo_violations.retain(|_, violation| violation.started_at > cutoff_time);
    }

    /// Get performance summary
    pub async fn get_performance_summary(&self) -> PerformanceSummary {
        let active_alerts = self.get_active_alerts().await;
        let slo_violations = self.get_slo_violations().await;

        let critical_alerts = active_alerts
            .values()
            .filter(|a| a.severity == AlertSeverity::Critical)
            .count();

        let warning_alerts = active_alerts
            .values()
            .filter(|a| a.severity == AlertSeverity::Warning)
            .count();

        let slo_violation_count = slo_violations.len();

        PerformanceSummary {
            total_active_alerts: active_alerts.len(),
            critical_alerts,
            warning_alerts,
            slo_violations: slo_violation_count,
            monitoring_window_minutes: self.config.monitoring_window_minutes,
        }
    }

    // Helper methods
    fn metric_to_slo_type(&self, metric_name: &str) -> SLOType {
        match metric_name {
            "auth_duration_seconds" => SLOType::AuthLatency,
            "authz_duration_seconds" => SLOType::AuthzLatency,
            "auth_failures_total" => SLOType::ErrorBudget,
            "auth_requests_total" => SLOType::Throughput,
            _ => SLOType::AuthLatency, // Default
        }
    }

    fn get_slo_target(&self, slo_type: SLOType) -> Option<f64> {
        match slo_type {
            SLOType::AuthLatency => Some(self.config.slo_targets.auth_latency_p95_ms),
            SLOType::AuthzLatency => Some(self.config.slo_targets.authz_latency_p95_ms),
            SLOType::ErrorBudget => Some(self.config.slo_targets.error_budget_percentage),
            SLOType::Throughput => Some(self.config.slo_targets.throughput_requests_per_second),
        }
    }

    fn get_unit_for_slo_type(&self, slo_type: &SLOType) -> &'static str {
        match slo_type {
            SLOType::AuthLatency | SLOType::AuthzLatency => "ms",
            SLOType::ErrorBudget => "%",
            SLOType::Throughput => "req/s",
        }
    }
}

impl SLOType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SLOType::AuthLatency => "auth_latency",
            SLOType::AuthzLatency => "authz_latency",
            SLOType::ErrorBudget => "error_budget",
            SLOType::Throughput => "throughput",
        }
    }
}

#[derive(Debug)]
pub struct PerformanceSummary {
    pub total_active_alerts: usize,
    pub critical_alerts: usize,
    pub warning_alerts: usize,
    pub slo_violations: usize,
    pub monitoring_window_minutes: u64,
}

/// Automated performance baseline establishment
pub struct PerformanceBaselineManager {
    baselines: RwLock<HashMap<String, PerformanceBaseline>>,
}

#[derive(Debug, Clone)]
pub struct PerformanceBaseline {
    pub metric_name: String,
    pub baseline_value: f64,
    pub standard_deviation: f64,
    pub sample_count: usize,
    pub established_at: Instant,
    pub last_updated: Instant,
}

impl PerformanceBaselineManager {
    pub fn new() -> Self {
        Self {
            baselines: RwLock::new(HashMap::new()),
        }
    }

    /// Establish or update baseline for a metric
    pub async fn update_baseline(&self, metric_name: &str, measurements: &[f64]) {
        if measurements.is_empty() {
            return;
        }

        let mean = measurements.iter().sum::<f64>() / measurements.len() as f64;
        let variance = measurements.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / measurements.len() as f64;
        let std_dev = variance.sqrt();

        let mut baselines = self.baselines.write().await;

        let baseline =
            baselines
                .entry(metric_name.to_string())
                .or_insert_with(|| PerformanceBaseline {
                    metric_name: metric_name.to_string(),
                    baseline_value: mean,
                    standard_deviation: std_dev,
                    sample_count: measurements.len(),
                    established_at: Instant::now(),
                    last_updated: Instant::now(),
                });

        // Update existing baseline with exponential moving average
        let alpha = 0.1; // Smoothing factor
        baseline.baseline_value = alpha * mean + (1.0 - alpha) * baseline.baseline_value;
        baseline.standard_deviation = alpha * std_dev + (1.0 - alpha) * baseline.standard_deviation;
        baseline.sample_count += measurements.len();
        baseline.last_updated = Instant::now();
    }

    /// Get baseline for a metric
    pub async fn get_baseline(&self, metric_name: &str) -> Option<PerformanceBaseline> {
        let baselines = self.baselines.read().await;
        baselines.get(metric_name).cloned()
    }

    /// Check if a measurement deviates significantly from baseline
    pub async fn check_deviation(&self, metric_name: &str, measurement: f64) -> Option<f64> {
        if let Some(baseline) = self.get_baseline(metric_name).await {
            let deviation = (measurement - baseline.baseline_value).abs();
            let deviation_percentage = (deviation / baseline.baseline_value) * 100.0;

            // Consider it a significant deviation if it's more than 2 standard deviations
            let threshold = baseline.standard_deviation * 2.0;
            if deviation > threshold {
                Some(deviation_percentage)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_performance_monitor_initialization() {
        let config = PerformanceAlertConfig::default();
        let monitor = PerformanceMonitor::new(config);

        monitor
            .initialize_metric("test_metric", Some(vec![100.0, 105.0, 95.0]))
            .await;

        let baseline = monitor.baselines.read().await;
        assert!(baseline.contains_key("test_metric"));
    }

    #[tokio::test]
    async fn test_slo_violation_detection() {
        let config = PerformanceAlertConfig::default();
        let monitor = PerformanceMonitor::new(config);

        // Test auth latency violation
        monitor
            .record_measurement(
                "auth_duration_seconds",
                150.0, // Above 100ms target
                Instant::now(),
            )
            .await;

        let violations = monitor.get_slo_violations().await;
        assert!(!violations.is_empty(), "Should detect SLO violation");

        let violation = violations.values().next().unwrap();
        assert_eq!(violation.slo_type, SLOType::AuthLatency);
        assert!(violation.violation_percentage > 0.0);
    }

    #[tokio::test]
    async fn test_performance_regression_detection() {
        let config = PerformanceAlertConfig {
            regression_threshold_percentage: 10.0,
            ..Default::default()
        };
        let monitor = PerformanceMonitor::new(config);

        // Initialize with baseline
        monitor
            .initialize_metric("test_latency", Some(vec![100.0, 102.0, 98.0]))
            .await;

        // Record measurements that show regression
        for _ in 0..15 {
            monitor
                .record_measurement("test_latency", 120.0, Instant::now())
                .await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let alerts = monitor.get_active_alerts().await;
        assert!(!alerts.is_empty(), "Should detect performance regression");

        let alert = alerts.values().next().unwrap();
        assert_eq!(alert.alert_type, PerformanceAlertType::LatencyRegression);
        assert!(alert.current_value >= 10.0);
    }

    #[tokio::test]
    async fn test_baseline_manager() {
        let manager = PerformanceBaselineManager::new();

        let measurements = vec![100.0, 102.0, 98.0, 101.0, 99.0];
        manager.update_baseline("test_metric", &measurements).await;

        let baseline = manager.get_baseline("test_metric").await.unwrap();
        assert!((baseline.baseline_value - 100.0).abs() < 1.0);
        assert!(baseline.sample_count == measurements.len());

        // Test deviation detection
        let deviation = manager.check_deviation("test_metric", 120.0).await;
        assert!(deviation.is_some(), "Should detect significant deviation");
        assert!(deviation.unwrap() > 15.0, "Deviation should be > 15%");
    }

    #[test]
    fn test_slo_type_conversion() {
        let monitor = PerformanceMonitor::new(PerformanceAlertConfig::default());

        assert_eq!(
            monitor.metric_to_slo_type("auth_duration_seconds"),
            SLOType::AuthLatency
        );
        assert_eq!(
            monitor.metric_to_slo_type("authz_duration_seconds"),
            SLOType::AuthzLatency
        );
        assert_eq!(
            monitor.metric_to_slo_type("auth_failures_total"),
            SLOType::ErrorBudget
        );

        assert_eq!(SLOType::AuthLatency.as_str(), "auth_latency");
        assert_eq!(SLOType::Throughput.as_str(), "throughput");
    }
}
