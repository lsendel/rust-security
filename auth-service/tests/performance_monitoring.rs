//! Performance Monitoring and Alerting
//!
//! This module provides performance monitoring capabilities including:
//! - Real-time performance tracking
//! - Performance regression alerts
//! - Historical performance analysis
//! - Performance anomaly detection

// Performance metrics (simplified for self-contained module)
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Simplified performance metrics for monitoring
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub operations_completed: usize,
    pub total_duration: Duration,
    pub throughput: f64,
    pub avg_latency: Duration,
    pub p95_latency: Duration,
    pub p99_latency: Duration,
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
            error_count: 0,
        }
    }
}

/// Simplified regression detector
pub struct PerformanceRegressionDetector {
    baseline_throughput: HashMap<String, f64>,
    regression_threshold: f64,
}

impl PerformanceRegressionDetector {
    pub fn new(regression_threshold: f64) -> Self {
        Self {
            baseline_throughput: HashMap::new(),
            regression_threshold,
        }
    }

    pub fn set_baseline(&mut self, test_name: &str, metrics: &PerformanceMetrics) {
        self.baseline_throughput
            .insert(test_name.to_string(), metrics.throughput);
    }

    pub fn check_regression(
        &self,
        test_name: &str,
        current_metrics: &PerformanceMetrics,
    ) -> RegressionResult {
        if let Some(baseline) = self.baseline_throughput.get(test_name) {
            let throughput_regression = (baseline - current_metrics.throughput) / baseline * 100.0;
            let has_regression = throughput_regression > self.regression_threshold;
            RegressionResult {
                has_regression,
                throughput_regression,
                latency_regression: 0.0, // Simplified for now
            }
        } else {
            RegressionResult {
                has_regression: false,
                throughput_regression: 0.0,
                latency_regression: 0.0,
            }
        }
    }
}

/// Regression result
pub struct RegressionResult {
    pub has_regression: bool,
    pub throughput_regression: f64,
    pub latency_regression: f64,
}

/// Performance alert levels
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

/// Performance alert
#[derive(Debug, Clone)]
pub struct PerformanceAlert {
    pub id: String,
    pub level: AlertLevel,
    pub message: String,
    pub metric: String,
    pub current_value: f64,
    pub threshold: f64,
    pub timestamp: SystemTime,
}

/// Performance monitor configuration
#[derive(Debug, Clone)]
pub struct PerformanceMonitorConfig {
    /// Alert thresholds
    pub throughput_threshold: f64,
    pub latency_threshold_ms: u64,
    pub error_rate_threshold: f64,
    /// Monitoring intervals
    pub check_interval: Duration,
    pub baseline_update_interval: Duration,
    /// Alert settings
    pub enable_alerts: bool,
    pub alert_cooldown: Duration,
}

impl Default for PerformanceMonitorConfig {
    fn default() -> Self {
        Self {
            throughput_threshold: 50.0, // ops/sec
            latency_threshold_ms: 1000, // 1 second
            error_rate_threshold: 0.05, // 5%
            check_interval: Duration::from_secs(60),
            baseline_update_interval: Duration::from_secs(3600), // 1 hour
            enable_alerts: true,
            alert_cooldown: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Performance monitor for real-time tracking
pub struct PerformanceMonitor {
    config: PerformanceMonitorConfig,
    metrics_history: Arc<RwLock<HashMap<String, Vec<(SystemTime, PerformanceMetrics)>>>>,
    regression_detector: Arc<RwLock<PerformanceRegressionDetector>>,
    alerts: Arc<RwLock<Vec<PerformanceAlert>>>,
    last_alert_times: Arc<RwLock<HashMap<String, SystemTime>>>,
}

impl PerformanceMonitor {
    /// Create a new performance monitor
    pub fn new(config: PerformanceMonitorConfig) -> Self {
        Self {
            config,
            metrics_history: Arc::new(RwLock::new(HashMap::new())),
            regression_detector: Arc::new(RwLock::new(PerformanceRegressionDetector::new(10.0))),
            alerts: Arc::new(RwLock::new(Vec::new())),
            last_alert_times: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record performance metrics
    pub async fn record_metrics(&self, test_name: &str, metrics: PerformanceMetrics) {
        let mut history = self.metrics_history.write().await;
        let test_history = history.entry(test_name.to_string()).or_default();

        let timestamp = SystemTime::now();
        test_history.push((timestamp, metrics.clone()));

        // Keep only recent history (last 100 entries)
        if test_history.len() > 100 {
            test_history.remove(0);
        }

        // Check for alerts
        if self.config.enable_alerts {
            self.check_alerts(test_name, &metrics).await;
        }

        // Update baseline periodically
        if self.should_update_baseline(test_name).await {
            self.update_baseline(test_name, &metrics).await;
        }
    }

    /// Check for performance alerts
    async fn check_alerts(&self, test_name: &str, metrics: &PerformanceMetrics) {
        let mut alerts = Vec::new();
        let timestamp = SystemTime::now();

        // Throughput alert
        if metrics.throughput < self.config.throughput_threshold {
            alerts.push(PerformanceAlert {
                id: format!(
                    "throughput_{}_{}",
                    test_name,
                    timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs()
                ),
                level: AlertLevel::Warning,
                message: format!(
                    "Throughput dropped below threshold: {:.1} ops/sec < {:.1} ops/sec",
                    metrics.throughput, self.config.throughput_threshold
                ),
                metric: "throughput".to_string(),
                current_value: metrics.throughput,
                threshold: self.config.throughput_threshold,
                timestamp,
            });
        }

        // Latency alert
        let latency_ms = metrics.avg_latency.as_millis() as u64;
        if latency_ms > self.config.latency_threshold_ms {
            alerts.push(PerformanceAlert {
                id: format!(
                    "latency_{}_{}",
                    test_name,
                    timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs()
                ),
                level: AlertLevel::Warning,
                message: format!(
                    "Average latency exceeded threshold: {}ms > {}ms",
                    latency_ms, self.config.latency_threshold_ms
                ),
                metric: "latency".to_string(),
                current_value: latency_ms as f64,
                threshold: self.config.latency_threshold_ms as f64,
                timestamp,
            });
        }

        // Error rate alert
        let error_rate = if metrics.operations_completed > 0 {
            metrics.error_count as f64 / (metrics.operations_completed + metrics.error_count) as f64
        } else {
            0.0
        };

        if error_rate > self.config.error_rate_threshold {
            alerts.push(PerformanceAlert {
                id: format!(
                    "error_rate_{}_{}",
                    test_name,
                    timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs()
                ),
                level: AlertLevel::Critical,
                message: format!(
                    "Error rate exceeded threshold: {:.1}% > {:.1}%",
                    error_rate * 100.0,
                    self.config.error_rate_threshold * 100.0
                ),
                metric: "error_rate".to_string(),
                current_value: error_rate * 100.0,
                threshold: self.config.error_rate_threshold * 100.0,
                timestamp,
            });
        }

        // Check for regressions
        let detector = self.regression_detector.read().await;
        let regression = detector.check_regression(test_name, metrics);

        if regression.has_regression {
            alerts.push(PerformanceAlert {
                id: format!(
                    "regression_{}_{}",
                    test_name,
                    timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs()
                ),
                level: AlertLevel::Critical,
                message: format!(
                    "Performance regression detected: throughput {:.1}%, latency {:.1}%",
                    regression.throughput_regression, regression.latency_regression
                ),
                metric: "regression".to_string(),
                current_value: regression
                    .throughput_regression
                    .max(regression.latency_regression),
                threshold: detector.regression_threshold,
                timestamp,
            });
        }

        // Filter alerts based on cooldown
        let mut last_alerts = self.last_alert_times.write().await;
        let mut valid_alerts = Vec::new();

        for alert in alerts {
            let should_alert = if let Some(last_time) = last_alerts.get(&alert.id) {
                timestamp
                    .duration_since(*last_time)
                    .unwrap_or(Duration::from_secs(0))
                    >= self.config.alert_cooldown
            } else {
                true
            };

            if should_alert {
                valid_alerts.push(alert.clone());
                last_alerts.insert(alert.id.clone(), timestamp);
            }
        }

        // Store alerts
        if !valid_alerts.is_empty() {
            let mut all_alerts = self.alerts.write().await;
            all_alerts.extend(valid_alerts);
        }
    }

    /// Check if baseline should be updated
    async fn should_update_baseline(&self, test_name: &str) -> bool {
        let history = self.metrics_history.read().await;
        if let Some(test_history) = history.get(test_name) {
            if let Some((last_timestamp, _)) = test_history.last() {
                let elapsed = SystemTime::now()
                    .duration_since(*last_timestamp)
                    .unwrap_or(Duration::from_secs(0));
                elapsed >= self.config.baseline_update_interval
            } else {
                true
            }
        } else {
            true
        }
    }

    /// Update baseline metrics
    async fn update_baseline(&self, test_name: &str, metrics: &PerformanceMetrics) {
        let mut detector = self.regression_detector.write().await;
        detector.set_baseline(test_name, metrics);
        println!("📊 Updated baseline for {}", test_name);
    }

    /// Get recent alerts
    pub async fn get_recent_alerts(&self, limit: usize) -> Vec<PerformanceAlert> {
        let alerts = self.alerts.read().await;
        alerts.iter().rev().take(limit).cloned().collect()
    }

    /// Get performance history for a test
    pub async fn get_performance_history(
        &self,
        test_name: &str,
        limit: usize,
    ) -> Vec<(SystemTime, PerformanceMetrics)> {
        let history = self.metrics_history.read().await;
        if let Some(test_history) = history.get(test_name) {
            test_history.iter().rev().take(limit).cloned().collect()
        } else {
            Vec::new()
        }
    }

    /// Generate performance report
    pub async fn generate_report(&self, test_name: &str) -> String {
        let history = self.get_performance_history(test_name, 10).await;
        let alerts = self.get_recent_alerts(5).await;

        let mut report = format!("# Performance Report for {}\n\n", test_name);

        // Current metrics
        if let Some((_, latest_metrics)) = history.first() {
            report.push_str("## Current Metrics\n\n");
            report.push_str(&format!(
                "- Throughput: {:.1} ops/sec\n",
                latest_metrics.throughput
            ));
            report.push_str(&format!(
                "- Average Latency: {:?}\n",
                latest_metrics.avg_latency
            ));
            report.push_str(&format!(
                "- 95th Percentile: {:?}\n",
                latest_metrics.p95_latency
            ));
            report.push_str(&format!(
                "- 99th Percentile: {:?}\n",
                latest_metrics.p99_latency
            ));
            report.push_str(&format!(
                "- Error Count: {}\n\n",
                latest_metrics.error_count
            ));
        }

        // Recent history
        if history.len() > 1 {
            report.push_str("## Recent History\n\n");
            report.push_str("| Timestamp | Throughput | Avg Latency | Errors |\n");
            report.push_str("|-----------|------------|-------------|--------|\n");

            for (timestamp, metrics) in history.iter().take(5) {
                let time_str = timestamp
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string();
                report.push_str(&format!(
                    "| {} | {:.1} | {:?} | {} |\n",
                    time_str, metrics.throughput, metrics.avg_latency, metrics.error_count
                ));
            }
            report.push('\n');
        }

        // Recent alerts
        if !alerts.is_empty() {
            report.push_str("## Recent Alerts\n\n");
            for alert in alerts.iter().take(5) {
                let level_emoji = match alert.level {
                    AlertLevel::Info => "ℹ️",
                    AlertLevel::Warning => "⚠️",
                    AlertLevel::Critical => "🚨",
                };
                let level_str = match alert.level {
                    AlertLevel::Info => "Info",
                    AlertLevel::Warning => "Warning",
                    AlertLevel::Critical => "Critical",
                };
                report.push_str(&format!(
                    "{} **{}**: {}\n",
                    level_emoji, level_str, alert.message
                ));
            }
        }

        report
    }

    /// Start monitoring loop
    pub async fn start_monitoring(&self) {
        println!("📊 Starting performance monitoring...");

        let config = self.config.clone();
        let _monitor = Arc::new(self.clone());

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.check_interval);

            loop {
                interval.tick().await;

                // In a real implementation, you would collect metrics from running systems
                // For now, this is a placeholder for the monitoring loop
                println!("🔍 Performance check completed");
            }
        });
    }
}

impl Clone for PerformanceMonitor {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            metrics_history: Arc::clone(&self.metrics_history),
            regression_detector: Arc::clone(&self.regression_detector),
            alerts: Arc::clone(&self.alerts),
            last_alert_times: Arc::clone(&self.last_alert_times),
        }
    }
}

/// Performance anomaly detector using statistical methods
pub struct PerformanceAnomalyDetector {
    window_size: usize,
    threshold_sigma: f64,
    latency_history: HashMap<String, Vec<f64>>,
}

impl PerformanceAnomalyDetector {
    /// Create a new anomaly detector
    pub fn new(window_size: usize, threshold_sigma: f64) -> Self {
        Self {
            window_size,
            threshold_sigma,
            latency_history: HashMap::new(),
        }
    }

    /// Record latency measurement
    pub fn record_latency(&mut self, test_name: &str, latency_ms: f64) {
        let history = self
            .latency_history
            .entry(test_name.to_string())
            .or_default();
        history.push(latency_ms);

        // Keep only recent measurements
        if history.len() > self.window_size {
            history.remove(0);
        }
    }

    /// Detect anomalies in the recent measurements
    pub fn detect_anomaly(&self, test_name: &str, current_latency: f64) -> Option<f64> {
        if let Some(history) = self.latency_history.get(test_name) {
            if history.len() < 10 {
                // Need minimum samples
                return None;
            }

            let mean: f64 = history.iter().sum::<f64>() / history.len() as f64;
            let variance: f64 =
                history.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / history.len() as f64;
            let std_dev = variance.sqrt();

            let z_score = (current_latency - mean) / std_dev;

            if z_score.abs() > self.threshold_sigma {
                Some(z_score)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get anomaly statistics
    pub fn get_statistics(&self, test_name: &str) -> Option<(f64, f64, usize)> {
        self.latency_history.get(test_name).and_then(|history| {
            if history.is_empty() {
                None
            } else {
                let mean = history.iter().sum::<f64>() / history.len() as f64;
                let variance =
                    history.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / history.len() as f64;
                let std_dev = variance.sqrt();
                Some((mean, std_dev, history.len()))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_performance_monitor() {
        let config = PerformanceMonitorConfig {
            throughput_threshold: 10.0,
            latency_threshold_ms: 100,
            error_rate_threshold: 0.1,
            check_interval: Duration::from_secs(1),
            baseline_update_interval: Duration::from_secs(1),
            enable_alerts: true,
            alert_cooldown: Duration::from_millis(100),
        };

        let monitor = PerformanceMonitor::new(config);

        // Record metrics that should trigger alerts
        let metrics = PerformanceMetrics {
            operations_completed: 100,
            total_duration: Duration::from_secs(10),
            throughput: 5.0,                         // Below threshold
            avg_latency: Duration::from_millis(200), // Above threshold
            error_count: 20,                         // High error rate
            ..Default::default()
        };

        monitor.record_metrics("test_operation", metrics).await;

        // Check alerts
        let alerts = monitor.get_recent_alerts(10).await;
        assert!(!alerts.is_empty());

        // Should have throughput, latency, and error rate alerts
        let alert_types: Vec<_> = alerts.iter().map(|a| a.metric.as_str()).collect();
        assert!(alert_types.contains(&"throughput"));
        assert!(alert_types.contains(&"latency"));
        assert!(alert_types.contains(&"error_rate"));
    }

    #[test]
    fn test_anomaly_detector() {
        let mut detector = PerformanceAnomalyDetector::new(20, 2.0);

        // Record normal latencies
        for i in 0..15 {
            detector.record_latency("test", 100.0 + i as f64);
        }

        // Normal value should not be anomalous
        assert!(detector.detect_anomaly("test", 110.0).is_none());

        // Anomalous value should be detected
        let anomaly = detector.detect_anomaly("test", 200.0);
        assert!(anomaly.is_some());
        assert!(anomaly.unwrap() > 2.0);

        // Check statistics
        let stats = detector.get_statistics("test");
        assert!(stats.is_some());
        let (mean, std_dev, count) = stats.unwrap();
        assert!(mean > 100.0);
        assert!(std_dev > 0.0);
        assert_eq!(count, 15);
    }

    #[tokio::test]
    async fn test_performance_report() {
        let config = PerformanceMonitorConfig::default();
        let monitor = PerformanceMonitor::new(config);

        let metrics = PerformanceMetrics {
            operations_completed: 1000,
            total_duration: Duration::from_secs(10),
            throughput: 100.0,
            avg_latency: Duration::from_millis(100),
            p95_latency: Duration::from_millis(150),
            p99_latency: Duration::from_millis(200),
            error_count: 5,
        };

        monitor.record_metrics("test_operation", metrics).await;

        let report = monitor.generate_report("test_operation").await;
        assert!(report.contains("Performance Report"));
        assert!(report.contains("100.0 ops/sec"));
        assert!(report.contains("100ms"));
    }
}
