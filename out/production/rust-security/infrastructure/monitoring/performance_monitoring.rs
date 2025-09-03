#![allow(clippy::unused_async)]
// Performance Monitoring and SLO Implementation
// Comprehensive performance tracking with automated regression detection

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Service Level Objective (SLO) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSLO {
    /// P50 latency target in milliseconds
    pub p50_latency_ms: f64,
    /// P95 latency target in milliseconds
    pub p95_latency_ms: f64,
    /// P99 latency target in milliseconds
    pub p99_latency_ms: f64,
    /// Error rate threshold (0.0 to 1.0)
    pub error_rate_threshold: f64,
    /// Availability target (0.0 to 1.0)
    pub availability_target: f64,
    /// Throughput target (requests per second)
    pub throughput_target: f64,
}

impl Default for PerformanceSLO {
    fn default() -> Self {
        Self {
            p50_latency_ms: 25.0,
            p95_latency_ms: 50.0,
            p99_latency_ms: 100.0,
            error_rate_threshold: 0.001, // 0.1%
            availability_target: 0.999,  // 99.9%
            throughput_target: 1000.0,   // 1000 RPS
        }
    }
}

/// Performance metrics for a time window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub timestamp: DateTime<Utc>,
    pub window_duration: Duration,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub latencies: Vec<f64>,
    pub p50_latency: f64,
    pub p95_latency: f64,
    pub p99_latency: f64,
    pub mean_latency: f64,
    pub error_rate: f64,
    pub availability: f64,
    pub throughput: f64,
    pub endpoint_metrics: HashMap<String, EndpointMetrics>,
}

/// Per-endpoint performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointMetrics {
    pub requests: u64,
    pub errors: u64,
    pub mean_latency: f64,
    pub p95_latency: f64,
    pub slowest_request: f64,
    pub fastest_request: f64,
}

/// Performance regression detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionAnalysis {
    pub has_regression: bool,
    pub regression_type: Option<RegressionType>,
    pub severity: RegressionSeverity,
    pub baseline_value: f64,
    pub current_value: f64,
    pub change_percentage: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegressionType {
    LatencyIncrease,
    ThroughputDecrease,
    ErrorRateIncrease,
    AvailabilityDecrease,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegressionSeverity {
    Minor,    // <10% degradation
    Moderate, // 10-25% degradation
    Major,    // 25-50% degradation
    Critical, // >50% degradation
}

/// Performance monitoring configuration
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    /// Metrics collection window
    pub collection_window: Duration,
    /// Number of historical windows to keep
    pub history_size: usize,
    /// Regression detection threshold (percentage)
    pub regression_threshold: f64,
    /// Enable automatic alerting
    pub enable_alerting: bool,
    /// Alert webhook URL
    pub alert_webhook: Option<String>,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            collection_window: Duration::from_secs(60), // 1 minute windows
            history_size: 1440,                         // 24 hours of 1-minute windows
            regression_threshold: 0.15,                 // 15% degradation threshold
            enable_alerting: true,
            alert_webhook: None,
        }
    }
}

/// Request timing information
#[derive(Debug, Clone)]
pub struct RequestTiming {
    pub endpoint: String,
    pub method: String,
    pub start_time: Instant,
    pub duration: Option<Duration>,
    pub status_code: u16,
    pub error: Option<String>,
}

impl RequestTiming {
    #[must_use]
    pub fn new(endpoint: String, method: String) -> Self {
        Self {
            endpoint,
            method,
            start_time: Instant::now(),
            duration: None,
            status_code: 200,
            error: None,
        }
    }

    pub fn finish(&mut self, status_code: u16, error: Option<String>) {
        self.duration = Some(self.start_time.elapsed());
        self.status_code = status_code;
        self.error = error;
    }

    #[must_use]
    pub const fn is_successful(&self) -> bool {
        self.status_code < 400 && self.error.is_none()
    }
}

/// Performance monitor
pub struct PerformanceMonitor {
    config: MonitoringConfig,
    slo: PerformanceSLO,
    current_window: Arc<RwLock<Vec<RequestTiming>>>,
    historical_metrics: Arc<RwLock<Vec<PerformanceMetrics>>>,
    baseline_metrics: Arc<RwLock<Option<PerformanceMetrics>>>,
}

impl PerformanceMonitor {
    /// Create new performance monitor
    #[must_use]
    pub fn new(config: MonitoringConfig, slo: PerformanceSLO) -> Self {
        Self {
            config,
            slo,
            current_window: Arc::new(RwLock::new(Vec::new())),
            historical_metrics: Arc::new(RwLock::new(Vec::new())),
            baseline_metrics: Arc::new(RwLock::new(None)),
        }
    }

    /// Record a request timing
    pub async fn record_request(&self, timing: RequestTiming) {
        let mut window = self.current_window.write().await;
        window.push(timing);
    }

    /// Start timing a request
    #[must_use]
    pub fn start_timing(&self, endpoint: String, method: String) -> RequestTiming {
        RequestTiming::new(endpoint, method)
    }

    /// Process current window and generate metrics
    pub async fn process_window(&self) -> PerformanceMetrics {
        let mut window = self.current_window.write().await;
        let timings = window.drain(..).collect::<Vec<_>>();
        drop(window);

        let metrics = self.calculate_metrics(timings).await;

        // Store in history
        {
            let mut history = self.historical_metrics.write().await;
            history.push(metrics.clone());

            // Keep only recent history
            if history.len() > self.config.history_size {
                history.remove(0);
            }
        }

        // Check for regressions
        if let Some(regression) = self.detect_regression(&metrics).await {
            self.handle_regression(regression).await;
        }

        // Check SLO compliance
        self.check_slo_compliance(&metrics).await;

        metrics
    }

    /// Calculate performance metrics from timings
    async fn calculate_metrics(&self, timings: Vec<RequestTiming>) -> PerformanceMetrics {
        let total_requests = timings.len() as u64;
        let successful_requests = timings.iter().filter(|t| t.is_successful()).count() as u64;
        let failed_requests = total_requests - successful_requests;

        let mut latencies: Vec<f64> = timings
            .iter()
            .filter_map(|t| t.duration.map(|d| d.as_secs_f64() * 1000.0))
            .collect();

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let (p50, p95, p99, mean) = if latencies.is_empty() {
            (0.0, 0.0, 0.0, 0.0)
        } else {
            let p50 = percentile(&latencies, 0.5);
            let p95 = percentile(&latencies, 0.95);
            let p99 = percentile(&latencies, 0.99);
            #[allow(clippy::cast_precision_loss)]
            let mean = latencies.iter().sum::<f64>() / latencies.len() as f64;
            (p50, p95, p99, mean)
        };

        let error_rate = if total_requests > 0 {
            #[allow(clippy::cast_precision_loss)]
            let rate = failed_requests as f64 / total_requests as f64;
            rate
        } else {
            0.0
        };

        let availability = 1.0 - error_rate;
        #[allow(clippy::cast_precision_loss)]
        let throughput = total_requests as f64 / self.config.collection_window.as_secs_f64();

        // Calculate per-endpoint metrics
        let mut endpoint_metrics = HashMap::new();
        let mut endpoint_groups: HashMap<String, Vec<&RequestTiming>> = HashMap::new();

        for timing in &timings {
            endpoint_groups
                .entry(timing.endpoint.clone())
                .or_default()
                .push(timing);
        }

        for (endpoint, endpoint_timings) in endpoint_groups {
            let requests = endpoint_timings.len() as u64;
            let errors = endpoint_timings
                .iter()
                .filter(|t| !t.is_successful())
                .count() as u64;

            let endpoint_latencies: Vec<f64> = endpoint_timings
                .iter()
                .filter_map(|t| t.duration.map(|d| d.as_secs_f64() * 1000.0))
                .collect();

            let (mean_latency, p95_latency, slowest, fastest) = if endpoint_latencies.is_empty() {
                (0.0, 0.0, 0.0, 0.0)
            } else {
                #[allow(clippy::cast_precision_loss)]
                let mean = endpoint_latencies.iter().sum::<f64>() / endpoint_latencies.len() as f64;
                let p95 = percentile(&endpoint_latencies, 0.95);
                let slowest = endpoint_latencies.iter().fold(0.0f64, |a, &b| a.max(b));
                let fastest = endpoint_latencies
                    .iter()
                    .fold(f64::INFINITY, |a, &b| a.min(b));
                (mean, p95, slowest, fastest)
            };

            endpoint_metrics.insert(
                endpoint,
                EndpointMetrics {
                    requests,
                    errors,
                    mean_latency,
                    p95_latency,
                    slowest_request: slowest,
                    fastest_request: fastest,
                },
            );
        }

        PerformanceMetrics {
            timestamp: Utc::now(),
            window_duration: self.config.collection_window,
            total_requests,
            successful_requests,
            failed_requests,
            latencies,
            p50_latency: p50,
            p95_latency: p95,
            p99_latency: p99,
            mean_latency: mean,
            error_rate,
            availability,
            throughput,
            endpoint_metrics,
        }
    }

    /// Detect performance regressions
    async fn detect_regression(&self, current: &PerformanceMetrics) -> Option<RegressionAnalysis> {
        let baseline = {
            let baseline_guard = self.baseline_metrics.read().await;
            baseline_guard.clone()?
        };

        // Check P95 latency regression
        if let Some(regression) = self.check_latency_regression(&baseline, current) {
            return Some(regression);
        }

        // Check throughput regression
        if let Some(regression) = self.check_throughput_regression(&baseline, current) {
            return Some(regression);
        }

        // Check error rate regression
        if let Some(regression) = self.check_error_rate_regression(&baseline, current) {
            return Some(regression);
        }

        None
    }

    fn check_latency_regression(
        &self,
        baseline: &PerformanceMetrics,
        current: &PerformanceMetrics,
    ) -> Option<RegressionAnalysis> {
        let baseline_p95 = baseline.p95_latency;
        let current_p95 = current.p95_latency;

        if baseline_p95 > 0.0 {
            let change = (current_p95 - baseline_p95) / baseline_p95;
            if change > self.config.regression_threshold {
                return Some(RegressionAnalysis {
                    has_regression: true,
                    regression_type: Some(RegressionType::LatencyIncrease),
                    severity: self.classify_severity(change),
                    baseline_value: baseline_p95,
                    current_value: current_p95,
                    change_percentage: change * 100.0,
                    description: format!("P95 latency increased by {:.1}%", change * 100.0),
                });
            }
        }
        None
    }

    fn check_throughput_regression(
        &self,
        baseline: &PerformanceMetrics,
        current: &PerformanceMetrics,
    ) -> Option<RegressionAnalysis> {
        let baseline_throughput = baseline.throughput;
        let current_throughput = current.throughput;

        if baseline_throughput > 0.0 {
            let change = (baseline_throughput - current_throughput) / baseline_throughput;
            if change > self.config.regression_threshold {
                return Some(RegressionAnalysis {
                    has_regression: true,
                    regression_type: Some(RegressionType::ThroughputDecrease),
                    severity: self.classify_severity(change),
                    baseline_value: baseline_throughput,
                    current_value: current_throughput,
                    change_percentage: change * 100.0,
                    description: format!("Throughput decreased by {:.1}%", change * 100.0),
                });
            }
        }
        None
    }

    fn check_error_rate_regression(
        &self,
        baseline: &PerformanceMetrics,
        current: &PerformanceMetrics,
    ) -> Option<RegressionAnalysis> {
        let baseline_error_rate = baseline.error_rate;
        let current_error_rate = current.error_rate;

        let change = current_error_rate - baseline_error_rate;
        if change > 0.01 {
            // 1% absolute increase in error rate
            return Some(RegressionAnalysis {
                has_regression: true,
                regression_type: Some(RegressionType::ErrorRateIncrease),
                severity: self.classify_severity(change * 10.0), // Scale for severity
                baseline_value: baseline_error_rate,
                current_value: current_error_rate,
                change_percentage: change * 100.0,
                description: format!("Error rate increased by {:.2}%", change * 100.0),
            });
        }
        None
    }

    fn classify_severity(&self, change: f64) -> RegressionSeverity {
        if change > 0.5 {
            RegressionSeverity::Critical
        } else if change > 0.25 {
            RegressionSeverity::Major
        } else if change > 0.1 {
            RegressionSeverity::Moderate
        } else {
            RegressionSeverity::Minor
        }
    }

    /// Handle detected regression
    async fn handle_regression(&self, regression: RegressionAnalysis) {
        match regression.severity {
            RegressionSeverity::Critical => {
                error!(
                    "CRITICAL performance regression detected: {}",
                    regression.description
                );
            }
            RegressionSeverity::Major => {
                error!(
                    "MAJOR performance regression detected: {}",
                    regression.description
                );
            }
            RegressionSeverity::Moderate => {
                warn!(
                    "MODERATE performance regression detected: {}",
                    regression.description
                );
            }
            RegressionSeverity::Minor => {
                info!(
                    "Minor performance regression detected: {}",
                    regression.description
                );
            }
        }

        // Send alert if configured
        if self.config.enable_alerting {
            self.send_regression_alert(&regression).await;
        }
    }

    /// Check SLO compliance
    async fn check_slo_compliance(&self, metrics: &PerformanceMetrics) {
        let mut violations = Vec::new();

        if metrics.p50_latency > self.slo.p50_latency_ms {
            violations.push(format!(
                "P50 latency: {:.1}ms > {:.1}ms",
                metrics.p50_latency, self.slo.p50_latency_ms
            ));
        }

        if metrics.p95_latency > self.slo.p95_latency_ms {
            violations.push(format!(
                "P95 latency: {:.1}ms > {:.1}ms",
                metrics.p95_latency, self.slo.p95_latency_ms
            ));
        }

        if metrics.p99_latency > self.slo.p99_latency_ms {
            violations.push(format!(
                "P99 latency: {:.1}ms > {:.1}ms",
                metrics.p99_latency, self.slo.p99_latency_ms
            ));
        }

        if metrics.error_rate > self.slo.error_rate_threshold {
            violations.push(format!(
                "Error rate: {:.3}% > {:.3}%",
                metrics.error_rate * 100.0,
                self.slo.error_rate_threshold * 100.0
            ));
        }

        if metrics.availability < self.slo.availability_target {
            violations.push(format!(
                "Availability: {:.3}% < {:.3}%",
                metrics.availability * 100.0,
                self.slo.availability_target * 100.0
            ));
        }

        if metrics.throughput < self.slo.throughput_target {
            violations.push(format!(
                "Throughput: {:.1} RPS < {:.1} RPS",
                metrics.throughput, self.slo.throughput_target
            ));
        }

        if violations.is_empty() {
            info!("All SLOs met for current window");
        } else {
            warn!("SLO violations detected: {}", violations.join(", "));
        }
    }

    /// Send regression alert
    async fn send_regression_alert(&self, regression: &RegressionAnalysis) {
        if let Some(webhook_url) = &self.config.alert_webhook {
            // In a real implementation, send HTTP POST to webhook
            info!(
                "Would send alert to {}: {}",
                webhook_url, regression.description
            );
        }
    }

    /// Set baseline metrics for regression detection
    pub async fn set_baseline(&self, metrics: PerformanceMetrics) {
        let mut baseline = self.baseline_metrics.write().await;
        *baseline = Some(metrics);
        info!("Performance baseline updated");
    }

    /// Get current performance summary
    pub async fn get_performance_summary(&self) -> PerformanceSummary {
        let history = self.historical_metrics.read().await;
        let recent_metrics = history.last().cloned();

        let slo_compliance = if let Some(ref metrics) = recent_metrics {
            SloCompliance {
                p50_compliant: metrics.p50_latency <= self.slo.p50_latency_ms,
                p95_compliant: metrics.p95_latency <= self.slo.p95_latency_ms,
                p99_compliant: metrics.p99_latency <= self.slo.p99_latency_ms,
                error_rate_compliant: metrics.error_rate <= self.slo.error_rate_threshold,
                availability_compliant: metrics.availability >= self.slo.availability_target,
                throughput_compliant: metrics.throughput >= self.slo.throughput_target,
            }
        } else {
            SloCompliance::default()
        };

        PerformanceSummary {
            current_metrics: recent_metrics,
            slo_compliance,
            total_windows: history.len(),
            baseline_set: self.baseline_metrics.read().await.is_some(),
        }
    }
}

/// Performance summary
#[derive(Debug, Serialize)]
pub struct PerformanceSummary {
    pub current_metrics: Option<PerformanceMetrics>,
    pub slo_compliance: SloCompliance,
    pub total_windows: usize,
    pub baseline_set: bool,
}

/// SLO compliance status
#[derive(Debug, Default, Serialize)]
pub struct SloCompliance {
    pub p50_compliant: bool,
    pub p95_compliant: bool,
    pub p99_compliant: bool,
    pub error_rate_compliant: bool,
    pub availability_compliant: bool,
    pub throughput_compliant: bool,
}

/// Calculate percentile from sorted values
fn percentile(sorted_values: &[f64], p: f64) -> f64 {
    if sorted_values.is_empty() {
        return 0.0;
    }

    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let index = (p * (sorted_values.len() - 1) as f64).round() as usize;
    sorted_values[index.min(sorted_values.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_percentile_calculation() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];

        assert!((percentile(&values, 0.5) - 5.0).abs() < f64::EPSILON); // P50
        assert!((percentile(&values, 0.95) - 10.0).abs() < f64::EPSILON); // P95
        assert!((percentile(&values, 0.99) - 10.0).abs() < f64::EPSILON); // P99
    }

    #[tokio::test]
    async fn test_performance_monitoring() {
        let config = MonitoringConfig::default();
        let slo = PerformanceSLO::default();
        let monitor = PerformanceMonitor::new(config, slo);

        // Record some timings
        let mut timing = monitor.start_timing("/test".to_string(), "GET".to_string());
        tokio::time::sleep(Duration::from_millis(10)).await;
        timing.finish(200, None);

        monitor.record_request(timing).await;

        // Process window
        let metrics = monitor.process_window().await;
        assert_eq!(metrics.total_requests, 1);
        assert_eq!(metrics.successful_requests, 1);
    }

    #[test]
    fn test_regression_severity_classification() {
        let config = MonitoringConfig::default();
        let slo = PerformanceSLO::default();
        let monitor = PerformanceMonitor::new(config, slo);

        assert!(matches!(
            monitor.classify_severity(0.05),
            RegressionSeverity::Minor
        ));
        assert!(matches!(
            monitor.classify_severity(0.15),
            RegressionSeverity::Moderate
        ));
        assert!(matches!(
            monitor.classify_severity(0.35),
            RegressionSeverity::Major
        ));
        assert!(matches!(
            monitor.classify_severity(0.75),
            RegressionSeverity::Critical
        ));
    }
}
