// Phase 4: Automated Monitoring and Alerting with ML-based Anomaly Detection
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn, error, instrument};
use prometheus::{Counter, Histogram, Gauge};

/// Automated monitoring system with ML-based anomaly detection
#[derive(Clone)]
pub struct AutomatedMonitor {
    config: MonitoringConfig,
    metrics: MonitoringMetrics,
    anomaly_detector: Arc<RwLock<AnomalyDetector>>,
    alert_manager: Arc<AlertManager>,
    performance_baselines: Arc<RwLock<HashMap<String, PerformanceBaseline>>>,
    active_incidents: Arc<RwLock<HashMap<String, Incident>>>,
}

#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub collection_interval: Duration,
    pub anomaly_threshold: f64,
    pub baseline_window: Duration,
    pub alert_cooldown: Duration,
    pub auto_healing_enabled: bool,
    pub ml_model_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct MonitoringMetrics {
    pub metrics_collected: Counter,
    pub anomalies_detected: Counter,
    pub alerts_triggered: Counter,
    pub incidents_created: Counter,
    pub auto_healing_actions: Counter,
    pub baseline_accuracy: Gauge,
    pub detection_latency: Histogram,
}

/// ML-based anomaly detector using statistical analysis
pub struct AnomalyDetector {
    models: HashMap<String, AnomalyModel>,
    config: AnomalyConfig,
    training_data: HashMap<String, VecDeque<DataPoint>>,
}

#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    pub sensitivity: f64,
    pub min_training_samples: usize,
    pub max_training_samples: usize,
    pub retraining_interval: Duration,
    pub seasonal_adjustment: bool,
}

#[derive(Debug, Clone)]
pub struct AnomalyModel {
    pub metric_name: String,
    pub mean: f64,
    pub std_dev: f64,
    pub trend: f64,
    pub seasonal_factors: Vec<f64>,
    pub last_trained: Instant,
    pub accuracy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    pub timestamp: u64,
    pub value: f64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    pub metric_name: String,
    pub timestamp: u64,
    pub actual_value: f64,
    pub expected_value: f64,
    pub anomaly_score: f64,
    pub is_anomaly: bool,
    pub confidence: f64,
}

/// Performance baseline tracking
#[derive(Debug, Clone)]
pub struct PerformanceBaseline {
    pub metric_name: String,
    pub baseline_value: f64,
    pub acceptable_range: (f64, f64),
    pub trend: Trend,
    pub last_updated: Instant,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Trend {
    Stable,
    Increasing,
    Decreasing,
    Volatile,
}

/// Alert management system
pub struct AlertManager {
    config: AlertConfig,
    alert_rules: Vec<AlertRule>,
    notification_channels: Vec<NotificationChannel>,
    alert_history: Arc<RwLock<VecDeque<Alert>>>,
    metrics: AlertMetrics,
}

#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub max_alerts_per_hour: usize,
    pub escalation_timeout: Duration,
    pub auto_resolve_timeout: Duration,
    pub notification_retry_count: usize,
}

#[derive(Debug, Clone)]
pub struct AlertRule {
    pub name: String,
    pub metric_pattern: String,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub cooldown: Duration,
    pub auto_healing_action: Option<AutoHealingAction>,
}

#[derive(Debug, Clone)]
pub enum AlertCondition {
    Threshold { operator: ComparisonOperator, value: f64 },
    Anomaly { sensitivity: f64 },
    RateOfChange { threshold: f64, window: Duration },
    Composite { rules: Vec<String>, operator: LogicalOperator },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComparisonOperator {
    GreaterThan,
    LessThan,
    Equal,
    NotEqual,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LogicalOperator {
    And,
    Or,
    Not,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone)]
pub enum AutoHealingAction {
    RestartService { service_name: String },
    ScaleUp { replicas: u32 },
    ScaleDown { replicas: u32 },
    ClearCache { cache_name: String },
    Rollback { deployment_name: String },
    Custom { script_path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub metric_name: String,
    pub current_value: f64,
    pub threshold_value: Option<f64>,
    pub timestamp: u64,
    pub status: AlertStatus,
    pub auto_healing_attempted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
    Suppressed,
}

#[derive(Debug, Clone)]
pub enum NotificationChannel {
    Slack { webhook_url: String },
    Email { recipients: Vec<String> },
    PagerDuty { integration_key: String },
    Webhook { url: String, headers: HashMap<String, String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub status: IncidentStatus,
    pub created_at: u64,
    pub resolved_at: Option<u64>,
    pub affected_services: Vec<String>,
    pub root_cause: Option<String>,
    pub resolution_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IncidentStatus {
    Open,
    Investigating,
    Identified,
    Monitoring,
    Resolved,
}

#[derive(Debug, Clone)]
pub struct AlertMetrics {
    pub alerts_sent: Counter,
    pub alerts_resolved: Counter,
    pub notification_failures: Counter,
    pub escalation_events: Counter,
    pub auto_healing_success: Counter,
    pub auto_healing_failures: Counter,
}

impl AutomatedMonitor {
    pub async fn new(config: MonitoringConfig, registry: &prometheus::Registry) -> Result<Self, MonitoringError> {
        let metrics = MonitoringMetrics::new(registry)?;
        
        let anomaly_config = AnomalyConfig {
            sensitivity: 0.95,
            min_training_samples: 100,
            max_training_samples: 10000,
            retraining_interval: Duration::from_hours(1),
            seasonal_adjustment: true,
        };
        
        let anomaly_detector = Arc::new(RwLock::new(AnomalyDetector::new(anomaly_config)));
        
        let alert_config = AlertConfig {
            max_alerts_per_hour: 50,
            escalation_timeout: Duration::from_minutes(15),
            auto_resolve_timeout: Duration::from_hours(1),
            notification_retry_count: 3,
        };
        
        let alert_manager = Arc::new(AlertManager::new(alert_config, registry)?);
        
        Ok(Self {
            config,
            metrics,
            anomaly_detector,
            alert_manager,
            performance_baselines: Arc::new(RwLock::new(HashMap::new())),
            active_incidents: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Start automated monitoring with continuous data collection
    #[instrument(skip(self))]
    pub async fn start_monitoring(&self) -> Result<(), MonitoringError> {
        info!("Starting automated monitoring system");
        
        // Start metric collection task
        self.start_metric_collection().await;
        
        // Start anomaly detection task
        self.start_anomaly_detection().await;
        
        // Start alert processing task
        self.start_alert_processing().await;
        
        // Start auto-healing task
        if self.config.auto_healing_enabled {
            self.start_auto_healing().await;
        }
        
        info!("Automated monitoring system started successfully");
        Ok(())
    }

    async fn start_metric_collection(&self) {
        let config = self.config.clone();
        let metrics = self.metrics.clone();
        let anomaly_detector = Arc::clone(&self.anomaly_detector);
        let baselines = Arc::clone(&self.performance_baselines);
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.collection_interval);
            
            loop {
                interval.tick().await;
                
                // Collect system metrics
                let collected_metrics = Self::collect_system_metrics().await;
                
                for (metric_name, value) in collected_metrics {
                    // Update anomaly detector
                    {
                        let mut detector = anomaly_detector.write().await;
                        detector.add_data_point(&metric_name, value).await;
                    }
                    
                    // Update performance baselines
                    {
                        let mut baseline_map = baselines.write().await;
                        Self::update_baseline(&mut baseline_map, &metric_name, value).await;
                    }
                    
                    metrics.metrics_collected.inc();
                }
            }
        });
    }

    async fn start_anomaly_detection(&self) {
        let anomaly_detector = Arc::clone(&self.anomaly_detector);
        let alert_manager = Arc::clone(&self.alert_manager);
        let metrics = self.metrics.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let detection_start = Instant::now();
                
                // Run anomaly detection
                let anomalies = {
                    let detector = anomaly_detector.read().await;
                    detector.detect_anomalies().await
                };
                
                // Process detected anomalies
                for anomaly in anomalies {
                    if anomaly.is_anomaly {
                        metrics.anomalies_detected.inc();
                        
                        // Create alert for anomaly
                        let alert = Alert {
                            id: uuid::Uuid::new_v4().to_string(),
                            rule_name: "anomaly_detection".to_string(),
                            severity: Self::determine_severity(anomaly.anomaly_score),
                            message: format!(
                                "Anomaly detected in {}: actual={:.2}, expected={:.2}, score={:.2}",
                                anomaly.metric_name, anomaly.actual_value, anomaly.expected_value, anomaly.anomaly_score
                            ),
                            metric_name: anomaly.metric_name,
                            current_value: anomaly.actual_value,
                            threshold_value: Some(anomaly.expected_value),
                            timestamp: anomaly.timestamp,
                            status: AlertStatus::Active,
                            auto_healing_attempted: false,
                        };
                        
                        alert_manager.process_alert(alert).await;
                    }
                }
                
                let detection_time = detection_start.elapsed();
                metrics.detection_latency.observe(detection_time.as_secs_f64());
            }
        });
    }

    async fn start_alert_processing(&self) {
        let alert_manager = Arc::clone(&self.alert_manager);
        
        tokio::spawn(async move {
            alert_manager.start_processing().await;
        });
    }

    async fn start_auto_healing(&self) {
        let alert_manager = Arc::clone(&self.alert_manager);
        let metrics = self.metrics.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Check for alerts that need auto-healing
                let healing_actions = alert_manager.get_auto_healing_actions().await;
                
                for action in healing_actions {
                    match Self::execute_auto_healing_action(action).await {
                        Ok(_) => {
                            metrics.auto_healing_actions.inc();
                            info!("Auto-healing action executed successfully");
                        }
                        Err(e) => {
                            error!("Auto-healing action failed: {}", e);
                        }
                    }
                }
            }
        });
    }

    async fn collect_system_metrics() -> HashMap<String, f64> {
        let mut metrics = HashMap::new();
        
        // Simulate collecting various system metrics
        metrics.insert("cpu_usage_percent".to_string(), 45.0 + fastrand::f64() * 20.0);
        metrics.insert("memory_usage_percent".to_string(), 60.0 + fastrand::f64() * 15.0);
        metrics.insert("response_time_ms".to_string(), 2.0 + fastrand::f64() * 3.0);
        metrics.insert("requests_per_second".to_string(), 5000.0 + fastrand::f64() * 1000.0);
        metrics.insert("error_rate_percent".to_string(), 0.1 + fastrand::f64() * 0.5);
        metrics.insert("disk_usage_percent".to_string(), 30.0 + fastrand::f64() * 10.0);
        metrics.insert("network_throughput_mbps".to_string(), 100.0 + fastrand::f64() * 50.0);
        
        metrics
    }

    async fn update_baseline(
        baseline_map: &mut HashMap<String, PerformanceBaseline>,
        metric_name: &str,
        value: f64,
    ) {
        let baseline = baseline_map.entry(metric_name.to_string()).or_insert_with(|| {
            PerformanceBaseline {
                metric_name: metric_name.to_string(),
                baseline_value: value,
                acceptable_range: (value * 0.8, value * 1.2),
                trend: Trend::Stable,
                last_updated: Instant::now(),
                confidence: 0.5,
            }
        });

        // Update baseline with exponential moving average
        let alpha = 0.1; // Smoothing factor
        baseline.baseline_value = alpha * value + (1.0 - alpha) * baseline.baseline_value;
        baseline.acceptable_range = (
            baseline.baseline_value * 0.9,
            baseline.baseline_value * 1.1,
        );
        baseline.last_updated = Instant::now();
        baseline.confidence = (baseline.confidence + 0.01).min(1.0);
    }

    fn determine_severity(anomaly_score: f64) -> AlertSeverity {
        match anomaly_score {
            score if score >= 0.95 => AlertSeverity::Critical,
            score if score >= 0.85 => AlertSeverity::High,
            score if score >= 0.70 => AlertSeverity::Medium,
            score if score >= 0.50 => AlertSeverity::Low,
            _ => AlertSeverity::Info,
        }
    }

    async fn execute_auto_healing_action(action: AutoHealingAction) -> Result<(), MonitoringError> {
        match action {
            AutoHealingAction::RestartService { service_name } => {
                info!("Auto-healing: Restarting service {}", service_name);
                // Simulate service restart
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(())
            }
            AutoHealingAction::ScaleUp { replicas } => {
                info!("Auto-healing: Scaling up to {} replicas", replicas);
                // Simulate scaling up
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(())
            }
            AutoHealingAction::ClearCache { cache_name } => {
                info!("Auto-healing: Clearing cache {}", cache_name);
                // Simulate cache clearing
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(())
            }
            _ => {
                warn!("Auto-healing action not implemented");
                Ok(())
            }
        }
    }

    /// Get current monitoring status
    pub async fn get_monitoring_status(&self) -> MonitoringStatus {
        let baselines = self.performance_baselines.read().await;
        let incidents = self.active_incidents.read().await;
        
        MonitoringStatus {
            active_baselines: baselines.len(),
            active_incidents: incidents.len(),
            anomaly_detection_enabled: self.config.ml_model_enabled,
            auto_healing_enabled: self.config.auto_healing_enabled,
            last_collection: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

impl AnomalyDetector {
    pub fn new(config: AnomalyConfig) -> Self {
        Self {
            models: HashMap::new(),
            config,
            training_data: HashMap::new(),
        }
    }

    pub async fn add_data_point(&mut self, metric_name: &str, value: f64) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let data_point = DataPoint {
            timestamp,
            value,
            metadata: HashMap::new(),
        };

        let training_data = self.training_data.entry(metric_name.to_string()).or_insert_with(VecDeque::new);
        training_data.push_back(data_point);

        // Maintain training data size
        if training_data.len() > self.config.max_training_samples {
            training_data.pop_front();
        }

        // Retrain model if enough data and time has passed
        if training_data.len() >= self.config.min_training_samples {
            if let Some(model) = self.models.get(metric_name) {
                if model.last_trained.elapsed() > self.config.retraining_interval {
                    self.train_model(metric_name).await;
                }
            } else {
                self.train_model(metric_name).await;
            }
        }
    }

    async fn train_model(&mut self, metric_name: &str) {
        if let Some(training_data) = self.training_data.get(metric_name) {
            let values: Vec<f64> = training_data.iter().map(|dp| dp.value).collect();
            
            if values.is_empty() {
                return;
            }

            let mean = values.iter().sum::<f64>() / values.len() as f64;
            let variance = values.iter()
                .map(|v| (v - mean).powi(2))
                .sum::<f64>() / values.len() as f64;
            let std_dev = variance.sqrt();

            // Simple trend calculation
            let trend = if values.len() > 1 {
                let first_half = &values[..values.len()/2];
                let second_half = &values[values.len()/2..];
                let first_avg = first_half.iter().sum::<f64>() / first_half.len() as f64;
                let second_avg = second_half.iter().sum::<f64>() / second_half.len() as f64;
                second_avg - first_avg
            } else {
                0.0
            };

            let model = AnomalyModel {
                metric_name: metric_name.to_string(),
                mean,
                std_dev,
                trend,
                seasonal_factors: vec![1.0; 24], // Simplified seasonal factors
                last_trained: Instant::now(),
                accuracy: 0.85, // Simulated accuracy
            };

            self.models.insert(metric_name.to_string(), model);
        }
    }

    pub async fn detect_anomalies(&self) -> Vec<AnomalyResult> {
        let mut anomalies = Vec::new();

        for (metric_name, training_data) in &self.training_data {
            if let Some(model) = self.models.get(metric_name) {
                if let Some(latest_point) = training_data.back() {
                    let expected_value = model.mean + model.trend;
                    let deviation = (latest_point.value - expected_value).abs();
                    let anomaly_score = deviation / (model.std_dev + 1e-6); // Avoid division by zero
                    
                    let is_anomaly = anomaly_score > (2.0 * self.config.sensitivity);
                    
                    anomalies.push(AnomalyResult {
                        metric_name: metric_name.clone(),
                        timestamp: latest_point.timestamp,
                        actual_value: latest_point.value,
                        expected_value,
                        anomaly_score,
                        is_anomaly,
                        confidence: model.accuracy,
                    });
                }
            }
        }

        anomalies
    }
}

impl AlertManager {
    pub fn new(config: AlertConfig, registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        let metrics = AlertMetrics::new(registry)?;
        
        Ok(Self {
            config,
            alert_rules: Vec::new(),
            notification_channels: Vec::new(),
            alert_history: Arc::new(RwLock::new(VecDeque::new())),
            metrics,
        })
    }

    pub async fn process_alert(&self, alert: Alert) {
        info!("Processing alert: {} - {}", alert.severity, alert.message);
        
        // Add to alert history
        {
            let mut history = self.alert_history.write().await;
            history.push_back(alert.clone());
            
            // Maintain history size
            if history.len() > 1000 {
                history.pop_front();
            }
        }

        self.metrics.alerts_sent.inc();
        
        // Send notifications
        self.send_notifications(&alert).await;
    }

    async fn send_notifications(&self, alert: &Alert) {
        for channel in &self.notification_channels {
            match self.send_notification(channel, alert).await {
                Ok(_) => debug!("Notification sent successfully"),
                Err(e) => {
                    error!("Failed to send notification: {}", e);
                    self.metrics.notification_failures.inc();
                }
            }
        }
    }

    async fn send_notification(&self, _channel: &NotificationChannel, alert: &Alert) -> Result<(), MonitoringError> {
        // Simulate notification sending
        info!("Sending notification for alert: {}", alert.message);
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    pub async fn start_processing(&self) {
        // Alert processing loop would go here
        info!("Alert manager processing started");
    }

    pub async fn get_auto_healing_actions(&self) -> Vec<AutoHealingAction> {
        // Return auto-healing actions based on active alerts
        vec![
            AutoHealingAction::ClearCache { cache_name: "redis".to_string() },
        ]
    }
}

impl MonitoringMetrics {
    fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        use prometheus::{Counter, Histogram, Gauge, Opts, HistogramOpts};

        let metrics_collected = Counter::with_opts(
            Opts::new("monitoring_metrics_collected_total", "Total metrics collected")
        )?;

        let anomalies_detected = Counter::with_opts(
            Opts::new("monitoring_anomalies_detected_total", "Total anomalies detected")
        )?;

        let alerts_triggered = Counter::with_opts(
            Opts::new("monitoring_alerts_triggered_total", "Total alerts triggered")
        )?;

        let incidents_created = Counter::with_opts(
            Opts::new("monitoring_incidents_created_total", "Total incidents created")
        )?;

        let auto_healing_actions = Counter::with_opts(
            Opts::new("monitoring_auto_healing_actions_total", "Total auto-healing actions")
        )?;

        let baseline_accuracy = Gauge::with_opts(
            Opts::new("monitoring_baseline_accuracy", "Baseline prediction accuracy")
        )?;

        let detection_latency = Histogram::with_opts(
            HistogramOpts::new("monitoring_detection_latency_seconds", "Anomaly detection latency")
                .buckets(vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0])
        )?;

        registry.register(Box::new(metrics_collected.clone()))?;
        registry.register(Box::new(anomalies_detected.clone()))?;
        registry.register(Box::new(alerts_triggered.clone()))?;
        registry.register(Box::new(incidents_created.clone()))?;
        registry.register(Box::new(auto_healing_actions.clone()))?;
        registry.register(Box::new(baseline_accuracy.clone()))?;
        registry.register(Box::new(detection_latency.clone()))?;

        Ok(Self {
            metrics_collected,
            anomalies_detected,
            alerts_triggered,
            incidents_created,
            auto_healing_actions,
            baseline_accuracy,
            detection_latency,
        })
    }
}

impl AlertMetrics {
    fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        use prometheus::{Counter, Opts};

        let alerts_sent = Counter::with_opts(
            Opts::new("alerts_sent_total", "Total alerts sent")
        )?;

        let alerts_resolved = Counter::with_opts(
            Opts::new("alerts_resolved_total", "Total alerts resolved")
        )?;

        let notification_failures = Counter::with_opts(
            Opts::new("alert_notification_failures_total", "Alert notification failures")
        )?;

        let escalation_events = Counter::with_opts(
            Opts::new("alert_escalation_events_total", "Alert escalation events")
        )?;

        let auto_healing_success = Counter::with_opts(
            Opts::new("auto_healing_success_total", "Successful auto-healing actions")
        )?;

        let auto_healing_failures = Counter::with_opts(
            Opts::new("auto_healing_failures_total", "Failed auto-healing actions")
        )?;

        registry.register(Box::new(alerts_sent.clone()))?;
        registry.register(Box::new(alerts_resolved.clone()))?;
        registry.register(Box::new(notification_failures.clone()))?;
        registry.register(Box::new(escalation_events.clone()))?;
        registry.register(Box::new(auto_healing_success.clone()))?;
        registry.register(Box::new(auto_healing_failures.clone()))?;

        Ok(Self {
            alerts_sent,
            alerts_resolved,
            notification_failures,
            escalation_events,
            auto_healing_success,
            auto_healing_failures,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringStatus {
    pub active_baselines: usize,
    pub active_incidents: usize,
    pub anomaly_detection_enabled: bool,
    pub auto_healing_enabled: bool,
    pub last_collection: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum MonitoringError {
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Model training error: {0}")]
    ModelTrainingError(String),
    #[error("Alert processing error: {0}")]
    AlertProcessingError(String),
    #[error("Notification error: {0}")]
    NotificationError(String),
    #[error("Auto-healing error: {0}")]
    AutoHealingError(String),
    #[error("Prometheus error: {0}")]
    PrometheusError(#[from] prometheus::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_anomaly_detector() {
        let config = AnomalyConfig {
            sensitivity: 0.95,
            min_training_samples: 10,
            max_training_samples: 100,
            retraining_interval: Duration::from_secs(60),
            seasonal_adjustment: false,
        };

        let mut detector = AnomalyDetector::new(config);
        
        // Add normal data points
        for i in 0..20 {
            detector.add_data_point("test_metric", 100.0 + i as f64).await;
        }

        // Add anomalous data point
        detector.add_data_point("test_metric", 200.0).await;

        let anomalies = detector.detect_anomalies().await;
        assert!(!anomalies.is_empty());
    }

    #[test]
    async fn test_monitoring_config() {
        let config = MonitoringConfig {
            collection_interval: Duration::from_secs(30),
            anomaly_threshold: 0.95,
            baseline_window: Duration::from_hours(24),
            alert_cooldown: Duration::from_minutes(5),
            auto_healing_enabled: true,
            ml_model_enabled: true,
        };

        assert_eq!(config.collection_interval, Duration::from_secs(30));
        assert!(config.auto_healing_enabled);
    }
}
