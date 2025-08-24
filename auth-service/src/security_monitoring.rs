#[cfg(feature = "monitoring")]
use crate::security_metrics::SECURITY_METRICS;
use once_cell::sync::Lazy;
#[cfg(feature = "monitoring")]
use prometheus::{Encoder, TextEncoder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: String,
    pub alert_type: SecurityAlertType,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub timestamp: u64,
    pub source_ip: Option<String>,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub resolved: bool,
    pub resolution_notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub enum SecurityAlertType {
    AuthenticationFailure,
    RateLimitExceeded,
    TokenBindingViolation,
    SuspiciousActivity,
    MfaBypass,
    InputValidationFailure,
    UnauthorizedAccess,
    AnomalousPattern,
    DataExfiltration,
    SystemIntegrity,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, utoipa::ToSchema,
)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SecurityThreshold {
    pub metric_name: String,
    pub threshold_value: f64,
    pub time_window_seconds: u64,
    pub alert_type: SecurityAlertType,
    pub severity: AlertSeverity,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub alert_retention_days: u64,
    pub max_alerts_per_hour: u32,
    pub notification_endpoints: Vec<NotificationEndpoint>,
    pub thresholds: Vec<SecurityThreshold>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NotificationEndpoint {
    pub name: String,
    pub endpoint_type: NotificationType,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub enabled: bool,
    pub min_severity: AlertSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub enum NotificationType {
    Webhook,
    Slack,
    Email,
    Pagerduty,
    Discord,
}

pub struct SecurityMonitor {
    config: Arc<RwLock<MonitoringConfig>>,
    active_alerts: Arc<Mutex<HashMap<String, SecurityAlert>>>,
    alert_history: Arc<Mutex<Vec<SecurityAlert>>>,
    metric_snapshots: Arc<Mutex<HashMap<String, f64>>>,
    client: reqwest::Client,
}

impl SecurityMonitor {
    pub fn new() -> Self {
        let default_config = MonitoringConfig {
            enabled: std::env::var("SECURITY_MONITORING_ENABLED").unwrap_or_default() == "true",
            alert_retention_days: 30,
            max_alerts_per_hour: 100,
            notification_endpoints: vec![],
            thresholds: Self::default_thresholds(),
        };

        Self {
            config: Arc::new(RwLock::new(default_config)),
            active_alerts: Arc::new(Mutex::new(HashMap::new())),
            alert_history: Arc::new(Mutex::new(Vec::new())),
            metric_snapshots: Arc::new(Mutex::new(HashMap::new())),
            client: reqwest::Client::new(),
        }
    }

    fn default_thresholds() -> Vec<SecurityThreshold> {
        vec![
            SecurityThreshold {
                metric_name: "auth_failures_total".to_string(),
                threshold_value: 10.0,
                time_window_seconds: 300, // 5 minutes
                alert_type: SecurityAlertType::AuthenticationFailure,
                severity: AlertSeverity::Medium,
                enabled: true,
            },
            SecurityThreshold {
                metric_name: "rate_limit_hits_total".to_string(),
                threshold_value: 5.0,
                time_window_seconds: 60, // 1 minute
                alert_type: SecurityAlertType::RateLimitExceeded,
                severity: AlertSeverity::High,
                enabled: true,
            },
            SecurityThreshold {
                metric_name: "token_binding_violations_total".to_string(),
                threshold_value: 1.0,
                time_window_seconds: 60,
                alert_type: SecurityAlertType::TokenBindingViolation,
                severity: AlertSeverity::Critical,
                enabled: true,
            },
            SecurityThreshold {
                metric_name: "mfa_failures_total".to_string(),
                threshold_value: 5.0,
                time_window_seconds: 300,
                alert_type: SecurityAlertType::MfaBypass,
                severity: AlertSeverity::High,
                enabled: true,
            },
            SecurityThreshold {
                metric_name: "input_validation_failures_total".to_string(),
                threshold_value: 20.0,
                time_window_seconds: 300,
                alert_type: SecurityAlertType::InputValidationFailure,
                severity: AlertSeverity::Medium,
                enabled: true,
            },
        ]
    }

    pub async fn start_monitoring(&self) {
        let config = self.config.clone();
        let active_alerts = self.active_alerts.clone();
        let alert_history = self.alert_history.clone();
        let metric_snapshots = self.metric_snapshots.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let config_guard = config.read().await;
                if !config_guard.enabled {
                    continue;
                }

                // Get current metrics
                let encoder = TextEncoder::new();
                let metric_families = SECURITY_METRICS.registry.gather();
                let mut buffer = Vec::new();
                if encoder.encode(&metric_families, &mut buffer).is_ok() {
                    let metrics_text = String::from_utf8_lossy(&buffer);

                    // Parse metrics and check thresholds
                    for threshold in &config_guard.thresholds {
                        if !threshold.enabled {
                            continue;
                        }

                        if let Some(current_value) =
                            Self::extract_metric_value(&metrics_text, &threshold.metric_name)
                        {
                            let mut snapshots = metric_snapshots.lock().await;
                            let previous_value = snapshots
                                .get(&threshold.metric_name)
                                .copied()
                                .unwrap_or(0.0);
                            snapshots.insert(threshold.metric_name.clone(), current_value);

                            let delta = current_value - previous_value;

                            if delta >= threshold.threshold_value {
                                let alert = SecurityAlert {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    alert_type: threshold.alert_type.clone(),
                                    severity: threshold.severity.clone(),
                                    title: format!("Security threshold exceeded: {}", threshold.metric_name),
                                    description: format!(
                                        "Metric '{}' increased by {:.2} (threshold: {:.2}) in the last {} seconds",
                                        threshold.metric_name,
                                        delta,
                                        threshold.threshold_value,
                                        threshold.time_window_seconds
                                    ),
                                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                    source_ip: None,
                                    user_id: None,
                                    client_id: None,
                                    metadata: [
                                        ("metric_name".to_string(), serde_json::Value::String(threshold.metric_name.clone())),
                                        ("current_value".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(current_value).unwrap())),
                                        ("previous_value".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(previous_value).unwrap())),
                                        ("delta".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(delta).unwrap())),
                                        ("threshold".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(threshold.threshold_value).unwrap())),
                                    ].into(),
                                    resolved: false,
                                    resolution_notes: None,
                                };

                                // Store alert
                                let mut alerts = active_alerts.lock().await;
                                alerts.insert(alert.id.clone(), alert.clone());

                                let mut history = alert_history.lock().await;
                                history.push(alert.clone());

                                // Send notifications
                                for endpoint in &config_guard.notification_endpoints {
                                    if !endpoint.enabled || alert.severity < endpoint.min_severity {
                                        continue;
                                    }

                                    let client_clone = client.clone();
                                    let alert_clone = alert.clone();
                                    let endpoint_clone = endpoint.clone();

                                    tokio::spawn(async move {
                                        if let Err(e) = Self::send_notification(
                                            &client_clone,
                                            &endpoint_clone,
                                            &alert_clone,
                                        )
                                        .await
                                        {
                                            error!("Failed to send notification: {}", e);
                                        }
                                    });
                                }

                                // Log alert
                                match alert.severity {
                                    AlertSeverity::Critical => error!(
                                        alert_id = %alert.id,
                                        alert_type = ?alert.alert_type,
                                        "Critical security alert: {}", alert.title
                                    ),
                                    AlertSeverity::High => warn!(
                                        alert_id = %alert.id,
                                        alert_type = ?alert.alert_type,
                                        "High severity security alert: {}", alert.title
                                    ),
                                    _ => info!(
                                        alert_id = %alert.id,
                                        alert_type = ?alert.alert_type,
                                        "Security alert: {}", alert.title
                                    ),
                                }
                            }
                        }
                    }
                }

                // Clean up old alerts
                Self::cleanup_old_alerts(&alert_history, config_guard.alert_retention_days).await;
            }
        });

        info!("Security monitoring started");
    }

    async fn send_notification(
        client: &reqwest::Client,
        endpoint: &NotificationEndpoint,
        alert: &SecurityAlert,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let payload = match endpoint.endpoint_type {
            NotificationType::Webhook => serde_json::to_value(alert)?,
            NotificationType::Slack => serde_json::json!({
                "text": format!("🚨 Security Alert: {}", alert.title),
                "attachments": [{
                    "color": match alert.severity {
                        AlertSeverity::Critical => "danger",
                        AlertSeverity::High => "warning",
                        AlertSeverity::Medium => "#ffaa00",
                        AlertSeverity::Low => "good",
                    },
                    "fields": [
                        {
                            "title": "Severity",
                            "value": format!("{:?}", alert.severity),
                            "short": true
                        },
                        {
                            "title": "Type",
                            "value": format!("{:?}", alert.alert_type),
                            "short": true
                        },
                        {
                            "title": "Description",
                            "value": alert.description,
                            "short": false
                        }
                    ]
                }]
            }),
            NotificationType::Discord => serde_json::json!({
                "content": format!("🚨 **Security Alert**: {}", alert.title),
                "embeds": [{
                    "title": "Security Alert Details",
                    "description": alert.description,
                    "color": match alert.severity {
                        AlertSeverity::Critical => 16711680, // Red
                        AlertSeverity::High => 16753920,    // Orange
                        AlertSeverity::Medium => 16776960,  // Yellow
                        AlertSeverity::Low => 65280,        // Green
                    },
                    "fields": [
                        {
                            "name": "Severity",
                            "value": format!("{:?}", alert.severity),
                            "inline": true
                        },
                        {
                            "name": "Type",
                            "value": format!("{:?}", alert.alert_type),
                            "inline": true
                        },
                        {
                            "name": "Timestamp",
                            "value": format!("<t:{}:F>", alert.timestamp),
                            "inline": true
                        }
                    ]
                }]
            }),
            _ => serde_json::to_value(alert)?,
        };

        let mut request = client.post(&endpoint.url);

        for (key, value) in &endpoint.headers {
            request = request.header(key, value);
        }

        let response = request.json(&payload).send().await?;

        if !response.status().is_success() {
            return Err(format!("Notification failed with status: {}", response.status()).into());
        }

        Ok(())
    }

    fn extract_metric_value(metrics_text: &str, metric_name: &str) -> Option<f64> {
        for line in metrics_text.lines() {
            if line.starts_with(metric_name) && !line.starts_with('#') {
                if let Some(value_str) = line.split_whitespace().last() {
                    return value_str.parse().ok();
                }
            }
        }
        None
    }

    async fn cleanup_old_alerts(
        alert_history: &Arc<Mutex<Vec<SecurityAlert>>>,
        retention_days: u64,
    ) {
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(retention_days * 24 * 3600);

        let mut history = alert_history.lock().await;
        history.retain(|alert| alert.timestamp > cutoff_time);
    }

    pub async fn get_active_alerts(&self) -> Vec<SecurityAlert> {
        let alerts = self.active_alerts.lock().await;
        alerts.values().cloned().collect()
    }

    pub async fn resolve_alert(&self, alert_id: &str, resolution_notes: Option<String>) -> bool {
        let mut alerts = self.active_alerts.lock().await;
        if let Some(alert) = alerts.get_mut(alert_id) {
            alert.resolved = true;
            alert.resolution_notes = resolution_notes;
            true
        } else {
            false
        }
    }

    pub async fn get_alert_history(&self, limit: Option<usize>) -> Vec<SecurityAlert> {
        let history = self.alert_history.lock().await;
        let start = if let Some(limit) = limit {
            history.len().saturating_sub(limit)
        } else {
            0
        };
        history[start..].to_vec()
    }

    pub async fn update_config(&self, new_config: MonitoringConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
        info!("Security monitoring configuration updated");
    }

    pub async fn get_config(&self) -> MonitoringConfig {
        self.config.read().await.clone()
    }

    /// Create a custom alert
    pub async fn create_alert(
        &self,
        alert_type: SecurityAlertType,
        severity: AlertSeverity,
        title: String,
        description: String,
        source_ip: Option<String>,
        user_id: Option<String>,
        client_id: Option<String>,
        metadata: HashMap<String, serde_json::Value>,
    ) {
        let alert = SecurityAlert {
            id: uuid::Uuid::new_v4().to_string(),
            alert_type,
            severity,
            title,
            description,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            source_ip,
            user_id,
            client_id,
            metadata,
            resolved: false,
            resolution_notes: None,
        };

        let mut alerts = self.active_alerts.lock().await;
        alerts.insert(alert.id.clone(), alert.clone());

        let mut history = self.alert_history.lock().await;
        history.push(alert);
    }
}

impl Default for SecurityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Global security monitor instance
pub static SECURITY_MONITOR: Lazy<SecurityMonitor> = Lazy::new(SecurityMonitor::new);

/// Initialize security monitoring
pub async fn init_security_monitoring() {
    SECURITY_MONITOR.start_monitoring().await;
}

/// Convenience function to create security alerts
pub async fn create_security_alert(
    alert_type: SecurityAlertType,
    severity: AlertSeverity,
    title: String,
    description: String,
    source_ip: Option<String>,
    user_id: Option<String>,
    client_id: Option<String>,
    metadata: HashMap<String, serde_json::Value>,
) {
    SECURITY_MONITOR
        .create_alert(
            alert_type,
            severity,
            title,
            description,
            source_ip,
            user_id,
            client_id,
            metadata,
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_monitor_creation() {
        let monitor = SecurityMonitor::new();
        let config = monitor.get_config().await;
        assert!(!config.thresholds.is_empty());
    }

    #[tokio::test]
    async fn test_alert_creation_and_resolution() {
        let monitor = SecurityMonitor::new();

        monitor
            .create_alert(
                SecurityAlertType::AuthenticationFailure,
                AlertSeverity::High,
                "Test Alert".to_string(),
                "Test Description".to_string(),
                Some("192.168.1.1".to_string()),
                None,
                None,
                HashMap::new(),
            )
            .await;

        let alerts = monitor.get_active_alerts().await;
        assert_eq!(alerts.len(), 1);

        let alert_id = &alerts[0].id;
        let resolved = monitor
            .resolve_alert(alert_id, Some("Test resolution".to_string()))
            .await;
        assert!(resolved);
    }

    #[test]
    fn test_metric_value_extraction() {
        let metrics_text = r#"
# HELP auth_failures_total Total authentication failures
# TYPE auth_failures_total counter
auth_failures_total{client_id="test",reason="invalid_credentials",ip_address="192.168.1.1"} 5
auth_attempts_total{client_id="test",method="client_credentials",result="success"} 10
"#;

        let value = SecurityMonitor::extract_metric_value(metrics_text, "auth_failures_total");
        assert_eq!(value, Some(5.0));

        let value2 = SecurityMonitor::extract_metric_value(metrics_text, "auth_attempts_total");
        assert_eq!(value2, Some(10.0));

        let none_value = SecurityMonitor::extract_metric_value(metrics_text, "nonexistent_metric");
        assert_eq!(none_value, None);
    }
}
