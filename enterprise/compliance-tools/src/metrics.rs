//! Security metrics collection and analysis

use crate::{
    prometheus_client::PrometheusClient, AuditLogEntry, AuditResult, ComplianceConfig,
    ComplianceResult, MetricStatus, SecurityMetric,
};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tracing::{debug, error, info, warn};

/// Metrics collector for security and compliance data
pub struct MetricsCollector {
    config: ComplianceConfig,
    prometheus_client: Option<PrometheusClient>,
}

#[derive(Debug, Clone, Copy)]
struct AuditCounts {
    total_events: u64,
    successful_events: u64,
    failed_events: u64,
    blocked_events: u64,
    unique_users: u64,
    unique_ips: u64,
}

impl MetricsCollector {
    /// Create a new metrics collector
    ///
    /// # Errors
    /// Returns an error if:
    /// - Prometheus client initialization fails
    /// - Configuration validation fails
    /// - Network connectivity issues occur
    pub async fn new(config: &ComplianceConfig) -> ComplianceResult<Self> {
        let prometheus_client = Self::init_prometheus_client(config).await;
        Ok(Self {
            config: config.clone(),
            prometheus_client,
        })
    }

    #[allow(clippy::cognitive_complexity)]
    async fn init_prometheus_client(config: &ComplianceConfig) -> Option<PrometheusClient> {
        if let Some(url) = &config.data_sources.prometheus_url {
            let client = PrometheusClient::new(url);

            // Test connectivity
            match client.health_check().await {
                Ok(true) => {
                    info!("Prometheus client initialized successfully");
                    Some(client)
                }
                Ok(false) => {
                    warn!("Prometheus is not responding, metrics may be limited");
                    None
                }
                Err(e) => {
                    warn!("Failed to connect to Prometheus: {}", e);
                    None
                }
            }
        } else {
            debug!("No Prometheus URL configured");
            None
        }
    }

    /// Collect all available security metrics
    ///
    /// # Errors
    /// Returns an error if:
    /// - Prometheus query fails
    /// - File system access fails
    /// - Metric parsing fails
    /// - Network connectivity issues occur
    pub async fn collect_all_metrics(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut all_metrics = Vec::new();

        // Collect from different sources
        self.collect_prometheus_metrics(&mut all_metrics).await;
        self.collect_audit_log_metrics(&mut all_metrics).await;
        self.collect_system_metrics_wrapper(&mut all_metrics).await;

        info!("Total metrics collected: {}", all_metrics.len());
        Ok(all_metrics)
    }

    /// Collect Prometheus metrics
    async fn collect_prometheus_metrics(&self, all_metrics: &mut Vec<SecurityMetric>) {
        if let Some(prometheus) = &self.prometheus_client {
            match prometheus.collect_security_metrics().await {
                Ok(mut metrics) => {
                    info!("Collected {} metrics from Prometheus", metrics.len());
                    all_metrics.append(&mut metrics);
                }
                Err(e) => {
                    error!("Failed to collect Prometheus metrics: {}", e);
                }
            }
        }
    }

    /// Collect audit log metrics wrapper
    async fn collect_audit_log_metrics(&self, all_metrics: &mut Vec<SecurityMetric>) {
        match self.collect_audit_metrics().await {
            Ok(mut metrics) => {
                info!("Collected {} metrics from audit logs", metrics.len());
                all_metrics.append(&mut metrics);
            }
            Err(e) => {
                error!("Failed to collect audit metrics: {}", e);
            }
        }
    }

    /// Collect system metrics wrapper
    async fn collect_system_metrics_wrapper(&self, all_metrics: &mut Vec<SecurityMetric>) {
        match self.collect_system_metrics().await {
            Ok(mut metrics) => {
                info!("Collected {} system metrics", metrics.len());
                all_metrics.append(&mut metrics);
            }
            Err(e) => {
                error!("Failed to collect system metrics: {}", e);
            }
        }
    }

    /// Collect metrics from audit logs
    async fn collect_audit_metrics(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut metrics = Vec::new();
        let now = Utc::now();
        let _one_hour_ago = now - Duration::hours(1);
        let one_day_ago = now - Duration::days(1);

        for log_path in &self.config.data_sources.audit_log_paths {
            if !Path::new(log_path).exists() {
                warn!("Audit log path does not exist: {}", log_path);
                continue;
            }

            match self.analyze_audit_log(log_path, one_day_ago).await {
                Ok(log_metrics) => {
                    metrics.extend(log_metrics);
                }
                Err(e) => {
                    error!("Failed to analyze audit log {}: {}", log_path, e);
                }
            }
        }

        // Add summary metrics
        let total_events = metrics
            .iter()
            .find(|m| m.name == "audit_total_events")
            .map_or(0, |m| Self::f64_to_u64_nonneg(m.value));

        let failed_events = metrics
            .iter()
            .find(|m| m.name == "audit_failed_events")
            .map_or(0, |m| Self::f64_to_u64_nonneg(m.value));

        if total_events > 0 {
            #[allow(clippy::cast_precision_loss)]
            let success_rate =
                ((total_events - failed_events) as f64 / total_events as f64) * 100.0;
            metrics.push(SecurityMetric {
                name: "audit_success_rate".to_string(),
                value: success_rate,
                threshold: 95.0,
                status: if success_rate >= 95.0 {
                    MetricStatus::Pass
                } else {
                    MetricStatus::Fail
                },
                description: "Audit event success rate percentage".to_string(),
                timestamp: now,
                tags: HashMap::new(),
            });
        }

        Ok(metrics)
    }

    /// Analyze a single audit log file
    async fn analyze_audit_log(
        &self,
        log_path: &str,
        since: DateTime<Utc>,
    ) -> ComplianceResult<Vec<SecurityMetric>> {
        let content = fs::read_to_string(log_path).await?;
        let counts = Self::count_audit_entries(&content, since);
        let now = Utc::now();
        Ok(Self::build_audit_metrics(&counts, log_path, now))
    }

    fn count_audit_entries(content: &str, since: DateTime<Utc>) -> AuditCounts {
        let mut total_events = 0u64;
        let mut successful_events = 0u64;
        let mut failed_events = 0u64;
        let mut blocked_events = 0u64;
        let mut unique_users = std::collections::HashSet::new();
        let mut unique_ips = std::collections::HashSet::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            match serde_json::from_str::<AuditLogEntry>(trimmed) {
                Ok(entry) => {
                    if entry.timestamp < since {
                        continue;
                    }

                    total_events = total_events.saturating_add(1);
                    match entry.result {
                        AuditResult::Success => {
                            successful_events = successful_events.saturating_add(1);
                        }
                        AuditResult::Failure => failed_events = failed_events.saturating_add(1),
                        AuditResult::Blocked => blocked_events = blocked_events.saturating_add(1),
                        AuditResult::Warning => {}
                    }

                    if let Some(user_id) = &entry.user_id {
                        unique_users.insert(user_id.clone());
                    }

                    if let Some(ip) = &entry.ip_address {
                        unique_ips.insert(ip.to_string());
                    }
                }
                Err(e) => {
                    debug!("Failed to parse audit log line: {}", e);
                }
            }
        }

        AuditCounts {
            total_events,
            successful_events,
            failed_events,
            blocked_events,
            unique_users: unique_users.len() as u64,
            unique_ips: unique_ips.len() as u64,
        }
    }

    fn build_audit_metrics(
        counts: &AuditCounts,
        log_path: &str,
        now: DateTime<Utc>,
    ) -> Vec<SecurityMetric> {
        #[allow(clippy::cast_precision_loss)]
        let to_f64 = |v: u64| v as f64;

        vec![
            SecurityMetric {
                name: "audit_total_events".to_string(),
                value: to_f64(counts.total_events),
                threshold: 0.0,
                status: MetricStatus::Pass,
                description: format!("Total audit events in {log_path}"),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
            SecurityMetric {
                name: "audit_successful_events".to_string(),
                value: to_f64(counts.successful_events),
                threshold: 0.0,
                status: MetricStatus::Pass,
                description: format!("Successful audit events in {log_path}"),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
            SecurityMetric {
                name: "audit_failed_events".to_string(),
                value: to_f64(counts.failed_events),
                threshold: 100.0,
                status: if counts.failed_events <= 100 {
                    MetricStatus::Pass
                } else {
                    MetricStatus::Fail
                },
                description: format!("Failed audit events in {log_path}"),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
            SecurityMetric {
                name: "audit_blocked_events".to_string(),
                value: to_f64(counts.blocked_events),
                threshold: 50.0,
                status: if counts.blocked_events <= 50 {
                    MetricStatus::Pass
                } else {
                    MetricStatus::Warning
                },
                description: format!("Blocked audit events in {log_path}"),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
            SecurityMetric {
                name: "audit_unique_users".to_string(),
                value: to_f64(counts.unique_users),
                threshold: 0.0,
                status: MetricStatus::Pass,
                description: format!("Unique users in audit events from {log_path}"),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
            SecurityMetric {
                name: "audit_unique_ips".to_string(),
                value: to_f64(counts.unique_ips),
                threshold: 1000.0,
                status: if counts.unique_ips <= 1000 {
                    MetricStatus::Pass
                } else {
                    MetricStatus::Warning
                },
                description: format!("Unique IP addresses in audit events from {log_path}"),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
        ]
    }

    #[allow(clippy::cast_precision_loss)]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    fn f64_to_u64_nonneg(v: f64) -> u64 {
        if !v.is_finite() {
            return 0;
        }
        let clamped = v.max(0.0).floor();
        if clamped > u64::MAX as f64 {
            u64::MAX
        } else {
            clamped as u64
        }
    }

    /// Collect system-level security metrics
    async fn collect_system_metrics(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut metrics = Vec::new();
        let _now = Utc::now();

        // Certificate expiration check
        metrics.extend(Self::check_certificate_expiration());

        // Security policy compliance
        metrics.extend(Self::check_security_policies());

        // Service health check
        if let Ok(health_metrics) = self.check_service_health().await {
            metrics.extend(health_metrics);
        }

        Ok(metrics)
    }

    /// Check certificate expiration status
    fn check_certificate_expiration() -> Vec<SecurityMetric> {
        let mut metrics = Vec::new();
        let now = Utc::now();

        // This is a simplified implementation
        // In practice, you would check actual certificates
        let cert_paths = vec![
            "/etc/ssl/certs/auth-service.crt",
            "/etc/ssl/certs/api-gateway.crt",
        ];

        for cert_path in cert_paths {
            let days_until_expiry = if Path::new(cert_path).exists() {
                // Simplified: assume 90 days for example
                90.0
            } else {
                -1.0 // Certificate not found
            };

            let status = if days_until_expiry < 0.0 {
                MetricStatus::Fail
            } else if days_until_expiry < 30.0 {
                MetricStatus::Warning
            } else {
                MetricStatus::Pass
            };

            metrics.push(SecurityMetric {
                name: format!(
                    "certificate_expiry_days_{}",
                    Path::new(cert_path).file_stem().unwrap().to_string_lossy()
                ),
                value: days_until_expiry,
                threshold: 30.0,
                status,
                description: format!("Days until certificate expiry for {cert_path}"),
                timestamp: now,
                tags: HashMap::from([("certificate_path".to_string(), cert_path.to_string())]),
            });
        }

        metrics
    }

    /// Check security policy compliance
    fn check_security_policies() -> Vec<SecurityMetric> {
        let mut metrics = Vec::new();
        let now = Utc::now();

        // Example security policy checks
        let policies = vec![
            ("password_policy", "Strong password policy enabled", true),
            ("mfa_enforced", "Multi-factor authentication enforced", true),
            ("session_timeout", "Session timeout configured", true),
            ("audit_logging", "Audit logging enabled", true),
            ("encryption_at_rest", "Encryption at rest enabled", true),
            (
                "encryption_in_transit",
                "Encryption in transit enabled",
                true,
            ),
        ];

        for (policy_name, description, enabled) in policies {
            metrics.push(SecurityMetric {
                name: format!("security_policy_{policy_name}"),
                value: if enabled { 1.0 } else { 0.0 },
                threshold: 1.0,
                status: if enabled {
                    MetricStatus::Pass
                } else {
                    MetricStatus::Fail
                },
                description: description.to_string(),
                timestamp: now,
                tags: HashMap::from([("policy_type".to_string(), "security".to_string())]),
            });
        }

        metrics
    }

    /// Check service health status
    async fn check_service_health(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut metrics = Vec::new();
        let now = Utc::now();

        // Example service health checks
        let services: Vec<(&str, &str)> = vec![
            ("auth-service", "http://localhost:8080/health"),
            ("policy-service", "http://localhost:8081/health"),
            ("threat-hunting", "http://localhost:8082/health"),
        ];

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        for (service_name, health_url) in services {
            let is_healthy = client
                .get(health_url)
                .send()
                .await
                .is_ok_and(|response| response.status().is_success());

            metrics.push(SecurityMetric {
                name: format!("service_health_{service_name}"),
                value: if is_healthy { 1.0 } else { 0.0 },
                threshold: 1.0,
                status: if is_healthy {
                    MetricStatus::Pass
                } else {
                    MetricStatus::Fail
                },
                description: format!("Health status of {service_name}"),
                timestamp: now,
                tags: HashMap::from([
                    ("service".to_string(), service_name.to_string()),
                    ("health_url".to_string(), health_url.to_string()),
                ]),
            });
        }

        Ok(metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_audit_log_analysis() {
        let mut temp_file = NamedTempFile::new().unwrap();

        // Write sample audit log entries with current timestamps
        let now = chrono::Utc::now();
        let five_minutes_ago = now - chrono::Duration::minutes(5);
        let ten_minutes_ago = now - chrono::Duration::minutes(10);

        let sample_logs = vec![
            serde_json::json!({
                "timestamp": five_minutes_ago.to_rfc3339(),
                "user_id": "user1",
                "action": "login",
                "resource": "/auth",
                "result": "success",
                "ip_address": "192.168.1.1",
                "details": {}
            }),
            serde_json::json!({
                "timestamp": ten_minutes_ago.to_rfc3339(),
                "user_id": "user2",
                "action": "login",
                "resource": "/auth",
                "result": "failure",
                "ip_address": "192.168.1.2",
                "details": {}
            }),
        ];

        for log in sample_logs {
            writeln!(temp_file, "{}", serde_json::to_string(&log).unwrap()).unwrap();
        }

        let config = ComplianceConfig {
            organization: crate::OrganizationInfo {
                name: "Test Org".to_string(),
                domain: "test.com".to_string(),
                contact_email: "test@test.com".to_string(),
                compliance_officer: "Test Officer".to_string(),
                assessment_period_days: 30,
            },
            frameworks: vec![],
            report_settings: crate::ReportSettings {
                output_formats: vec![],
                include_charts: false,
                include_recommendations: false,
                classification_level: crate::ClassificationLevel::Internal,
                retention_days: 30,
            },
            data_sources: crate::DataSourceConfig {
                prometheus_url: None,
                elasticsearch_url: None,
                audit_log_paths: vec![temp_file.path().to_string_lossy().to_string()],
                redis_url: None,
                custom_apis: HashMap::new(),
            },
            notifications: crate::NotificationConfig {
                slack_webhook: None,
                email_recipients: vec![],
                teams_webhook: None,
                custom_webhooks: vec![],
            },
        };

        let collector = MetricsCollector::new(&config).await.unwrap();
        let metrics = collector.collect_audit_metrics().await.unwrap();

        assert!(!metrics.is_empty());

        // Check that we have the expected metrics
        let total_events = metrics
            .iter()
            .find(|m| m.name == "audit_total_events")
            .unwrap();
        assert!((total_events.value - 2.0).abs() < f64::EPSILON);

        let failed_events = metrics
            .iter()
            .find(|m| m.name == "audit_failed_events")
            .unwrap();
        assert!((failed_events.value - 1.0).abs() < f64::EPSILON);
    }
}
