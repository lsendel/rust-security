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

impl MetricsCollector {
    /// Create a new metrics collector
    pub async fn new(config: &ComplianceConfig) -> ComplianceResult<Self> {
        let prometheus_client = if let Some(url) = &config.data_sources.prometheus_url {
            let client = PrometheusClient::new(url.clone());

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
        };

        Ok(Self { config: config.clone(), prometheus_client })
    }

    /// Collect all available security metrics
    pub async fn collect_all_metrics(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut all_metrics = Vec::new();

        // Collect Prometheus metrics
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

        // Collect audit log metrics
        match self.collect_audit_metrics().await {
            Ok(mut metrics) => {
                info!("Collected {} metrics from audit logs", metrics.len());
                all_metrics.append(&mut metrics);
            }
            Err(e) => {
                error!("Failed to collect audit metrics: {}", e);
            }
        }

        // Collect system metrics
        match self.collect_system_metrics().await {
            Ok(mut metrics) => {
                info!("Collected {} system metrics", metrics.len());
                all_metrics.append(&mut metrics);
            }
            Err(e) => {
                error!("Failed to collect system metrics: {}", e);
            }
        }

        info!("Total metrics collected: {}", all_metrics.len());
        Ok(all_metrics)
    }

    /// Collect metrics from audit logs
    async fn collect_audit_metrics(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut metrics = Vec::new();
        let now = Utc::now();
        let one_hour_ago = now - Duration::hours(1);
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
            .map(|m| m.value as u64)
            .unwrap_or(0);

        let failed_events = metrics
            .iter()
            .find(|m| m.name == "audit_failed_events")
            .map(|m| m.value as u64)
            .unwrap_or(0);

        if total_events > 0 {
            let success_rate =
                ((total_events - failed_events) as f64 / total_events as f64) * 100.0;
            metrics.push(SecurityMetric {
                name: "audit_success_rate".to_string(),
                value: success_rate,
                threshold: 95.0,
                status: if success_rate >= 95.0 { MetricStatus::Pass } else { MetricStatus::Fail },
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
        let mut total_events = 0u64;
        let mut successful_events = 0u64;
        let mut failed_events = 0u64;
        let mut blocked_events = 0u64;
        let mut unique_users = std::collections::HashSet::new();
        let mut unique_ips = std::collections::HashSet::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<AuditLogEntry>(line) {
                Ok(entry) => {
                    if entry.timestamp < since {
                        continue;
                    }

                    total_events += 1;

                    match entry.result {
                        AuditResult::Success => successful_events += 1,
                        AuditResult::Failure => failed_events += 1,
                        AuditResult::Blocked => blocked_events += 1,
                        AuditResult::Warning => {} // Don't count warnings as failures
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
                    // Try alternative parsing formats here if needed
                }
            }
        }

        let now = Utc::now();
        let mut metrics = vec![
            SecurityMetric {
                name: "audit_total_events".to_string(),
                value: total_events as f64,
                threshold: 0.0, // No threshold for count metrics
                status: MetricStatus::Pass,
                description: format!("Total audit events in {}", log_path),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
            SecurityMetric {
                name: "audit_successful_events".to_string(),
                value: successful_events as f64,
                threshold: 0.0,
                status: MetricStatus::Pass,
                description: format!("Successful audit events in {}", log_path),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
            SecurityMetric {
                name: "audit_failed_events".to_string(),
                value: failed_events as f64,
                threshold: 100.0, // Fail if more than 100 failures
                status: if failed_events <= 100 { MetricStatus::Pass } else { MetricStatus::Fail },
                description: format!("Failed audit events in {}", log_path),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
            SecurityMetric {
                name: "audit_blocked_events".to_string(),
                value: blocked_events as f64,
                threshold: 50.0, // Warn if more than 50 blocked events
                status: if blocked_events <= 50 {
                    MetricStatus::Pass
                } else {
                    MetricStatus::Warning
                },
                description: format!("Blocked audit events in {}", log_path),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
            SecurityMetric {
                name: "audit_unique_users".to_string(),
                value: unique_users.len() as f64,
                threshold: 0.0,
                status: MetricStatus::Pass,
                description: format!("Unique users in audit events from {}", log_path),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
            SecurityMetric {
                name: "audit_unique_ips".to_string(),
                value: unique_ips.len() as f64,
                threshold: 1000.0, // Warn if more than 1000 unique IPs
                status: if unique_ips.len() <= 1000 {
                    MetricStatus::Pass
                } else {
                    MetricStatus::Warning
                },
                description: format!("Unique IP addresses in audit events from {}", log_path),
                timestamp: now,
                tags: HashMap::from([("log_file".to_string(), log_path.to_string())]),
            },
        ];

        Ok(metrics)
    }

    /// Collect system-level security metrics
    async fn collect_system_metrics(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut metrics = Vec::new();
        let now = Utc::now();

        // Certificate expiration check
        if let Ok(cert_metrics) = self.check_certificate_expiration().await {
            metrics.extend(cert_metrics);
        }

        // Security policy compliance
        if let Ok(policy_metrics) = self.check_security_policies().await {
            metrics.extend(policy_metrics);
        }

        // Service health check
        if let Ok(health_metrics) = self.check_service_health().await {
            metrics.extend(health_metrics);
        }

        Ok(metrics)
    }

    /// Check certificate expiration status
    async fn check_certificate_expiration(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut metrics = Vec::new();
        let now = Utc::now();

        // This is a simplified implementation
        // In practice, you would check actual certificates
        let cert_paths = vec!["/etc/ssl/certs/auth-service.crt", "/etc/ssl/certs/api-gateway.crt"];

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
                description: format!("Days until certificate expiry for {}", cert_path),
                timestamp: now,
                tags: HashMap::from([("certificate_path".to_string(), cert_path.to_string())]),
            });
        }

        Ok(metrics)
    }

    /// Check security policy compliance
    async fn check_security_policies(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut metrics = Vec::new();
        let now = Utc::now();

        // Example security policy checks
        let policies = vec![
            ("password_policy", "Strong password policy enabled", true),
            ("mfa_enforced", "Multi-factor authentication enforced", true),
            ("session_timeout", "Session timeout configured", true),
            ("audit_logging", "Audit logging enabled", true),
            ("encryption_at_rest", "Encryption at rest enabled", true),
            ("encryption_in_transit", "Encryption in transit enabled", true),
        ];

        for (policy_name, description, enabled) in policies {
            metrics.push(SecurityMetric {
                name: format!("security_policy_{}", policy_name),
                value: if enabled { 1.0 } else { 0.0 },
                threshold: 1.0,
                status: if enabled { MetricStatus::Pass } else { MetricStatus::Fail },
                description: description.to_string(),
                timestamp: now,
                tags: HashMap::from([("policy_type".to_string(), "security".to_string())]),
            });
        }

        Ok(metrics)
    }

    /// Check service health status
    async fn check_service_health(&self) -> ComplianceResult<Vec<SecurityMetric>> {
        let mut metrics = Vec::new();
        let now = Utc::now();

        // Example service health checks
        let services = vec![
            ("auth-service", "http://localhost:8080/health"),
            ("policy-service", "http://localhost:8081/health"),
            ("threat-hunting", "http://localhost:8082/health"),
        ];

        let client =
            reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build()?;

        for (service_name, health_url) in services {
            let is_healthy = match client.get(health_url).send().await {
                Ok(response) => response.status().is_success(),
                Err(_) => false,
            };

            metrics.push(SecurityMetric {
                name: format!("service_health_{}", service_name),
                value: if is_healthy { 1.0 } else { 0.0 },
                threshold: 1.0,
                status: if is_healthy { MetricStatus::Pass } else { MetricStatus::Fail },
                description: format!("Health status of {}", service_name),
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
        let total_events = metrics.iter().find(|m| m.name == "audit_total_events").unwrap();
        assert_eq!(total_events.value, 2.0);

        let failed_events = metrics.iter().find(|m| m.name == "audit_failed_events").unwrap();
        assert_eq!(failed_events.value, 1.0);
    }
}
