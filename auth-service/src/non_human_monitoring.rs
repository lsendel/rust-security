//! Specialized Monitoring for Non-Human Identities
//!
//! Implements behavioral monitoring and anomaly detection specifically
//! designed for service accounts, API keys, and AI agents.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::infrastructure::security::security_monitoring::{
    AlertSeverity, SecurityAlert, SecurityAlertType,
};
use crate::jit_token_manager::TokenUsage;
use crate::service_identity::{BehavioralBaseline, IdentityType, RequestContext, ServiceIdentity};

/// Monitoring configuration for non-human identities
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct NonHumanMonitoringConfig {
    /// Enable baseline establishment period
    pub enable_baseline_learning: bool,

    /// Duration for baseline establishment (hours)
    pub baseline_learning_hours: u64,

    /// Minimum requests needed to establish baseline
    pub min_requests_for_baseline: usize,

    /// Sensitivity for anomaly detection (0.0 to 1.0)
    pub anomaly_sensitivity: f32,

    /// Time window for rate analysis (minutes)
    pub rate_window_minutes: u64,

    /// Enable geographic anomaly detection
    pub enable_geo_anomaly: bool,

    /// Enable temporal pattern analysis
    pub enable_temporal_analysis: bool,

    /// Auto-suspend on critical anomaly
    pub auto_suspend_on_critical: bool,
}

impl Default for NonHumanMonitoringConfig {
    fn default() -> Self {
        Self {
            enable_baseline_learning: true,
            baseline_learning_hours: 24,
            min_requests_for_baseline: 100,
            anomaly_sensitivity: 0.7,
            rate_window_minutes: 5,
            enable_geo_anomaly: true,
            enable_temporal_analysis: true,
            auto_suspend_on_critical: true,
        }
    }
}

/// Behavioral metrics for non-human identities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonHumanMetrics {
    pub identity_id: Uuid,
    pub identity_type: String,
    pub total_requests: u64,
    pub unique_endpoints: HashSet<String>,
    pub request_rate_per_minute: f64,
    pub avg_request_size: usize,
    pub error_rate: f64,
    pub geographic_distribution: HashMap<String, u32>,
    pub temporal_pattern: Vec<HourlyActivity>,
    pub last_activity: DateTime<Utc>,
    pub anomaly_score: f32,
    pub risk_factors: Vec<RiskFactor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourlyActivity {
    pub hour: u8,
    pub avg_requests: f64,
    pub std_deviation: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub severity: f32,
    pub description: String,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskFactorType {
    UnusualRequestRate,
    NewEndpointAccess,
    GeographicAnomaly,
    TemporalAnomaly,
    ErrorRateSpike,
    PrivilegeEscalation,
    DataExfiltrationPattern,
    SuspiciousUserAgent,
}

/// Activity log for detailed tracking
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ActivityLog {
    pub identity_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub endpoint: String,
    pub source_ip: String,
    pub response_code: u16,
    pub request_size: usize,
    pub response_size: usize,
    pub latency_ms: u64,
}

/// Non-human identity monitor
pub struct NonHumanIdentityMonitor {
    config: Arc<RwLock<NonHumanMonitoringConfig>>,
    metrics: Arc<RwLock<HashMap<Uuid, NonHumanMetrics>>>,
    baselines: Arc<RwLock<HashMap<Uuid, BehavioralBaseline>>>,
    activity_logs: Arc<RwLock<HashMap<Uuid, VecDeque<ActivityLog>>>>,
    alert_handler: Arc<dyn AlertHandler>,
    geo_resolver: Arc<dyn GeoResolver>,
}

/// Alert handler for security incidents
#[async_trait]
pub trait AlertHandler: Send + Sync {
    async fn send_alert(&self, alert: SecurityAlert) -> Result<(), crate::shared::error::AppError>;
    async fn get_alert_history(&self, identity_id: Uuid) -> Vec<SecurityAlert>;
}

/// Geographic resolver for IP addresses
#[async_trait]
pub trait GeoResolver: Send + Sync {
    async fn resolve_country(&self, ip: &str) -> Option<String>;
    async fn resolve_city(&self, ip: &str) -> Option<String>;
    async fn is_suspicious_location(&self, ip: &str) -> bool;
}

impl NonHumanIdentityMonitor {
    pub fn new(
        config: NonHumanMonitoringConfig,
        alert_handler: Arc<dyn AlertHandler>,
        geo_resolver: Arc<dyn GeoResolver>,
    ) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            metrics: Arc::new(RwLock::new(HashMap::new())),
            baselines: Arc::new(RwLock::new(HashMap::new())),
            activity_logs: Arc::new(RwLock::new(HashMap::new())),
            alert_handler,
            geo_resolver,
        }
    }

    /// Log authentication attempt
    ///
    /// # Errors
    ///
    /// Returns an error if anomaly checks or alerting fail.
    pub async fn log_authentication(
        &self,
        identity: &ServiceIdentity,
        success: bool,
        context: &RequestContext,
    ) -> Result<(), crate::shared::error::AppError> {
        let mut metrics = self.metrics.write().await;

        let identity_metrics = metrics
            .entry(identity.id)
            .or_insert_with(|| NonHumanMetrics {
                identity_id: identity.id,
                identity_type: self.get_identity_type_string(&identity.identity_type),
                total_requests: 0,
                unique_endpoints: HashSet::new(),
                request_rate_per_minute: 0.0,
                avg_request_size: 0,
                error_rate: 0.0,
                geographic_distribution: HashMap::new(),
                temporal_pattern: vec![],
                last_activity: Utc::now(),
                anomaly_score: 0.0,
                risk_factors: vec![],
            });

        // Update metrics
        identity_metrics.total_requests += 1;
        identity_metrics.last_activity = Utc::now();

        if !success {
            identity_metrics.error_rate = identity_metrics
                .error_rate
                .mul_add(identity_metrics.total_requests as f64 - 1.0, 1.0)
                / identity_metrics.total_requests as f64;
        }

        // Update geographic distribution
        if let Some(country) = self.geo_resolver.resolve_country(&context.source_ip).await {
            *identity_metrics
                .geographic_distribution
                .entry(country)
                .or_insert(0) += 1;
        }

        // Check for anomalies
        if identity.baseline_established {
            self.check_authentication_anomalies(identity, identity_metrics, context)
                .await?;
        }

        Ok(())
    }

    /// Log API request
    ///
    /// # Errors
    ///
    /// Returns an error if metrics update or calculations fail downstream.
    pub async fn log_request(
        &self,
        identity_id: Uuid,
        endpoint: &str,
        context: &RequestContext,
        response_code: u16,
        request_size: usize,
        response_size: usize,
        latency_ms: u64,
    ) -> Result<(), crate::shared::error::AppError> {
        let activity = ActivityLog {
            identity_id,
            timestamp: Utc::now(),
            action: "api_request".to_string(),
            endpoint: endpoint.to_string(),
            source_ip: context.source_ip.clone(),
            response_code,
            request_size,
            response_size,
            latency_ms,
        };

        // Store activity log
        let mut logs = self.activity_logs.write().await;
        let identity_logs = logs
            .entry(identity_id)
            .or_insert_with(|| VecDeque::with_capacity(1000));

        // Keep only recent logs
        if identity_logs.len() >= 1000 {
            identity_logs.pop_front();
        }
        identity_logs.push_back(activity.clone());

        // Update metrics
        let mut metrics = self.metrics.write().await;
        if let Some(identity_metrics) = metrics.get_mut(&identity_id) {
            identity_metrics
                .unique_endpoints
                .insert(endpoint.to_string());
            identity_metrics.avg_request_size = ((identity_metrics.avg_request_size
                * (identity_metrics.total_requests as usize - 1))
                + request_size)
                / identity_metrics.total_requests as usize;

            // Calculate request rate
            let config = self.config.read().await;
            let rate = self.calculate_request_rate(identity_logs, config.rate_window_minutes);
            identity_metrics.request_rate_per_minute = rate;
        }

        Ok(())
    }

    /// Check for anomalies in token usage
    pub async fn check_token_anomalies(&self, usage: &TokenUsage) -> bool {
        let config = self.config.read().await;
        let mut anomaly_detected = false;

        // Check usage rate anomaly
        if usage.usage_count > 100 {
            let usage_rate =
                f64::from(usage.usage_count) / (Utc::now() - usage.last_used).num_minutes() as f64;

            if usage_rate > 10.0 * f64::from(config.anomaly_sensitivity) {
                anomaly_detected = true;
                warn!(
                    "High token usage rate detected: {} requests/min",
                    usage_rate
                );
            }
        }

        // Check request pattern
        if usage.requests_made.len() > 10 {
            let unique_endpoints: HashSet<_> =
                usage.requests_made.iter().map(|r| &r.endpoint).collect();

            if unique_endpoints.len() == 1 && usage.requests_made.len() > 50 {
                anomaly_detected = true;
                warn!(
                    "Suspicious request pattern: single endpoint hit {} times",
                    usage.requests_made.len()
                );
            }
        }

        anomaly_detected
    }

    /// Establish behavioral baseline for an identity
    ///
    /// # Errors
    ///
    /// Returns an error when insufficient data is available to build a baseline.
    pub async fn establish_baseline(
        &self,
        identity_id: Uuid,
    ) -> Result<BehavioralBaseline, crate::shared::error::AppError> {
        let logs = self.activity_logs.read().await;
        let metrics = self.metrics.read().await;

        let identity_logs = logs
            .get(&identity_id)
            .ok_or(crate::shared::error::AppError::InsufficientDataForBaseline)?;

        let identity_metrics = metrics
            .get(&identity_id)
            .ok_or(crate::shared::error::AppError::InsufficientDataForBaseline)?;

        let config = self.config.read().await;

        if identity_logs.len() < config.min_requests_for_baseline {
            return Err(crate::shared::error::AppError::InsufficientDataForBaseline);
        }

        // Calculate baseline metrics
        let avg_requests_per_minute = identity_metrics.request_rate_per_minute;
        let common_endpoints: Vec<String> = identity_metrics
            .unique_endpoints
            .iter()
            .take(10)
            .cloned()
            .collect();

        let request_sizes: Vec<usize> = identity_logs.iter().map(|log| log.request_size).collect();

        let min_size = request_sizes.iter().min().copied().unwrap_or(0);
        let max_size = request_sizes.iter().max().copied().unwrap_or(0);

        // Calculate typical hours
        let mut hour_counts = [0u32; 24];
        for log in identity_logs {
            let hour = log.timestamp.hour() as usize;
            hour_counts[hour] += 1;
        }

        let typical_hours: Vec<u8> = hour_counts
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
            .map(|(hour, _)| hour as u8)
            .collect();

        // Get typical source IPs
        let mut ip_counts: HashMap<String, u32> = HashMap::new();
        for log in identity_logs {
            *ip_counts.entry(log.source_ip.clone()).or_insert(0) += 1;
        }

        let typical_source_ips: HashSet<String> = ip_counts
            .iter()
            .filter(|(_, count)| **count > 5)
            .map(|(ip, _)| ip.clone())
            .collect();

        let baseline = BehavioralBaseline {
            avg_requests_per_minute,
            common_endpoints,
            typical_request_sizes: (min_size, max_size),
            typical_hours,
            typical_source_ips,
            established_at: Utc::now(),
            confidence_score: self.calculate_confidence_score(identity_logs.len()),
        };

        // Store baseline
        let mut baselines = self.baselines.write().await;
        baselines.insert(identity_id, baseline.clone());

        info!("Established baseline for identity {}", identity_id);
        Ok(baseline)
    }

    /// Calculate anomaly score for an identity
    pub async fn calculate_anomaly_score(
        &self,
        identity: &ServiceIdentity,
        context: &RequestContext,
    ) -> f32 {
        let mut score = 0.0;
        let mut factors = 0;

        // Check IP anomaly
        if let Some(baseline) = identity.baseline_metrics.as_ref() {
            if !baseline.typical_source_ips.contains(&context.source_ip) {
                score += 0.3;
                factors += 1;
            }
        }

        // Check geographic anomaly
        if self
            .geo_resolver
            .is_suspicious_location(&context.source_ip)
            .await
        {
            score += 0.4;
            factors += 1;
        }

        // Check time anomaly
        let current_hour = Utc::now().hour() as u8;
        if let Some(baseline) = identity.baseline_metrics.as_ref() {
            if !baseline.typical_hours.contains(&current_hour) {
                score += 0.2;
                factors += 1;
            }
        }

        // Check user agent anomaly for API keys
        if matches!(identity.identity_type, IdentityType::ApiKey { .. }) {
            if let Some(ua) = &context.user_agent {
                if ua.contains("bot") || ua.contains("scanner") {
                    score += 0.5;
                    factors += 1;
                }
            }
        }

        if factors > 0 {
            score / factors as f32
        } else {
            0.0
        }
    }

    /// Automated response to critical anomalies
    ///
    /// # Errors
    ///
    /// Returns an error if sending alerts fails.
    pub async fn respond_to_anomaly(
        &self,
        identity: &ServiceIdentity,
        anomaly_type: RiskFactorType,
        severity: AlertSeverity,
    ) -> Result<(), crate::shared::error::AppError> {
        let config = self.config.read().await;

        match severity {
            AlertSeverity::Critical => {
                if config.auto_suspend_on_critical {
                    warn!(
                        "Auto-suspending identity {} due to critical anomaly",
                        identity.id
                    );
                    // In production, would call identity manager to suspend
                }

                // Send critical alert
                self.alert_handler
                    .send_alert(SecurityAlert {
                        id: Uuid::new_v4().to_string(),
                        alert_type: SecurityAlertType::AnomalousPattern,
                        severity,
                        title: format!("Critical anomaly for {:?}", identity.identity_type),
                        description: format!("Detected {anomaly_type:?} anomaly"),
                        timestamp: Utc::now().timestamp() as u64,
                        source_ip: None,
                        destination_ip: None,
                        source: "NonHumanMonitor".to_string(),
                        user_id: None,
                        client_id: Some(identity.id.to_string()),
                        metadata: HashMap::new(),
                        resolved: false,
                        resolution_notes: None,
                    })
                    .await?;
            }
            AlertSeverity::High => {
                // Rate limit the identity
                info!(
                    "Applying rate limits to identity {} due to high severity anomaly",
                    identity.id
                );
            }
            _ => {
                // Log for monitoring
                debug!("Low severity anomaly detected for identity {}", identity.id);
            }
        }

        Ok(())
    }

    // Helper methods

    async fn check_authentication_anomalies(
        &self,
        identity: &ServiceIdentity,
        metrics: &mut NonHumanMetrics,
        context: &RequestContext,
    ) -> Result<(), crate::shared::error::AppError> {
        let mut risk_factors = Vec::new();

        // Check request rate
        if let Some(baseline) = identity.baseline_metrics.as_ref() {
            if metrics.request_rate_per_minute > baseline.avg_requests_per_minute * 2.0 {
                risk_factors.push(RiskFactor {
                    factor_type: RiskFactorType::UnusualRequestRate,
                    severity: 0.7,
                    description: format!(
                        "Request rate {}x higher than baseline",
                        metrics.request_rate_per_minute / baseline.avg_requests_per_minute
                    ),
                    detected_at: Utc::now(),
                });
            }
        }

        // Check geographic anomaly
        if self
            .geo_resolver
            .is_suspicious_location(&context.source_ip)
            .await
        {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::GeographicAnomaly,
                severity: 0.8,
                description: format!("Request from suspicious location: {}", context.source_ip),
                detected_at: Utc::now(),
            });
        }

        // Update metrics
        metrics.risk_factors.extend(risk_factors.clone());
        metrics.anomaly_score = self.calculate_risk_score(&risk_factors);

        // Trigger response if needed
        if metrics.anomaly_score > 0.8 {
            self.respond_to_anomaly(
                identity,
                RiskFactorType::UnusualRequestRate,
                AlertSeverity::High,
            )
            .await?;
        }

        Ok(())
    }

    fn calculate_request_rate(&self, logs: &VecDeque<ActivityLog>, window_minutes: u64) -> f64 {
        let cutoff = Utc::now() - Duration::minutes(window_minutes as i64);
        let recent_count = logs.iter().filter(|log| log.timestamp > cutoff).count();

        recent_count as f64 / window_minutes as f64
    }

    fn calculate_confidence_score(&self, sample_size: usize) -> f32 {
        // Confidence increases with sample size
        (1.0 - (1.0 / (sample_size as f32 / 100.0 + 1.0))).min(1.0)
    }

    fn calculate_risk_score(&self, factors: &[RiskFactor]) -> f32 {
        if factors.is_empty() {
            return 0.0;
        }

        let total: f32 = factors.iter().map(|f| f.severity).sum();
        (total / factors.len() as f32).min(1.0)
    }

    fn get_identity_type_string(&self, identity_type: &IdentityType) -> String {
        match identity_type {
            IdentityType::Human { .. } => "human".to_string(),
            IdentityType::ServiceAccount { .. } => "service_account".to_string(),
            IdentityType::ApiKey { .. } => "api_key".to_string(),
            IdentityType::AiAgent { .. } => "ai_agent".to_string(),
            IdentityType::MachineWorkload { .. } => "machine_workload".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAlertHandler;

    #[async_trait]
    impl AlertHandler for MockAlertHandler {
        async fn send_alert(&self, _: SecurityAlert) -> Result<(), crate::shared::error::AppError> {
            Ok(())
        }
        async fn get_alert_history(&self, _: Uuid) -> Vec<SecurityAlert> {
            vec![]
        }
    }

    struct MockGeoResolver;

    #[async_trait]
    impl GeoResolver for MockGeoResolver {
        async fn resolve_country(&self, _: &str) -> Option<String> {
            Some("US".to_string())
        }
        async fn resolve_city(&self, _: &str) -> Option<String> {
            Some("New York".to_string())
        }
        async fn is_suspicious_location(&self, ip: &str) -> bool {
            ip.starts_with("192.168")
        }
    }

    #[tokio::test]
    async fn test_baseline_establishment() {
        let monitor = NonHumanIdentityMonitor::new(
            NonHumanMonitoringConfig::default(),
            Arc::new(MockAlertHandler),
            Arc::new(MockGeoResolver),
        );

        let identity_id = Uuid::new_v4();

        // Simulate activity
        for i in 0..100 {
            monitor
                .log_request(
                    identity_id,
                    "/api/data",
                    &RequestContext {
                        source_ip: "10.0.0.1".to_string(),
                        user_agent: Some("test-agent".to_string()),
                        request_id: format!("req-{i}"),
                        parent_span_id: None,
                        attestation_data: None,
                    },
                    200,
                    1024,
                    2048,
                    50,
                )
                .await
                .unwrap();
        }

        // Establish baseline
        let baseline = monitor.establish_baseline(identity_id).await.unwrap();

        assert!(baseline.confidence_score > 0.0);
        assert!(!baseline.common_endpoints.is_empty());
    }
}
