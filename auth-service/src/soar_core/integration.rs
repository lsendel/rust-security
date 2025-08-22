//! Integration framework for external security tools
//!
//! This module provides a framework for integrating with external security
//! tools and services, including health monitoring and metrics collection.

use super::types::*;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Integration framework for external tools
pub struct IntegrationFramework {
    /// Registered integrations
    integrations: Arc<DashMap<String, IntegrationConfig>>,

    /// Health check results
    health_status: Arc<DashMap<String, IntegrationHealthInfo>>,

    /// Integration metrics
    metrics: Arc<DashMap<String, IntegrationMetrics>>,

    /// Active integration instances
    active_integrations: Arc<DashMap<String, Box<dyn Integration + Send + Sync>>>,
}

impl IntegrationFramework {
    /// Create a new integration framework
    pub async fn new(
        configs: HashMap<String, IntegrationConfig>,
    ) -> Result<Self, IntegrationError> {
        let framework = Self {
            integrations: Arc::new(DashMap::new()),
            health_status: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            active_integrations: Arc::new(DashMap::new()),
        };

        // Initialize integrations from config
        for (id, config) in configs {
            framework.integrations.insert(id.clone(), config);

            // Initialize metrics
            framework.metrics.insert(
                id.clone(),
                IntegrationMetrics {
                    integration_name: id.clone(),
                    total_requests: 0,
                    successful_requests: 0,
                    failed_requests: 0,
                    avg_response_time_ms: 0.0,
                    last_request: None,
                    error_rate: 0.0,
                },
            );
        }

        Ok(framework)
    }

    /// Start health checks for all integrations
    pub async fn start_health_checks(&self) -> Result<(), IntegrationError> {
        info!("Starting integration health checks");

        let framework_clone = self.clone();
        tokio::spawn(async move {
            framework_clone.health_check_loop().await;
        });

        Ok(())
    }

    /// Stop the integration framework
    pub async fn stop(&self) -> Result<(), IntegrationError> {
        info!("Stopping integration framework");
        Ok(())
    }

    /// Register an integration
    pub async fn register_integration(
        &self,
        id: String,
        integration: Box<dyn Integration + Send + Sync>,
    ) -> Result<(), IntegrationError> {
        self.active_integrations.insert(id.clone(), integration);
        info!("Registered integration: {}", id);
        Ok(())
    }

    /// Execute action through integration
    pub async fn execute_action(
        &self,
        integration_id: &str,
        action: &StepAction,
        context: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, IntegrationError> {
        let start_time = std::time::Instant::now();

        // Get integration
        let integration = self
            .active_integrations
            .get(integration_id)
            .ok_or_else(|| IntegrationError {
                code: "INTEGRATION_NOT_FOUND".to_string(),
                message: format!("Integration not found: {}", integration_id),
                details: None,
                retryable: false,
            })?;

        // Execute action
        let result = integration.execute_action(action, context).await;

        // Update metrics
        let duration = start_time.elapsed();
        self.update_metrics(integration_id, &result, duration.as_millis() as f64)
            .await;

        result
    }

    /// Get health status for all integrations
    pub async fn get_health_summary(&self) -> Result<HealthMetrics, IntegrationError> {
        let total_integrations = self.integrations.len();
        let mut healthy_integrations = 0;
        let mut unhealthy_integrations = 0;

        for entry in self.health_status.iter() {
            match entry.value().status.status {
                IntegrationHealth::Healthy => healthy_integrations += 1,
                IntegrationHealth::Unhealthy => unhealthy_integrations += 1,
                _ => {}
            }
        }

        let overall_health_percentage = if total_integrations > 0 {
            (healthy_integrations * 100) / total_integrations
        } else {
            100
        };

        Ok(HealthMetrics {
            total_integrations,
            healthy_integrations,
            unhealthy_integrations,
            overall_health_percentage,
            last_check: Utc::now(),
        })
    }

    /// Get integration metrics
    pub async fn get_integration_metrics(
        &self,
        integration_id: &str,
    ) -> Option<IntegrationMetrics> {
        self.metrics
            .get(integration_id)
            .map(|entry| entry.value().clone())
    }

    /// Get all integration metrics
    pub async fn get_all_metrics(&self) -> HashMap<String, IntegrationMetrics> {
        self.metrics
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Health check loop
    async fn health_check_loop(&self) {
        let check_interval = tokio::time::Duration::from_secs(300); // 5 minutes
        let mut interval = tokio::time::interval(check_interval);

        loop {
            interval.tick().await;

            for entry in self.active_integrations.iter() {
                let integration_id = entry.key().clone();
                let integration = entry.value();

                match integration.health_check().await {
                    Ok(health_info) => {
                        self.health_status
                            .insert(integration_id.clone(), health_info);
                    }
                    Err(error) => {
                        let health_info = IntegrationHealthInfo {
                            integration_id: integration_id.clone(),
                            status: IntegrationHealth {
                                integration_name: integration_id.clone(),
                                status: super::types::IntegrationHealth::Unhealthy,
                                last_check: Utc::now(),
                                response_time_ms: 0,
                                error_message: Some(error.message.clone()),
                                metrics: HashMap::new(),
                            },
                            status_message: error.message,
                            response_time_ms: None,
                            last_check: Utc::now(),
                            consecutive_failures: 1,
                            metadata: HashMap::new(),
                        };

                        self.health_status.insert(integration_id, health_info);
                    }
                }
            }
        }
    }

    /// Update integration metrics
    async fn update_metrics(
        &self,
        integration_id: &str,
        result: &Result<HashMap<String, serde_json::Value>, IntegrationError>,
        response_time_ms: f64,
    ) {
        if let Some(mut metrics) = self.metrics.get_mut(integration_id) {
            metrics.total_requests += 1;
            metrics.last_request = Some(Utc::now());

            match result {
                Ok(_) => {
                    metrics.successful_requests += 1;
                }
                Err(_) => {
                    metrics.failed_requests += 1;
                }
            }

            // Update average response time
            let total_time = metrics.avg_response_time_ms * (metrics.total_requests - 1) as f64;
            metrics.avg_response_time_ms =
                (total_time + response_time_ms) / metrics.total_requests as f64;

            // Update error rate
            metrics.error_rate =
                (metrics.failed_requests as f64 / metrics.total_requests as f64) * 100.0;
        }
    }
}

impl Clone for IntegrationFramework {
    fn clone(&self) -> Self {
        Self {
            integrations: Arc::clone(&self.integrations),
            health_status: Arc::clone(&self.health_status),
            metrics: Arc::clone(&self.metrics),
            active_integrations: Arc::clone(&self.active_integrations),
        }
    }
}

/// Integration trait
#[async_trait::async_trait]
pub trait Integration {
    async fn execute_action(
        &self,
        action: &StepAction,
        context: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, IntegrationError>;

    async fn health_check(&self) -> Result<IntegrationHealthInfo, IntegrationError>;

    fn get_integration_type(&self) -> IntegrationType;

    fn get_integration_name(&self) -> String;
}

/// Integration manager for specific integration types
pub struct IntegrationManager {
    framework: Arc<IntegrationFramework>,
}

impl IntegrationManager {
    pub fn new(framework: Arc<IntegrationFramework>) -> Self {
        Self { framework }
    }

    /// Create SIEM integration
    pub async fn create_siem_integration(
        &self,
        config: IntegrationConfig,
    ) -> Result<Box<dyn Integration + Send + Sync>, IntegrationError> {
        Ok(Box::new(SiemIntegration::new(config).await?))
    }

    /// Create EDR integration
    pub async fn create_edr_integration(
        &self,
        config: IntegrationConfig,
    ) -> Result<Box<dyn Integration + Send + Sync>, IntegrationError> {
        Ok(Box::new(EdrIntegration::new(config).await?))
    }

    /// Create firewall integration
    pub async fn create_firewall_integration(
        &self,
        config: IntegrationConfig,
    ) -> Result<Box<dyn Integration + Send + Sync>, IntegrationError> {
        Ok(Box::new(FirewallIntegration::new(config).await?))
    }
}

/// SIEM integration implementation
pub struct SiemIntegration {
    config: IntegrationConfig,
    client: reqwest::Client,
}

impl SiemIntegration {
    pub async fn new(config: IntegrationConfig) -> Result<Self, IntegrationError> {
        let client = reqwest::Client::new();
        Ok(Self { config, client })
    }
}

#[async_trait::async_trait]
impl Integration for SiemIntegration {
    async fn execute_action(
        &self,
        action: &StepAction,
        context: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, IntegrationError> {
        match action {
            StepAction::QuerySiem {
                query,
                time_range,
                max_results,
            } => {
                debug!("Executing SIEM query: {}", query);

                // Simulate SIEM query execution
                let mut results = HashMap::new();
                results.insert(
                    "query_executed".to_string(),
                    serde_json::Value::String(query.clone()),
                );
                results.insert(
                    "time_range".to_string(),
                    serde_json::Value::String(time_range.clone()),
                );
                results.insert(
                    "max_results".to_string(),
                    serde_json::Value::Number((*max_results).into()),
                );
                results.insert(
                    "results_count".to_string(),
                    serde_json::Value::Number(42.into()),
                );

                Ok(results)
            }
            _ => Err(IntegrationError {
                code: "UNSUPPORTED_ACTION".to_string(),
                message: format!("SIEM integration does not support action: {:?}", action),
                details: None,
                retryable: false,
            }),
        }
    }

    async fn health_check(&self) -> Result<IntegrationHealthInfo, IntegrationError> {
        let start_time = std::time::Instant::now();

        // Simulate health check
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let response_time = start_time.elapsed().as_millis() as u64;

        Ok(IntegrationHealthInfo {
            integration_id: self.config.id.clone(),
            status: IntegrationHealth {
                integration_name: self.get_integration_name(),
                status: super::types::IntegrationHealth::Healthy,
                last_check: Utc::now(),
                response_time_ms: response_time,
                error_message: None,
                metrics: HashMap::new(),
            },
            status_message: "SIEM integration healthy".to_string(),
            response_time_ms: Some(response_time),
            last_check: Utc::now(),
            consecutive_failures: 0,
            metadata: HashMap::new(),
        })
    }

    fn get_integration_type(&self) -> IntegrationType {
        IntegrationType::Siem
    }

    fn get_integration_name(&self) -> String {
        format!("SIEM-{}", self.config.id)
    }
}

/// EDR integration implementation
pub struct EdrIntegration {
    config: IntegrationConfig,
    client: reqwest::Client,
}

impl EdrIntegration {
    pub async fn new(config: IntegrationConfig) -> Result<Self, IntegrationError> {
        let client = reqwest::Client::new();
        Ok(Self { config, client })
    }
}

#[async_trait::async_trait]
impl Integration for EdrIntegration {
    async fn execute_action(
        &self,
        action: &StepAction,
        _context: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, IntegrationError> {
        match action {
            StepAction::BlockIp {
                ip_address,
                duration_minutes,
                reason,
            } => {
                debug!("Blocking IP via EDR: {}", ip_address);

                let mut results = HashMap::new();
                results.insert(
                    "ip_blocked".to_string(),
                    serde_json::Value::String(ip_address.clone()),
                );
                results.insert(
                    "duration_minutes".to_string(),
                    serde_json::Value::Number((*duration_minutes).into()),
                );
                results.insert(
                    "reason".to_string(),
                    serde_json::Value::String(reason.clone()),
                );
                results.insert(
                    "block_id".to_string(),
                    serde_json::Value::String(Uuid::new_v4().to_string()),
                );

                Ok(results)
            }
            _ => Err(IntegrationError {
                code: "UNSUPPORTED_ACTION".to_string(),
                message: format!("EDR integration does not support action: {:?}", action),
                details: None,
                retryable: false,
            }),
        }
    }

    async fn health_check(&self) -> Result<IntegrationHealthInfo, IntegrationError> {
        let start_time = std::time::Instant::now();

        // Simulate health check
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;

        let response_time = start_time.elapsed().as_millis() as u64;

        Ok(IntegrationHealthInfo {
            integration_id: self.config.id.clone(),
            status: IntegrationHealth {
                integration_name: self.get_integration_name(),
                status: super::types::IntegrationHealth::Healthy,
                last_check: Utc::now(),
                response_time_ms: response_time,
                error_message: None,
                metrics: HashMap::new(),
            },
            status_message: "EDR integration healthy".to_string(),
            response_time_ms: Some(response_time),
            last_check: Utc::now(),
            consecutive_failures: 0,
            metadata: HashMap::new(),
        })
    }

    fn get_integration_type(&self) -> IntegrationType {
        IntegrationType::Edr
    }

    fn get_integration_name(&self) -> String {
        format!("EDR-{}", self.config.id)
    }
}

/// Firewall integration implementation
pub struct FirewallIntegration {
    config: IntegrationConfig,
    client: reqwest::Client,
}

impl FirewallIntegration {
    pub async fn new(config: IntegrationConfig) -> Result<Self, IntegrationError> {
        let client = reqwest::Client::new();
        Ok(Self { config, client })
    }
}

#[async_trait::async_trait]
impl Integration for FirewallIntegration {
    async fn execute_action(
        &self,
        action: &StepAction,
        _context: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, IntegrationError> {
        match action {
            StepAction::BlockIp {
                ip_address,
                duration_minutes,
                reason,
            } => {
                debug!("Blocking IP via firewall: {}", ip_address);

                let mut results = HashMap::new();
                results.insert(
                    "firewall_rule_created".to_string(),
                    serde_json::Value::Bool(true),
                );
                results.insert(
                    "blocked_ip".to_string(),
                    serde_json::Value::String(ip_address.clone()),
                );
                results.insert(
                    "rule_id".to_string(),
                    serde_json::Value::String(Uuid::new_v4().to_string()),
                );

                Ok(results)
            }
            _ => Err(IntegrationError {
                code: "UNSUPPORTED_ACTION".to_string(),
                message: format!("Firewall integration does not support action: {:?}", action),
                details: None,
                retryable: false,
            }),
        }
    }

    async fn health_check(&self) -> Result<IntegrationHealthInfo, IntegrationError> {
        let start_time = std::time::Instant::now();

        // Simulate health check
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        let response_time = start_time.elapsed().as_millis() as u64;

        Ok(IntegrationHealthInfo {
            integration_id: self.config.id.clone(),
            status: IntegrationHealth {
                integration_name: self.get_integration_name(),
                status: super::types::IntegrationHealth::Healthy,
                last_check: Utc::now(),
                response_time_ms: response_time,
                error_message: None,
                metrics: HashMap::new(),
            },
            status_message: "Firewall integration healthy".to_string(),
            response_time_ms: Some(response_time),
            last_check: Utc::now(),
            consecutive_failures: 0,
            metadata: HashMap::new(),
        })
    }

    fn get_integration_type(&self) -> IntegrationType {
        IntegrationType::Firewall
    }

    fn get_integration_name(&self) -> String {
        format!("Firewall-{}", self.config.id)
    }
}

/// Health metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    /// Total number of integrations
    pub total_integrations: usize,

    /// Number of healthy integrations
    pub healthy_integrations: usize,

    /// Number of unhealthy integrations
    pub unhealthy_integrations: usize,

    /// Overall health percentage
    pub overall_health_percentage: usize,

    /// Last check timestamp
    pub last_check: DateTime<Utc>,
}

// Missing type definitions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum IntegrationHealth {
    Healthy,
    Unhealthy,
    Unknown,
}
