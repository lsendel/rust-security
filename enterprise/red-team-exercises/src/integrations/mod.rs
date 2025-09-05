//! External Security Tool Integrations
//!
//! Comprehensive integration framework for connecting with external security tools,
//! SIEM systems, vulnerability scanners, threat intelligence platforms, and compliance frameworks.

pub mod config;
pub mod siem;
pub mod vulnerability_scanners;
pub mod threat_intelligence;
pub mod security_orchestration;
pub mod compliance_reporting;
pub mod common;
pub mod auth;
pub mod error;

// Re-export core types
pub use auth::{AuthMethod, IntegrationAuth};
pub use common::{IntegrationResult, IntegrationMetadata, SecurityAlert, EventSeverity};
pub use config::IntegrationConfig;
pub use error::{IntegrationError, Result};

use anyhow::Result as AnyhowResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;
use tracing::{info, error, warn};

/// Core integration manager that coordinates all security tool integrations
#[derive(Debug)]
pub struct SecurityIntegrationManager {
    config: IntegrationConfig,
    siem_clients: Arc<RwLock<HashMap<String, Box<dyn siem::SiemIntegration + Send + Sync>>>>,
    scanner_clients: Arc<RwLock<HashMap<String, Box<dyn vulnerability_scanners::VulnerabilityScanner + Send + Sync>>>>,
    ti_clients: Arc<RwLock<HashMap<String, Box<dyn threat_intelligence::ThreatIntelligence + Send + Sync>>>>,
    soar_clients: Arc<RwLock<HashMap<String, Box<dyn security_orchestration::SoarIntegration + Send + Sync>>>>,
    compliance_clients: Arc<RwLock<HashMap<String, Box<dyn compliance_reporting::ComplianceReporter + Send + Sync>>>>,
}

impl SecurityIntegrationManager {
    /// Create a new security integration manager
    pub async fn new(config: IntegrationConfig) -> AnyhowResult<Self> {
        info!("Initializing Security Integration Manager");
        
        Ok(Self {
            config,
            siem_clients: Arc::new(RwLock::new(HashMap::new())),
            scanner_clients: Arc::new(RwLock::new(HashMap::new())),
            ti_clients: Arc::new(RwLock::new(HashMap::new())),
            soar_clients: Arc::new(RwLock::new(HashMap::new())),
            compliance_clients: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Initialize all configured integrations
    pub async fn initialize_integrations(&mut self) -> AnyhowResult<()> {
        info!("Initializing all security tool integrations");

        // Initialize SIEM integrations
        if let Some(siem_configs) = &self.config.siem {
            self.initialize_siem_integrations(siem_configs).await?;
        }

        // Initialize vulnerability scanners
        if let Some(scanner_configs) = &self.config.vulnerability_scanners {
            self.initialize_scanner_integrations(scanner_configs).await?;
        }

        // Initialize threat intelligence
        if let Some(ti_configs) = &self.config.threat_intelligence {
            self.initialize_ti_integrations(ti_configs).await?;
        }

        // Initialize SOAR platforms
        if let Some(soar_configs) = &self.config.security_orchestration {
            self.initialize_soar_integrations(soar_configs).await?;
        }

        // Initialize compliance reporting
        if let Some(compliance_configs) = &self.config.compliance_reporting {
            self.initialize_compliance_integrations(compliance_configs).await?;
        }

        info!("All security integrations initialized successfully");
        Ok(())
    }

    /// Send security alert to all configured SIEM systems
    pub async fn send_security_alert(&self, alert: SecurityAlert) -> Vec<Result<IntegrationResult>> {
        let siem_clients = self.siem_clients.read().await;
        let mut results = Vec::new();

        for (name, client) in siem_clients.iter() {
            info!("Sending security alert to SIEM: {}", name);
            match client.send_alert(&alert).await {
                Ok(result) => {
                    info!("Successfully sent alert to {}: {:?}", name, result);
                    results.push(Ok(result));
                }
                Err(e) => {
                    error!("Failed to send alert to {}: {}", name, e);
                    results.push(Err(e));
                }
            }
        }

        results
    }

    /// Run vulnerability scan across all configured scanners
    pub async fn run_vulnerability_scan(&self, target: &str) -> Vec<Result<IntegrationResult>> {
        let scanner_clients = self.scanner_clients.read().await;
        let mut results = Vec::new();

        for (name, client) in scanner_clients.iter() {
            info!("Running vulnerability scan with: {}", name);
            match client.scan_target(target).await {
                Ok(result) => {
                    info!("Vulnerability scan completed for {}: {:?}", name, result);
                    results.push(Ok(result));
                }
                Err(e) => {
                    error!("Vulnerability scan failed for {}: {}", name, e);
                    results.push(Err(e));
                }
            }
        }

        results
    }

    /// Query threat intelligence for IoCs
    pub async fn query_threat_intelligence(&self, indicators: &[String]) -> Vec<Result<IntegrationResult>> {
        let ti_clients = self.ti_clients.read().await;
        let mut results = Vec::new();

        for (name, client) in ti_clients.iter() {
            info!("Querying threat intelligence: {}", name);
            match client.query_indicators(indicators).await {
                Ok(result) => {
                    info!("Threat intelligence query completed for {}: {:?}", name, result);
                    results.push(Ok(result));
                }
                Err(e) => {
                    error!("Threat intelligence query failed for {}: {}", name, e);
                    results.push(Err(e));
                }
            }
        }

        results
    }

    /// Generate compliance report
    pub async fn generate_compliance_report(&self, framework: &str) -> Vec<Result<IntegrationResult>> {
        let compliance_clients = self.compliance_clients.read().await;
        let mut results = Vec::new();

        for (name, client) in compliance_clients.iter() {
            info!("Generating compliance report with: {}", name);
            match client.generate_report(framework).await {
                Ok(result) => {
                    info!("Compliance report generated for {}: {:?}", name, result);
                    results.push(Ok(result));
                }
                Err(e) => {
                    error!("Compliance report generation failed for {}: {}", name, e);
                    results.push(Err(e));
                }
            }
        }

        results
    }

    /// Private helper methods for initialization
    async fn initialize_siem_integrations(&mut self, configs: &HashMap<String, serde_json::Value>) -> AnyhowResult<()> {
        let mut siem_clients = self.siem_clients.write().await;

        for (name, config) in configs {
            info!("Initializing SIEM integration: {}", name);
            
            let client: Box<dyn siem::SiemIntegration + Send + Sync> = match name.as_str() {
                "splunk" => Box::new(siem::SplunkIntegration::new(config).await?),
                "elasticsearch" => Box::new(siem::ElasticsearchIntegration::new(config).await?),
                "qradar" => Box::new(siem::QRadarIntegration::new(config).await?),
                _ => {
                    warn!("Unknown SIEM type: {}, creating custom integration", name);
                    Box::new(siem::CustomSiemIntegration::new(config).await?)
                }
            };
            
            siem_clients.insert(name.clone(), client);
        }

        Ok(())
    }

    async fn initialize_scanner_integrations(&mut self, configs: &HashMap<String, serde_json::Value>) -> AnyhowResult<()> {
        let mut scanner_clients = self.scanner_clients.write().await;

        for (name, config) in configs {
            info!("Initializing vulnerability scanner integration: {}", name);
            
            let client: Box<dyn vulnerability_scanners::VulnerabilityScanner + Send + Sync> = match name.as_str() {
                "nessus" => Box::new(vulnerability_scanners::NessusIntegration::new(config).await?),
                "openvas" => Box::new(vulnerability_scanners::OpenVasIntegration::new(config).await?),
                "qualys" => Box::new(vulnerability_scanners::QualysIntegration::new(config).await?),
                _ => {
                    warn!("Unknown vulnerability scanner type: {}, creating custom integration", name);
                    Box::new(vulnerability_scanners::CustomScannerIntegration::new(config).await?)
                }
            };
            
            scanner_clients.insert(name.clone(), client);
        }

        Ok(())
    }

    async fn initialize_ti_integrations(&mut self, configs: &HashMap<String, serde_json::Value>) -> AnyhowResult<()> {
        let mut ti_clients = self.ti_clients.write().await;

        for (name, config) in configs {
            info!("Initializing threat intelligence integration: {}", name);
            
            let client: Box<dyn threat_intelligence::ThreatIntelligence + Send + Sync> = match name.as_str() {
                "misp" => Box::new(threat_intelligence::MispIntegration::new(config).await?),
                "virustotal" => Box::new(threat_intelligence::VirusTotalIntegration::new(config).await?),
                "shodan" => Box::new(threat_intelligence::ShodanIntegration::new(config).await?),
                _ => {
                    warn!("Unknown threat intelligence type: {}, creating custom integration", name);
                    Box::new(threat_intelligence::CustomTiIntegration::new(config).await?)
                }
            };
            
            ti_clients.insert(name.clone(), client);
        }

        Ok(())
    }

    async fn initialize_soar_integrations(&mut self, configs: &HashMap<String, serde_json::Value>) -> AnyhowResult<()> {
        let mut soar_clients = self.soar_clients.write().await;

        for (name, config) in configs {
            info!("Initializing SOAR integration: {}", name);
            
            let client: Box<dyn security_orchestration::SoarIntegration + Send + Sync> = match name.as_str() {
                "phantom" => Box::new(security_orchestration::PhantomIntegration::new(config).await?),
                "demisto" => Box::new(security_orchestration::DemistoIntegration::new(config).await?),
                "webhook" => Box::new(security_orchestration::WebhookIntegration::new(config).await?),
                _ => {
                    warn!("Unknown SOAR type: {}, creating custom integration", name);
                    Box::new(security_orchestration::CustomSoarIntegration::new(config).await?)
                }
            };
            
            soar_clients.insert(name.clone(), client);
        }

        Ok(())
    }

    async fn initialize_compliance_integrations(&mut self, configs: &HashMap<String, serde_json::Value>) -> AnyhowResult<()> {
        let mut compliance_clients = self.compliance_clients.write().await;

        for (name, config) in configs {
            info!("Initializing compliance reporting integration: {}", name);
            
            let client: Box<dyn compliance_reporting::ComplianceReporter + Send + Sync> = match name.as_str() {
                "pci_dss" => Box::new(compliance_reporting::PciDssReporter::new(config).await?),
                "sox" => Box::new(compliance_reporting::SoxReporter::new(config).await?),
                "gdpr" => Box::new(compliance_reporting::GdprReporter::new(config).await?),
                _ => {
                    warn!("Unknown compliance framework: {}, creating custom reporter", name);
                    Box::new(compliance_reporting::CustomComplianceReporter::new(config).await?)
                }
            };
            
            compliance_clients.insert(name.clone(), client);
        }

        Ok(())
    }

    /// Get integration health status
    pub async fn get_integration_health(&self) -> HashMap<String, bool> {
        let mut health = HashMap::new();

        // Check SIEM integrations
        let siem_clients = self.siem_clients.read().await;
        for (name, client) in siem_clients.iter() {
            health.insert(format!("siem_{}", name), client.health_check().await);
        }

        // Check vulnerability scanners
        let scanner_clients = self.scanner_clients.read().await;
        for (name, client) in scanner_clients.iter() {
            health.insert(format!("scanner_{}", name), client.health_check().await);
        }

        // Check threat intelligence
        let ti_clients = self.ti_clients.read().await;
        for (name, client) in ti_clients.iter() {
            health.insert(format!("ti_{}", name), client.health_check().await);
        }

        // Check SOAR platforms
        let soar_clients = self.soar_clients.read().await;
        for (name, client) in soar_clients.iter() {
            health.insert(format!("soar_{}", name), client.health_check().await);
        }

        // Check compliance reporting
        let compliance_clients = self.compliance_clients.read().await;
        for (name, client) in compliance_clients.iter() {
            health.insert(format!("compliance_{}", name), client.health_check().await);
        }

        health
    }
}