//! Compliance Manager
//!
//! Central management system for all compliance frameworks, automated monitoring,
//! and reporting capabilities.

use super::*;
use crate::monitoring::security_alerts::SecurityAlert;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Central compliance management system
pub struct ComplianceManager {
    alert_service: Arc<SecurityAlert>,
    report_config: Arc<RwLock<ComplianceReportConfig>>,
    enabled_frameworks: Vec<ComplianceFramework>,
}

impl ComplianceManager {
    /// Create new compliance manager
    pub fn new(alert_service: Arc<SecurityAlert>) -> Self {
        let default_config = ComplianceReportConfig {
            enabled_frameworks: vec![
                ComplianceFramework::SOC2,
                ComplianceFramework::HIPAA,
                ComplianceFramework::PciDss,
            ],
            report_frequency: ReviewFrequency::Monthly,
            recipients: vec!["compliance@company.com".to_string()],
            include_metrics: true,
            include_violations: true,
            include_evidence: false,
            format: ReportFormat::Json,
        };

        Self {
            alert_service,
            report_config: Arc::new(RwLock::new(default_config.clone())),
            enabled_frameworks: default_config.enabled_frameworks,
        }
    }

    /// Initialize compliance manager and all frameworks
    pub async fn initialize(&self) -> ComplianceResult<()> {
        info!("🔒 Initializing Compliance Manager");
        
        // Initialize audit trail
        audit_trail::initialize_audit_trail();
        
        // Initialize all compliance frameworks
        initialize_compliance_monitoring().await?;
        
        // Start automated monitoring
        self.start_compliance_monitoring().await?;
        
        info!("✅ Compliance Manager initialized successfully");
        Ok(())
    }

    /// Start automated compliance monitoring
    async fn start_compliance_monitoring(&self) -> ComplianceResult<()> {
        info!("Starting automated compliance monitoring");
        
        // Spawn monitoring task
        let alert_service = self.alert_service.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // Hourly checks
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::run_compliance_checks(&alert_service).await {
                    error!("Compliance monitoring failed: {}", e);
                }
            }
        });
        
        // Spawn reporting task
        let report_config = self.report_config.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(86400)); // Daily checks for reporting
            
            loop {
                interval.tick().await;
                
                let config = report_config.read().await;
                if let Err(e) = Self::check_reporting_schedule(&config).await {
                    error!("Compliance reporting check failed: {}", e);
                }
            }
        });
        
        Ok(())
    }

    /// Run compliance checks for all frameworks
    async fn run_compliance_checks(alert_service: &SecurityAlert) -> ComplianceResult<()> {
        // Run automated checks
        if let Err(e) = run_automated_compliance_checks().await {
            warn!("Automated compliance checks failed: {}", e);
            
            // Send alert about compliance check failure
            let security_event = crate::monitoring::security_alerts::SecurityEvent {
                event_type: crate::monitoring::security_alerts::SecurityEventType::SystemError,
                severity: crate::monitoring::security_alerts::AlertSeverity::Warning,
                timestamp: chrono::Utc::now().timestamp() as u64,
                source_ip: None,
                user_id: Some("compliance_system".to_string()),
                session_id: None,
                user_agent: None,
                endpoint: Some("/compliance/automated_checks".to_string()),
                message: format!("Automated compliance checks failed: {}", e),
                metadata: std::collections::HashMap::new(),
                count: 1,
            };
            
            if let Err(alert_err) = alert_service.send_alert(&security_event).await {
                error!("Failed to send compliance alert: {}", alert_err);
            }
        }
        
        Ok(())
    }

    /// Check if compliance reports need to be generated
    async fn check_reporting_schedule(config: &ComplianceReportConfig) -> ComplianceResult<()> {
        // This would check if it's time to generate reports based on frequency
        // For now, just log that we're checking
        info!("Checking compliance reporting schedule for {:?} frequency", config.report_frequency);
        Ok(())
    }

    /// Generate comprehensive compliance dashboard
    pub async fn get_compliance_dashboard(&self) -> ComplianceResult<ComplianceDashboard> {
        let summary = get_compliance_summary().await?;
        let mut dashboard = ComplianceDashboard {
            last_updated: chrono::Utc::now().timestamp() as u64,
            overall_compliance_score: 0.0,
            framework_metrics: summary.clone(),
            critical_violations: Vec::new(),
            upcoming_reviews: Vec::new(),
            compliance_trends: Vec::new(),
            recommendations: Vec::new(),
        };

        // Calculate overall compliance score
        let mut total_score = 0.0;
        let mut framework_count = 0;
        
        for (_, metrics) in &summary {
            total_score += metrics.compliance_percentage;
            framework_count += 1;
        }
        
        if framework_count > 0 {
            dashboard.overall_compliance_score = total_score / framework_count as f64;
        }

        // Collect critical violations
        for (framework, metrics) in &summary {
            if metrics.critical_violations > 0 {
                dashboard.critical_violations.push(CriticalViolationSummary {
                    framework: *framework,
                    count: metrics.critical_violations,
                    risk_level: metrics.get_risk_level(),
                });
            }
        }

        // Generate recommendations
        dashboard.recommendations = self.generate_recommendations(&summary).await;

        Ok(dashboard)
    }

    /// Generate compliance recommendations based on current state
    async fn generate_recommendations(&self, summary: &std::collections::HashMap<ComplianceFramework, ComplianceMetrics>) -> Vec<String> {
        let mut recommendations = Vec::new();

        for (framework, metrics) in summary {
            if metrics.compliance_percentage < 90.0 {
                recommendations.push(format!(
                    "🔴 {}: Compliance below 90% ({:.1}%) - Review non-compliant controls",
                    framework, metrics.compliance_percentage
                ));
            }

            if metrics.critical_violations > 0 {
                recommendations.push(format!(
                    "⚠️ {}: {} critical violations require immediate attention",
                    framework, metrics.critical_violations
                ));
            }

            if metrics.manual_verification_pending > 5 {
                recommendations.push(format!(
                    "📋 {}: {} controls pending manual verification",
                    framework, metrics.manual_verification_pending
                ));
            }

            if metrics.compliance_percentage >= 95.0 {
                recommendations.push(format!(
                    "✅ {}: Excellent compliance ({:.1}%) - Maintain current practices",
                    framework, metrics.compliance_percentage
                ));
            }
        }

        if recommendations.is_empty() {
            recommendations.push("✅ All compliance frameworks are performing well".to_string());
        }

        recommendations
    }

    /// Update compliance report configuration
    pub async fn update_report_config(&self, config: ComplianceReportConfig) -> ComplianceResult<()> {
        let mut current_config = self.report_config.write().await;
        *current_config = config;
        info!("Compliance report configuration updated");
        Ok(())
    }

    /// Generate and send compliance reports
    pub async fn generate_and_send_reports(&self) -> ComplianceResult<()> {
        let config = self.report_config.read().await;
        
        info!("Generating compliance reports for {} frameworks", config.enabled_frameworks.len());
        
        let report_content = generate_compliance_report(config.clone()).await?;
        
        // In a real implementation, this would send emails/notifications
        info!("Compliance report generated ({} characters)", report_content.len());
        
        // Log audit event for report generation
        audit_trail::log_data_access_event(
            "compliance_system",
            "compliance_reports",
            "generate_report",
            audit_trail::AuditOutcome::Success,
            config.enabled_frameworks.clone(),
        ).await?;
        
        Ok(())
    }

    /// Handle compliance violation alerts
    pub async fn handle_violation(&self, violation: ComplianceViolation) -> ComplianceResult<()> {
        warn!("Processing compliance violation: {} - {}", violation.framework, violation.title);
        
        // Log security incident
        audit_trail::log_security_incident(
            "compliance_violation",
            &format!("{}: {}", violation.title, violation.description),
            "compliance_system",
            violation.severity.clone(),
        ).await?;
        
        // Send alert if severity is high enough
        if matches!(violation.severity, ViolationSeverity::Critical | ViolationSeverity::High) {
            let security_event = crate::monitoring::security_alerts::SecurityEvent {
                event_type: crate::monitoring::security_alerts::SecurityEventType::PolicyViolation,
                severity: match violation.severity {
                    ViolationSeverity::Critical => crate::monitoring::security_alerts::AlertSeverity::Critical,
                    ViolationSeverity::High => crate::monitoring::security_alerts::AlertSeverity::Warning,
                    _ => crate::monitoring::security_alerts::AlertSeverity::Info,
                },
                timestamp: violation.detected_at,
                source_ip: None,
                user_id: Some("compliance_system".to_string()),
                session_id: None,
                user_agent: None,
                endpoint: Some("/compliance/violation".to_string()),
                message: format!("{} Compliance Violation: {}", violation.framework, violation.title),
                metadata: {
                    let mut metadata = std::collections::HashMap::new();
                    metadata.insert("framework".to_string(), format!("{}", violation.framework));
                    metadata.insert("control_id".to_string(), violation.control_id.clone());
                    metadata.insert("severity".to_string(), format!("{:?}", violation.severity));
                    metadata
                },
                count: 1,
            };
            
            self.alert_service.send_alert(&security_event).await.map_err(|e| {
                ComplianceError::ReportGenerationFailed(format!("Failed to send violation alert: {}", e))
            })?;
        }
        
        Ok(())
    }
}

/// Compliance dashboard data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceDashboard {
    pub last_updated: u64,
    pub overall_compliance_score: f64,
    pub framework_metrics: std::collections::HashMap<ComplianceFramework, ComplianceMetrics>,
    pub critical_violations: Vec<CriticalViolationSummary>,
    pub upcoming_reviews: Vec<UpcomingReview>,
    pub compliance_trends: Vec<ComplianceTrend>,
    pub recommendations: Vec<String>,
}

/// Critical violation summary for dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalViolationSummary {
    pub framework: ComplianceFramework,
    pub count: u32,
    pub risk_level: ViolationSeverity,
}

/// Upcoming review information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpcomingReview {
    pub framework: ComplianceFramework,
    pub control_id: String,
    pub due_date: u64,
    pub review_type: ReviewType,
}

/// Review types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewType {
    ControlReview,
    AuditPreparation,
    PolicyUpdate,
    EvidenceCollection,
}

/// Compliance trend data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTrend {
    pub framework: ComplianceFramework,
    pub timestamp: u64,
    pub compliance_percentage: f64,
    pub violation_count: u32,
}

/// Global compliance manager instance
static COMPLIANCE_MANAGER: std::sync::OnceLock<std::sync::Arc<ComplianceManager>> = std::sync::OnceLock::new();

/// Initialize global compliance manager
pub async fn initialize_compliance_manager(alert_service: Arc<SecurityAlert>) -> ComplianceResult<()> {
    let manager = Arc::new(ComplianceManager::new(alert_service));
    manager.initialize().await?;
    
    let _ = COMPLIANCE_MANAGER.set(manager);
    info!("✅ Global compliance manager initialized");
    
    Ok(())
}

/// Get global compliance manager
pub fn get_compliance_manager() -> Option<Arc<ComplianceManager>> {
    COMPLIANCE_MANAGER.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::alert_handlers::AlertHandlerFactory;

    #[tokio::test]
    async fn test_compliance_manager_initialization() {
        let handlers = AlertHandlerFactory::create_handlers();
        let alert_service = Arc::new(SecurityAlert::new(handlers));
        
        let manager = ComplianceManager::new(alert_service);
        let result = manager.initialize().await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_compliance_dashboard_generation() {
        let handlers = AlertHandlerFactory::create_handlers();
        let alert_service = Arc::new(SecurityAlert::new(handlers));
        
        let manager = ComplianceManager::new(alert_service);
        let _ = manager.initialize().await;
        
        let dashboard = manager.get_compliance_dashboard().await;
        assert!(dashboard.is_ok());
        
        let dashboard = dashboard.unwrap();
        assert!(!dashboard.recommendations.is_empty());
    }

    #[tokio::test]
    async fn test_violation_handling() {
        let handlers = AlertHandlerFactory::create_handlers();
        let alert_service = Arc::new(SecurityAlert::new(handlers));
        
        let manager = ComplianceManager::new(alert_service);
        
        let violation = ComplianceViolation {
            id: "test_violation".to_string(),
            framework: ComplianceFramework::SOC2,
            control_id: "CC6.1".to_string(),
            severity: ViolationSeverity::High,
            title: "Test Violation".to_string(),
            description: "This is a test violation".to_string(),
            detected_at: chrono::Utc::now().timestamp() as u64,
            resolved_at: None,
            status: ViolationStatus::Open,
            remediation_plan: None,
            evidence: Vec::new(),
            impact_assessment: None,
        };
        
        let result = manager.handle_violation(violation).await;
        assert!(result.is_ok());
    }
}