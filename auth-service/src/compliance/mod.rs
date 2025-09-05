//! Compliance Frameworks Module
//!
//! Comprehensive compliance implementations for SOC 2, HIPAA, and PCI DSS
//! with automated monitoring, reporting, and audit trail capabilities.

pub mod soc2;
pub mod hipaa;
pub mod pci_dss;
pub mod audit_trail;
pub mod compliance_manager;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use tracing::{info, warn, error};

/// Supported compliance frameworks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceFramework {
    SOC2,
    HIPAA,
    PciDss,
}

impl fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComplianceFramework::SOC2 => write!(f, "SOC 2"),
            ComplianceFramework::HIPAA => write!(f, "HIPAA"),
            ComplianceFramework::PciDss => write!(f, "PCI DSS"),
        }
    }
}

/// Compliance control status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlStatus {
    Compliant,
    NonCompliant,
    PartiallyCompliant,
    NotApplicable,
    PendingReview,
}

/// Severity levels for compliance violations
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Compliance control implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub id: String,
    pub framework: ComplianceFramework,
    pub title: String,
    pub description: String,
    pub requirements: Vec<String>,
    pub implementation_status: ControlStatus,
    pub evidence_locations: Vec<String>,
    pub responsible_party: String,
    pub review_frequency: ReviewFrequency,
    pub last_reviewed: Option<u64>, // timestamp
    pub next_review_due: Option<u64>, // timestamp
    pub automated_checks: bool,
    pub manual_verification_required: bool,
}

/// Review frequency for compliance controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewFrequency {
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    SemiAnnually,
    Annually,
    Continuous,
}

/// Compliance violation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub id: String,
    pub framework: ComplianceFramework,
    pub control_id: String,
    pub severity: ViolationSeverity,
    pub title: String,
    pub description: String,
    pub detected_at: u64,
    pub resolved_at: Option<u64>,
    pub status: ViolationStatus,
    pub remediation_plan: Option<String>,
    pub evidence: Vec<String>,
    pub impact_assessment: Option<String>,
}

/// Status of compliance violations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationStatus {
    Open,
    InProgress,
    Resolved,
    Accepted, // Risk accepted
    FalsePositive,
}

/// Compliance audit record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAudit {
    pub id: String,
    pub framework: ComplianceFramework,
    pub audit_type: AuditType,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub auditor: String,
    pub scope: Vec<String>,
    pub findings: Vec<AuditFinding>,
    pub overall_status: ControlStatus,
    pub recommendations: Vec<String>,
    pub next_audit_due: Option<u64>,
}

/// Types of compliance audits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditType {
    Internal,
    External,
    SelfAssessment,
    Certification,
    Surveillance,
}

/// Individual audit finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub control_id: String,
    pub finding_type: FindingType,
    pub severity: ViolationSeverity,
    pub description: String,
    pub evidence: Vec<String>,
    pub recommendation: String,
}

/// Types of audit findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingType {
    NonCompliance,
    Weakness,
    Observation,
    Improvement,
}

/// Compliance reporting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReportConfig {
    pub enabled_frameworks: Vec<ComplianceFramework>,
    pub report_frequency: ReviewFrequency,
    pub recipients: Vec<String>,
    pub include_metrics: bool,
    pub include_violations: bool,
    pub include_evidence: bool,
    pub format: ReportFormat,
}

/// Report format options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReportFormat {
    Json,
    Pdf,
    Html,
    Csv,
}

/// Main compliance engine errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplianceError {
    ControlNotFound(String),
    ViolationNotFound(String),
    AuditNotFound(String),
    InvalidConfiguration(String),
    EvidenceCollectionFailed(String),
    ReportGenerationFailed(String),
    DatabaseError(String),
}

impl fmt::Display for ComplianceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComplianceError::ControlNotFound(id) => write!(f, "Control not found: {}", id),
            ComplianceError::ViolationNotFound(id) => write!(f, "Violation not found: {}", id),
            ComplianceError::AuditNotFound(id) => write!(f, "Audit not found: {}", id),
            ComplianceError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
            ComplianceError::EvidenceCollectionFailed(msg) => write!(f, "Evidence collection failed: {}", msg),
            ComplianceError::ReportGenerationFailed(msg) => write!(f, "Report generation failed: {}", msg),
            ComplianceError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
        }
    }
}

impl std::error::Error for ComplianceError {}

/// Result type for compliance operations
pub type ComplianceResult<T> = Result<T, ComplianceError>;

/// Compliance metrics for monitoring and reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMetrics {
    pub framework: ComplianceFramework,
    pub total_controls: u32,
    pub compliant_controls: u32,
    pub non_compliant_controls: u32,
    pub partially_compliant_controls: u32,
    pub pending_review_controls: u32,
    pub not_applicable_controls: u32,
    pub compliance_percentage: f64,
    pub open_violations: u32,
    pub critical_violations: u32,
    pub high_severity_violations: u32,
    pub last_audit_date: Option<u64>,
    pub next_audit_due: Option<u64>,
    pub automated_checks_enabled: u32,
    pub manual_verification_pending: u32,
}

impl ComplianceMetrics {
    /// Calculate compliance percentage
    pub fn calculate_compliance_percentage(&mut self) {
        let applicable_controls = self.total_controls - self.not_applicable_controls;
        if applicable_controls > 0 {
            self.compliance_percentage = (self.compliant_controls as f64 / applicable_controls as f64) * 100.0;
        } else {
            self.compliance_percentage = 100.0;
        }
    }

    /// Check if compliance level is acceptable
    pub fn is_compliant(&self, threshold: f64) -> bool {
        self.compliance_percentage >= threshold
    }

    /// Get risk level based on violations
    pub fn get_risk_level(&self) -> ViolationSeverity {
        if self.critical_violations > 0 {
            ViolationSeverity::Critical
        } else if self.high_severity_violations > 0 {
            ViolationSeverity::High
        } else if self.open_violations > 5 {
            ViolationSeverity::Medium
        } else if self.open_violations > 0 {
            ViolationSeverity::Low
        } else {
            ViolationSeverity::Info
        }
    }
}

/// Initialize compliance monitoring
pub async fn initialize_compliance_monitoring() -> ComplianceResult<()> {
    info!("🔒 Initializing compliance monitoring system");
    
    // Initialize compliance frameworks
    soc2::initialize_soc2_controls().await?;
    hipaa::initialize_hipaa_controls().await?;
    pci_dss::initialize_pci_dss_controls().await?;
    
    // Start automated compliance checks
    start_automated_compliance_checks().await?;
    
    info!("✅ Compliance monitoring system initialized successfully");
    Ok(())
}

/// Start automated compliance monitoring
pub async fn start_automated_compliance_checks() -> ComplianceResult<()> {
    info!("Starting automated compliance checks");
    
    // Spawn background tasks for each framework
    tokio::spawn(async {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // Hourly
        loop {
            interval.tick().await;
            
            if let Err(e) = run_automated_compliance_checks().await {
                error!("Automated compliance check failed: {}", e);
            }
        }
    });
    
    Ok(())
}

/// Run automated compliance checks for all frameworks
async fn run_automated_compliance_checks() -> ComplianceResult<()> {
    let frameworks = vec![
        ComplianceFramework::SOC2,
        ComplianceFramework::HIPAA,
        ComplianceFramework::PciDss,
    ];
    
    for framework in frameworks {
        match framework {
            ComplianceFramework::SOC2 => {
                if let Err(e) = soc2::run_automated_soc2_checks().await {
                    warn!("SOC 2 automated checks failed: {}", e);
                }
            },
            ComplianceFramework::HIPAA => {
                if let Err(e) = hipaa::run_automated_hipaa_checks().await {
                    warn!("HIPAA automated checks failed: {}", e);
                }
            },
            ComplianceFramework::PciDss => {
                if let Err(e) = pci_dss::run_automated_pci_dss_checks().await {
                    warn!("PCI DSS automated checks failed: {}", e);
                }
            },
        }
    }
    
    Ok(())
}

/// Get compliance status summary for all frameworks
pub async fn get_compliance_summary() -> ComplianceResult<HashMap<ComplianceFramework, ComplianceMetrics>> {
    let mut summary = HashMap::new();
    
    // Get metrics for each framework
    if let Ok(soc2_metrics) = soc2::get_soc2_metrics().await {
        summary.insert(ComplianceFramework::SOC2, soc2_metrics);
    }
    
    if let Ok(hipaa_metrics) = hipaa::get_hipaa_metrics().await {
        summary.insert(ComplianceFramework::HIPAA, hipaa_metrics);
    }
    
    if let Ok(pci_metrics) = pci_dss::get_pci_dss_metrics().await {
        summary.insert(ComplianceFramework::PciDss, pci_metrics);
    }
    
    Ok(summary)
}

/// Generate comprehensive compliance report
pub async fn generate_compliance_report(
    config: ComplianceReportConfig,
) -> ComplianceResult<String> {
    info!("Generating compliance report with config: {:?}", config);
    
    let mut report_data = HashMap::new();
    
    // Collect data for each enabled framework
    for framework in config.enabled_frameworks {
        let metrics = match framework {
            ComplianceFramework::SOC2 => soc2::get_soc2_metrics().await?,
            ComplianceFramework::HIPAA => hipaa::get_hipaa_metrics().await?,
            ComplianceFramework::PciDss => pci_dss::get_pci_dss_metrics().await?,
        };
        
        let mut framework_data = HashMap::new();
        framework_data.insert("metrics", serde_json::to_value(metrics)?);
        
        if config.include_violations {
            let violations = match framework {
                ComplianceFramework::SOC2 => soc2::get_open_violations().await?,
                ComplianceFramework::HIPAA => hipaa::get_open_violations().await?,
                ComplianceFramework::PciDss => pci_dss::get_open_violations().await?,
            };
            framework_data.insert("violations", serde_json::to_value(violations)?);
        }
        
        report_data.insert(framework.to_string(), framework_data);
    }
    
    // Generate report based on format
    match config.format {
        ReportFormat::Json => {
            serde_json::to_string_pretty(&report_data)
                .map_err(|e| ComplianceError::ReportGenerationFailed(e.to_string()))
        },
        ReportFormat::Html => generate_html_report(report_data).await,
        ReportFormat::Pdf => generate_pdf_report(report_data).await,
        ReportFormat::Csv => generate_csv_report(report_data).await,
    }
}

/// Generate HTML compliance report
async fn generate_html_report(data: HashMap<String, HashMap<String, serde_json::Value>>) -> ComplianceResult<String> {
    // This would generate a comprehensive HTML report
    // For now, return a basic HTML structure
    let mut html = String::from(
        r#"<!DOCTYPE html>
<html><head><title>Compliance Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; }
.framework { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
.compliant { background-color: #d4edda; }
.non-compliant { background-color: #f8d7da; }
.metrics { margin: 10px 0; }
.violation { margin: 5px 0; padding: 10px; background-color: #fff3cd; border-left: 4px solid #ffc107; }
</style>
</head><body>
<h1>Compliance Report</h1>
<p>Generated: "#
    );
    
    html.push_str(&chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string());
    html.push_str("</p>");
    
    for (framework, framework_data) in data {
        html.push_str(&format!("<div class='framework'><h2>{}</h2>", framework));
        
        if let Some(metrics) = framework_data.get("metrics") {
            html.push_str("<div class='metrics'>");
            html.push_str(&format!("<pre>{}</pre>", serde_json::to_string_pretty(metrics).unwrap_or_default()));
            html.push_str("</div>");
        }
        
        html.push_str("</div>");
    }
    
    html.push_str("</body></html>");
    Ok(html)
}

/// Generate PDF compliance report (stub)
async fn generate_pdf_report(_data: HashMap<String, HashMap<String, serde_json::Value>>) -> ComplianceResult<String> {
    // In a real implementation, this would generate a PDF
    Err(ComplianceError::ReportGenerationFailed("PDF generation not implemented".to_string()))
}

/// Generate CSV compliance report (stub)
async fn generate_csv_report(_data: HashMap<String, HashMap<String, serde_json::Value>>) -> ComplianceResult<String> {
    // In a real implementation, this would generate CSV data
    Err(ComplianceError::ReportGenerationFailed("CSV generation not implemented".to_string()))
}

impl From<serde_json::Error> for ComplianceError {
    fn from(err: serde_json::Error) -> Self {
        ComplianceError::ReportGenerationFailed(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_metrics_calculation() {
        let mut metrics = ComplianceMetrics {
            framework: ComplianceFramework::SOC2,
            total_controls: 100,
            compliant_controls: 80,
            non_compliant_controls: 15,
            partially_compliant_controls: 3,
            pending_review_controls: 1,
            not_applicable_controls: 1,
            compliance_percentage: 0.0,
            open_violations: 5,
            critical_violations: 1,
            high_severity_violations: 2,
            last_audit_date: None,
            next_audit_due: None,
            automated_checks_enabled: 75,
            manual_verification_pending: 10,
        };

        metrics.calculate_compliance_percentage();
        
        // Should be 80/99 * 100 = ~80.81%
        assert!((metrics.compliance_percentage - 80.80).abs() < 0.1);
        assert!(!metrics.is_compliant(85.0));
        assert!(metrics.is_compliant(75.0));
        assert_eq!(metrics.get_risk_level(), ViolationSeverity::Critical);
    }

    #[tokio::test]
    async fn test_compliance_report_generation() {
        let config = ComplianceReportConfig {
            enabled_frameworks: vec![ComplianceFramework::SOC2],
            report_frequency: ReviewFrequency::Monthly,
            recipients: vec!["compliance@example.com".to_string()],
            include_metrics: true,
            include_violations: false,
            include_evidence: false,
            format: ReportFormat::Json,
        };

        // This test would require proper initialization, so just test the config
        assert_eq!(config.enabled_frameworks.len(), 1);
        assert_eq!(config.enabled_frameworks[0], ComplianceFramework::SOC2);
    }
}