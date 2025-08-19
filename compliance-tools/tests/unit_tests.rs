//! Unit tests for compliance-tools functionality

use compliance_tools::*;
use chrono::Utc;
use std::collections::HashMap;
use tempfile::NamedTempFile;
use std::io::Write;

#[tokio::test]
async fn test_security_metric_creation() {
    let metric = SecurityMetric {
        name: "test_metric".to_string(),
        value: 95.5,
        threshold: 90.0,
        status: MetricStatus::Pass,
        description: "Test metric description".to_string(),
        timestamp: Utc::now(),
        tags: HashMap::new(),
    };

    assert_eq!(metric.name, "test_metric");
    assert_eq!(metric.value, 95.5);
    assert_eq!(metric.threshold, 90.0);
    assert_eq!(metric.status, MetricStatus::Pass);
}

#[tokio::test]
async fn test_compliance_control_creation() {
    let control = ComplianceControl {
        control_id: "CC-001".to_string(),
        framework: ComplianceFramework::Soc2,
        title: "Test Control".to_string(),
        description: "Test control description".to_string(),
        implementation_status: ImplementationStatus::Implemented,
        effectiveness: EffectivenessLevel::Effective,
        evidence: vec!["Evidence 1".to_string(), "Evidence 2".to_string()],
        last_tested: Utc::now(),
        next_review: Utc::now(),
        risk_level: RiskLevel::Low,
        assigned_to: Some("Test User".to_string()),
        remediation_plan: None,
    };

    assert_eq!(control.control_id, "CC-001");
    assert_eq!(control.framework, ComplianceFramework::Soc2);
    assert_eq!(control.implementation_status, ImplementationStatus::Implemented);
    assert_eq!(control.effectiveness, EffectivenessLevel::Effective);
    assert_eq!(control.risk_level, RiskLevel::Low);
}

#[tokio::test]
async fn test_security_incident_creation() {
    let incident = SecurityIncident {
        incident_id: "INC-001".to_string(),
        severity: IncidentSeverity::Medium,
        category: IncidentCategory::UnauthorizedAccess,
        title: "Test Incident".to_string(),
        description: "Test incident description".to_string(),
        detected_at: Utc::now(),
        resolved_at: None,
        impact: "Medium impact".to_string(),
        root_cause: Some("Test root cause".to_string()),
        remediation_actions: vec!["Action 1".to_string(), "Action 2".to_string()],
        affected_systems: vec!["System A".to_string(), "System B".to_string()],
        assigned_to: Some("Security Team".to_string()),
        lessons_learned: None,
    };

    assert_eq!(incident.incident_id, "INC-001");
    assert_eq!(incident.severity, IncidentSeverity::Medium);
    assert_eq!(incident.category, IncidentCategory::UnauthorizedAccess);
    assert_eq!(incident.remediation_actions.len(), 2);
    assert_eq!(incident.affected_systems.len(), 2);
}

#[tokio::test]
async fn test_audit_log_entry_creation() {
    let entry = AuditLogEntry {
        timestamp: Utc::now(),
        user_id: Some("user123".to_string()),
        session_id: Some("session456".to_string()),
        action: "login".to_string(),
        resource: "/auth".to_string(),
        result: AuditResult::Success,
        ip_address: Some("192.168.1.1".parse().unwrap()),
        user_agent: Some("TestAgent/1.0".to_string()),
        details: HashMap::new(),
    };

    assert_eq!(entry.user_id, Some("user123".to_string()));
    assert_eq!(entry.action, "login");
    assert_eq!(entry.resource, "/auth");
    assert_eq!(entry.result, AuditResult::Success);
}

#[tokio::test]
async fn test_compliance_config_creation() {
    let config = ComplianceConfig {
        organization: OrganizationInfo {
            name: "Test Organization".to_string(),
            domain: "test.example.com".to_string(),
            contact_email: "compliance@test.example.com".to_string(),
            compliance_officer: "Jane Doe".to_string(),
            assessment_period_days: 90,
        },
        frameworks: vec![ComplianceFramework::Soc2, ComplianceFramework::Iso27001],
        report_settings: ReportSettings {
            output_formats: vec![ReportFormat::Html, ReportFormat::Json],
            include_charts: true,
            include_recommendations: true,
            classification_level: ClassificationLevel::Internal,
            retention_days: 365,
        },
        data_sources: DataSourceConfig {
            prometheus_url: Some("http://localhost:9090".to_string()),
            elasticsearch_url: Some("http://localhost:9200".to_string()),
            audit_log_paths: vec!["/var/log/audit.log".to_string()],
            redis_url: Some("redis://localhost:6379".to_string()),
            custom_apis: HashMap::new(),
        },
        notifications: NotificationConfig {
            slack_webhook: Some("https://hooks.slack.com/webhook".to_string()),
            email_recipients: vec!["admin@test.example.com".to_string()],
            teams_webhook: None,
            custom_webhooks: vec![],
        },
    };

    assert_eq!(config.organization.name, "Test Organization");
    assert_eq!(config.frameworks.len(), 2);
    assert_eq!(config.report_settings.output_formats.len(), 2);
    assert!(config.report_settings.include_charts);
    assert!(config.report_settings.include_recommendations);
}

#[tokio::test]
async fn test_metric_status_hierarchy() {
    // Test that metric statuses can be properly ordered
    let statuses = vec![
        MetricStatus::Pass,
        MetricStatus::Warning,
        MetricStatus::Fail,
        MetricStatus::Unknown,
    ];

    for status in statuses {
        // Test serialization
        let serialized = serde_json::to_string(&status).unwrap();
        let deserialized: MetricStatus = serde_json::from_str(&serialized).unwrap();
        assert_eq!(status, deserialized);
    }
}

#[tokio::test]
async fn test_risk_level_ordering() {
    // Test that risk levels can be properly ordered
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);
}

#[tokio::test]
async fn test_incident_severity_ordering() {
    // Test that incident severities can be properly ordered
    assert!(IncidentSeverity::Info < IncidentSeverity::Low);
    assert!(IncidentSeverity::Low < IncidentSeverity::Medium);
    assert!(IncidentSeverity::Medium < IncidentSeverity::High);
    assert!(IncidentSeverity::High < IncidentSeverity::Critical);
}

#[tokio::test]
async fn test_compliance_framework_serialization() {
    let frameworks = vec![
        ComplianceFramework::Soc2,
        ComplianceFramework::Iso27001,
        ComplianceFramework::Gdpr,
        ComplianceFramework::Nist,
        ComplianceFramework::Pci,
        ComplianceFramework::Hipaa,
        ComplianceFramework::Custom("CustomFramework".to_string()),
    ];

    for framework in frameworks {
        let serialized = serde_json::to_string(&framework).unwrap();
        let deserialized: ComplianceFramework = serde_json::from_str(&serialized).unwrap();
        assert_eq!(framework, deserialized);
    }
}

#[test]
fn test_error_handling() {
    let error = ComplianceError::Configuration("Test configuration error".to_string());
    assert!(error.to_string().contains("Configuration error"));

    let error = ComplianceError::DataCollection("Test data collection error".to_string());
    assert!(error.to_string().contains("Data collection error"));

    let error = ComplianceError::ReportGeneration("Test report generation error".to_string());
    assert!(error.to_string().contains("Report generation error"));

    let error = ComplianceError::Validation("Test validation error".to_string());
    assert!(error.to_string().contains("Validation error"));

    let error = ComplianceError::Template("Test template error".to_string());
    assert!(error.to_string().contains("Template error"));
}