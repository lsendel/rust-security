//! Unit tests for red team exercises functionality

use chrono::Utc;
use red_team_exercises::attack_framework::*;
use red_team_exercises::reporting::*;
use red_team_exercises::scenarios::social_engineering::*;
use std::collections::HashMap;

#[tokio::test]
async fn test_red_team_framework_initialization() {
    let target_url = "http://localhost:8080".to_string();
    let _result = RedTeamFramework::new(target_url.clone()).await;

    assert!(result.is_ok());
    let framework = result.unwrap();
    // Basic validation that framework was created
    assert!(!framework.target_url.is_empty());
}

#[tokio::test]
async fn test_red_team_reporter_creation() {
    let campaign_id = "test_campaign_001".to_string();
    let reporter = RedTeamReporter::new(campaign_id.clone());

    assert_eq!(reporter.campaign_id, campaign_id);
}

#[tokio::test]
async fn test_social_engineering_scenario_validation() {
    // Test that social engineering scenarios can be properly configured
    let mut framework = RedTeamFramework::new("http://localhost:8080".to_string()).await.unwrap();
    let mut reporter = RedTeamReporter::new("test_campaign".to_string());

    // Test with low intensity (safe for testing)
    let _result = run_token_scenarios(&mut framework, &mut reporter, "low").await;
    assert!(result.is_ok());
}

#[test]
fn test_scenario_result_creation() {
    let _result = ScenarioResult {
        scenario_name: "test_scenario".to_string(),
        success: true,
        details: "Test scenario executed successfully".to_string(),
        timestamp: Utc::now(),
        metrics: HashMap::new(),
        recommendations: vec!["Recommendation 1".to_string()],
    };

    assert_eq!(result.scenario_name, "test_scenario");
    assert!(result.success);
    assert!(!result.details.is_empty());
    assert_eq!(result.recommendations.len(), 1);
}

#[test]
fn test_attack_vector_creation() {
    let vector = AttackVector {
        name: "Email Phishing".to_string(),
        description: "Targeted email phishing campaign".to_string(),
        difficulty: AttackDifficulty::Medium,
        risk_level: RiskLevel::High,
        techniques: vec!["Social Engineering".to_string(), "Email Spoofing".to_string()],
        mitigations: vec!["Email filtering".to_string(), "User training".to_string()],
    };

    assert_eq!(vector.name, "Email Phishing");
    assert_eq!(vector.difficulty, AttackDifficulty::Medium);
    assert_eq!(vector.risk_level, RiskLevel::High);
    assert_eq!(vector.techniques.len(), 2);
    assert_eq!(vector.mitigations.len(), 2);
}

#[test]
fn test_security_finding_creation() {
    let finding = SecurityFinding {
        id: "FIND-001".to_string(),
        title: "Test Security Finding".to_string(),
        description: "This is a test security finding".to_string(),
        severity: FindingSeverity::Medium,
        category: FindingCategory::Authentication,
        cvss_score: Some(6.5),
        affected_components: vec!["Login System".to_string()],
        remediation_steps: vec!["Step 1".to_string(), "Step 2".to_string()],
        references: vec!["https://example.com/vuln".to_string()],
        discovered_at: Utc::now(),
    };

    assert_eq!(finding.id, "FIND-001");
    assert_eq!(finding.severity, FindingSeverity::Medium);
    assert_eq!(finding.category, FindingCategory::Authentication);
    assert_eq!(finding.cvss_score, Some(6.5));
    assert_eq!(finding.affected_components.len(), 1);
    assert_eq!(finding.remediation_steps.len(), 2);
}

#[test]
fn test_campaign_metrics_aggregation() {
    let metrics = CampaignMetrics {
        total_scenarios: 10,
        successful_scenarios: 7,
        failed_scenarios: 3,
        average_execution_time: 120.5,
        findings_discovered: 5,
        critical_findings: 1,
        high_findings: 2,
        medium_findings: 2,
        low_findings: 0,
        success_rate: 0.7,
    };

    assert_eq!(metrics.total_scenarios, 10);
    assert_eq!(metrics.successful_scenarios, 7);
    assert_eq!(metrics.failed_scenarios, 3);
    assert_eq!(metrics.findings_discovered, 5);
    assert_eq!(metrics.success_rate, 0.7);

    // Validate calculations
    assert_eq!(metrics.successful_scenarios + metrics.failed_scenarios, metrics.total_scenarios);
    assert_eq!(
        metrics.critical_findings
            + metrics.high_findings
            + metrics.medium_findings
            + metrics.low_findings,
        metrics.findings_discovered
    );
}

#[test]
fn test_difficulty_level_ordering() {
    assert!(AttackDifficulty::Low < AttackDifficulty::Medium);
    assert!(AttackDifficulty::Medium < AttackDifficulty::High);
    assert!(AttackDifficulty::High < AttackDifficulty::Expert);
}

#[test]
fn test_finding_severity_ordering() {
    assert!(FindingSeverity::Info < FindingSeverity::Low);
    assert!(FindingSeverity::Low < FindingSeverity::Medium);
    assert!(FindingSeverity::Medium < FindingSeverity::High);
    assert!(FindingSeverity::High < FindingSeverity::Critical);
}

#[test]
fn test_risk_level_ordering() {
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);
}

#[test]
fn test_finding_category_enumeration() {
    let categories = vec![
        FindingCategory::Authentication,
        FindingCategory::Authorization,
        FindingCategory::DataValidation,
        FindingCategory::Cryptography,
        FindingCategory::SessionManagement,
        FindingCategory::ErrorHandling,
        FindingCategory::Logging,
        FindingCategory::Configuration,
        FindingCategory::NetworkSecurity,
        FindingCategory::Other("Custom Category".to_string()),
    ];

    // Test serialization/deserialization
    for category in categories {
        let serialized = serde_json::to_string(&category).unwrap();
        let deserialized: FindingCategory = serde_json::from_str(&serialized).unwrap();
        assert_eq!(category, deserialized);
    }
}

#[tokio::test]
async fn test_scenario_execution_safety() {
    // Ensure that test scenarios don't perform actual attacks
    let mut framework = RedTeamFramework::new("http://localhost:8080".to_string()).await.unwrap();
    let mut reporter = RedTeamReporter::new("safety_test".to_string());

    // All scenarios should run in "test" mode without making real network requests
    let _result = run_token_scenarios(&mut framework, &mut reporter, "test").await;
    assert!(result.is_ok());

    // Verify that the reporter has captured some results
    let report = reporter.generate_report().await;
    assert!(!report.scenario_results.is_empty());

    // Ensure all scenarios are marked as simulated/test runs
    for (_, result) in report.scenario_results.iter() {
        assert!(result.details.contains("simulated") || result.details.contains("test"));
    }
}
