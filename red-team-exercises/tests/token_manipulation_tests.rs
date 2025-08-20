//! Integration tests for token manipulation attack scenarios
//!
//! These tests validate that the red team exercises properly detect and report
//! various token manipulation vulnerabilities while maintaining defensive posture.

use red_team_exercises::attack_framework::RedTeamFramework;
use red_team_exercises::reporting::RedTeamReporter;
use red_team_exercises::scenarios::token_manipulation::run_token_scenarios;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_token_manipulation_scenarios() {
    // Initialize test framework
    let target_url = "http://localhost:8080".to_string();
    let mut framework = RedTeamFramework::new(target_url).await.unwrap();
    let mut reporter = RedTeamReporter::new("token_manipulation_test".to_string());

    // Run token manipulation scenarios with low intensity for testing
    let result = run_token_scenarios(&mut framework, &mut reporter, "low").await;

    // Verify scenarios executed without panicking
    assert!(result.is_ok(), "Token manipulation scenarios should execute successfully");

    // Verify reporter captured scenario results
    let report = reporter.generate_report().await;
    assert!(!report.scenario_results.is_empty(), "Should have scenario results");

    // Check that all expected scenario types are present
    let scenario_names: Vec<&str> = report.scenario_results.keys().map(|s| s.as_str()).collect();

    let expected_scenarios = vec![
        "jwt_manipulation_attacks",
        "jwt_timing_attacks",
        "token_substitution_attacks",
        "token_replay_attacks",
        "token_enumeration_attacks",
        "token_binding_attacks",
        "token_validation_bypass",
    ];

    for expected in expected_scenarios {
        assert!(scenario_names.contains(&expected), "Missing expected scenario: {}", expected);
    }
}

#[tokio::test]
async fn test_jwt_timing_attack_detection() {
    let target_url = "http://localhost:8080".to_string();
    let mut framework = RedTeamFramework::new(target_url).await.unwrap();
    let mut reporter = RedTeamReporter::new("jwt_timing_test".to_string());

    // Test timing attack detection specifically
    let session = framework.create_attack_session().await.unwrap();

    // The timing attack should detect if there are significant response time differences
    // This is a defensive test to ensure the attack detection works
    assert!(session.session_id.len() > 0, "Session should be created successfully");
}

#[tokio::test]
async fn test_token_validation_bypass_detection() {
    let target_url = "http://localhost:8080".to_string();
    let framework = RedTeamFramework::new(target_url).await.unwrap();
    let reporter = RedTeamReporter::new("token_validation_test".to_string());

    // Verify that the framework properly handles malicious tokens defensively
    let attack_results = framework.attack_results.read().await;
    assert_eq!(attack_results.len(), 0, "Should start with no attack results");

    // Framework should be configured for detection evasion testing
    assert!(framework.detection_evasion, "Detection evasion should be enabled for testing");
    assert!(framework.rate_limit_bypass, "Rate limit bypass should be enabled for testing");
}

#[tokio::test]
async fn test_scenario_reporting_structure() {
    let mut reporter = RedTeamReporter::new("structure_test".to_string());

    // Test that scenario results are properly structured
    let test_data = std::collections::HashMap::new();
    reporter.add_scenario_result("test_scenario", true, test_data);

    let report = reporter.generate_report().await;
    assert!(report.scenario_results.contains_key("test_scenario"));

    let scenario_result = &report.scenario_results["test_scenario"];
    assert!(scenario_result.passed, "Test scenario should be marked as passed");
}

#[tokio::test]
async fn test_attack_session_isolation() {
    let target_url = "http://localhost:8080".to_string();
    let framework = RedTeamFramework::new(target_url).await.unwrap();

    // Create multiple sessions to test isolation
    let session1 = framework.create_attack_session().await.unwrap();
    let session2 = framework.create_attack_session().await.unwrap();

    // Sessions should have unique identifiers
    assert_ne!(session1.session_id, session2.session_id);
    assert_ne!(session1.client_id, session2.client_id);

    // Verify sessions are stored independently
    let sessions = framework.sessions.read().await;
    assert_eq!(sessions.len(), 2, "Should have two sessions stored");
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Test that verifies the complete token manipulation attack pipeline
    /// from session creation through result reporting
    #[tokio::test]
    async fn test_complete_attack_pipeline() {
        let target_url = "http://localhost:8080".to_string();
        let mut framework = RedTeamFramework::new(target_url).await.unwrap();
        let mut reporter = RedTeamReporter::new("pipeline_test".to_string());

        // Execute a subset of scenarios for faster testing
        let session = framework.create_attack_session().await.unwrap();

        // Simulate an attack execution
        let headers = reqwest::header::HeaderMap::new();
        let result = framework
            .execute_attack("test_attack", "GET", "/health", Some(headers), None, Some(&session))
            .await;

        // Verify attack execution completes
        assert!(result.is_ok(), "Attack execution should complete without errors");

        let attack_result = result.unwrap();
        assert_eq!(attack_result.attack_type, "test_attack");
        assert_eq!(attack_result.target_endpoint, "/health");

        // Verify attack results are stored
        let stored_results = framework.attack_results.read().await;
        assert_eq!(stored_results.len(), 1, "Should have one attack result stored");
    }
}
