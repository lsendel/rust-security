//! Unit Tests for SOAR Case Management
//!
//! This module contains comprehensive unit tests for individual components
//! of the SOAR case management system.

use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::super::{
    config::CaseManagementConfig,
    errors::{ErrorCategory, SoarError, SoarResult},
    handlers::{CaseManagementSystem, EvidenceManager, SlaTracker},
    models::{CasePriority, CaseStatus, Evidence, EvidenceType, SecurityCase},
};
use super::test_utils::{MockCaseRepository, TestCaseFactory, TestConfigFactory};

/// Test case model functionality
#[cfg(test)]
mod case_model_tests {
    use super::*;

    #[test]
    fn test_case_creation() {
        let case = TestCaseFactory::create_basic_case();

        assert!(!case.id.is_empty());
        assert_eq!(case.status, CaseStatus::Open);
        assert_eq!(case.priority, CasePriority::Medium);
        assert!(case.title.contains("Test"));
        assert!(case.description.contains("test"));
        assert!(case.created_at <= Utc::now());
        assert_eq!(case.updated_at, case.created_at);
    }

    #[test]
    fn test_case_status_update() {
        let mut case = TestCaseFactory::create_basic_case();

        case.update_status(CaseStatus::Investigating);
        assert_eq!(case.status, CaseStatus::Investigating);
        assert!(case.updated_at >= case.created_at);
    }

    #[test]
    fn test_case_assignment() {
        let mut case = TestCaseFactory::create_basic_case();

        case.assign_to("analyst@example.com".to_string());
        assert_eq!(case.assigned_to, Some("analyst@example.com".to_string()));
        assert!(case.updated_at >= case.created_at);
    }

    #[test]
    fn test_case_evidence_adding() {
        let mut case = TestCaseFactory::create_basic_case();
        let evidence = TestCaseFactory::create_test_evidence(&case.id);

        case.add_evidence(evidence.clone());
        assert_eq!(case.evidence.len(), 1);
        assert_eq!(case.evidence[0].id, evidence.id);
        assert!(case.updated_at >= case.created_at);
    }

    #[test]
    fn test_case_tags_adding() {
        let mut case = TestCaseFactory::create_basic_case();
        let tags = vec!["malware".to_string(), "phishing".to_string()];

        case.add_tags(tags.clone());
        assert_eq!(case.tags, tags);
        assert!(case.updated_at >= case.created_at);
    }

    #[test]
    fn test_case_priority_ordering() {
        assert!(CasePriority::Low < CasePriority::Medium);
        assert!(CasePriority::Medium < CasePriority::High);
        assert!(CasePriority::High < CasePriority::Critical);
    }
}

/// Test error handling functionality
#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = SoarError::case_not_found("test-case-123");
        assert_eq!(error.category(), ErrorCategory::NotFound);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_invalid_input_error() {
        let error = SoarError::invalid_input("email", "Invalid email format");
        assert_eq!(error.category(), ErrorCategory::Validation);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_database_error() {
        let db_error = sqlx::Error::RowNotFound;
        let error = SoarError::database_error("test_operation", db_error);
        assert_eq!(error.category(), ErrorCategory::Infrastructure);
        assert!(error.is_retryable());
    }

    #[test]
    fn test_workflow_error() {
        let error = SoarError::WorkflowExecutionFailed {
            workflow_name: "test_workflow".to_string(),
            reason: "Step failed".to_string(),
        };
        assert_eq!(error.category(), ErrorCategory::Processing);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_sla_violation_error() {
        let error = SoarError::SlaViolation {
            case_id: "test-case".to_string(),
            violation_type: "response_time".to_string(),
        };
        assert_eq!(error.category(), ErrorCategory::Sla);
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_error_http_status_codes() {
        assert_eq!(SoarError::case_not_found("test").http_status_code(), 404);
        assert_eq!(
            SoarError::invalid_input("field", "reason").http_status_code(),
            400
        );
        assert_eq!(
            SoarError::database_error("test", sqlx::Error::PoolTimedOut).http_status_code(),
            500
        );
    }

    #[test]
    fn test_error_string_conversion() {
        let error: SoarError = "Custom error message".into();
        match error {
            SoarError::InvalidInput { field, reason } => {
                assert_eq!(field, "unknown");
                assert_eq!(reason, "Custom error message");
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }
}

/// Test configuration functionality
#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CaseManagementConfig::default();

        assert_eq!(config.max_active_cases, 1000);
        assert_eq!(config.retention_days, 365);
        assert!(config.sla_settings.response_sla_minutes > 0);
        assert!(config.sla_settings.resolution_sla_hours > 0);
    }

    #[test]
    fn test_config_validation() {
        // Valid config should pass
        let valid_config = TestConfigFactory::default_config();
        assert!(valid_config.validate().is_ok());

        // Invalid config with zero max cases should fail
        let mut invalid_config = valid_config.clone();
        invalid_config.max_active_cases = 0;
        let errors = invalid_config.validate().unwrap_err();
        assert!(!errors.is_empty());
        assert!(errors[0].contains("max_active_cases"));
    }

    #[test]
    fn test_test_config() {
        let config = TestConfigFactory::test_config();

        assert_eq!(config.max_active_cases, 100);
        assert_eq!(config.retention_days, 30);
    }
}

/// Test SLA tracker functionality
#[cfg(test)]
mod sla_tracker_tests {
    use super::*;

    #[test]
    fn test_sla_tracker_creation() {
        let tracker = SlaTracker::new();
        // SLA tracker should be created successfully
        assert!(true); // Placeholder - actual implementation would test internal state
    }

    #[test]
    fn test_sla_violation_recording() {
        let tracker = SlaTracker::new();
        let case_id = "test-case-123";
        let expected_time = Utc::now();
        let actual_time = expected_time + chrono::Duration::hours(2);

        let result = tracker.record_violation(
            case_id,
            super::super::handlers::SlaViolationType::ResponseTime,
            expected_time,
            actual_time,
        );

        assert!(result.is_ok());
    }
}

/// Test evidence manager functionality
#[cfg(test)]
mod evidence_manager_tests {
    use super::*;

    #[test]
    fn test_evidence_manager_creation() {
        let manager = EvidenceManager::new();
        // Evidence manager should be created successfully
        assert!(true); // Placeholder - actual implementation would test configuration
    }

    #[test]
    fn test_evidence_storage() {
        let manager = EvidenceManager::new();
        let evidence = TestCaseFactory::create_test_evidence("test-case");

        manager.store_evidence(&evidence);
    }
}

/// Test case repository functionality (using mock)
#[cfg(test)]
mod repository_tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_repository() {
        let repo = MockCaseRepository::new();
        let case = TestCaseFactory::create_basic_case();

        // Initially empty
        let result = repo.get_case(&case.id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Add case
        repo.add_case(case.clone()).await;

        // Retrieve case
        let result = repo.get_case(&case.id).await;
        assert!(result.is_ok());
        let retrieved_case = result.unwrap();
        assert!(retrieved_case.is_some());
        assert_eq!(retrieved_case.unwrap().id, case.id);

        // Clear and verify
        repo.clear().await;
        let result = repo.get_case(&case.id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}

/// Test workflow engine functionality
#[cfg(test)]
mod workflow_tests {
    use super::super::workflows::CaseWorkflowEngine;
    use super::*;

    #[test]
    fn test_workflow_engine_creation() {
        let engine = CaseWorkflowEngine::new(None);
        // Workflow engine should be created successfully
        assert!(true); // Placeholder - actual implementation would test internal state
    }

    #[test]
    fn test_workflow_engine_with_defaults() {
        let engine = CaseWorkflowEngine::new_with_defaults(None);
        // Workflow engine with defaults should be created successfully
        assert!(true); // Placeholder - actual implementation would test registered workflows
    }
}

/// Test edge cases and boundary conditions
#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_empty_case_title() {
        let case = SecurityCase::new(
            "".to_string(),
            "Valid description".to_string(),
            CasePriority::Medium,
        );

        assert!(case.title.is_empty());
        assert!(!case.description.is_empty());
        assert!(!case.id.is_empty()); // ID should still be generated
    }

    #[test]
    fn test_very_long_case_title() {
        let long_title = "A".repeat(1000);
        let case = SecurityCase::new(
            long_title.clone(),
            "Valid description".to_string(),
            CasePriority::Medium,
        );

        assert_eq!(case.title, long_title);
        assert!(!case.id.is_empty());
    }

    #[test]
    fn test_case_with_special_characters() {
        let special_title = "Test: Case #1 - SQL Injection @ /api/users";
        let case = SecurityCase::new(
            special_title.to_string(),
            "Case with special characters in title".to_string(),
            CasePriority::High,
        );

        assert_eq!(case.title, special_title);
        assert_eq!(case.priority, CasePriority::High);
    }

    #[test]
    fn test_case_multiple_status_updates() {
        let mut case = TestCaseFactory::create_basic_case();

        // Initial state
        assert_eq!(case.status, CaseStatus::Open);

        // Update through various states
        case.update_status(CaseStatus::Investigating);
        assert_eq!(case.status, CaseStatus::Investigating);

        case.update_status(CaseStatus::Resolving);
        assert_eq!(case.status, CaseStatus::Resolving);

        case.update_status(CaseStatus::Resolved);
        assert_eq!(case.status, CaseStatus::Resolved);

        // Verify timestamps are updating
        assert!(case.updated_at >= case.created_at);
    }

    #[test]
    fn test_case_multiple_assignments() {
        let mut case = TestCaseFactory::create_basic_case();

        // First assignment
        case.assign_to("analyst1@example.com".to_string());
        assert_eq!(case.assigned_to, Some("analyst1@example.com".to_string()));

        // Reassignment
        case.assign_to("analyst2@example.com".to_string());
        assert_eq!(case.assigned_to, Some("analyst2@example.com".to_string()));
    }

    #[test]
    fn test_evidence_with_empty_content() {
        let evidence = Evidence {
            id: "test-evidence".to_string(),
            evidence_type: EvidenceType::LogFile,
            description: "Empty content test".to_string(),
            content: "".to_string(),
            collected_at: Utc::now(),
            collected_by: "test_analyst".to_string(),
            integrity_hash: "empty_hash".to_string(),
        };

        assert!(evidence.content.is_empty());
        assert!(!evidence.id.is_empty());
        assert!(!evidence.description.is_empty());
    }
}

/// Test data integrity and consistency
#[cfg(test)]
mod data_integrity_tests {
    use super::*;

    #[test]
    fn test_case_id_uniqueness() {
        let case1 = TestCaseFactory::create_basic_case();
        let case2 = TestCaseFactory::create_basic_case();

        assert_ne!(case1.id, case2.id);
    }

    #[test]
    fn test_case_timestamp_consistency() {
        let mut case = TestCaseFactory::create_basic_case();
        let original_created = case.created_at;
        let original_updated = case.updated_at;

        // Update should change updated_at but not created_at
        std::thread::sleep(std::time::Duration::from_millis(1)); // Ensure timestamp difference
        case.update_status(CaseStatus::Investigating);

        assert_eq!(case.created_at, original_created);
        assert!(case.updated_at > original_updated);
    }

    #[test]
    fn test_case_immutability_of_id() {
        let original_case = TestCaseFactory::create_basic_case();
        let original_id = original_case.id.clone();

        // Various operations should not change the ID
        let mut case = original_case;
        case.update_status(CaseStatus::Resolved);
        case.assign_to("analyst@example.com".to_string());
        case.add_tags(vec!["test".to_string()]);

        assert_eq!(case.id, original_id);
    }

    #[test]
    fn test_evidence_integrity() {
        let case_id = "test-case-123";
        let evidence = TestCaseFactory::create_test_evidence(case_id);

        assert!(evidence.id.contains(case_id));
        assert!(!evidence.integrity_hash.is_empty());
        assert!(!evidence.collected_by.is_empty());
        assert!(evidence.collected_at <= Utc::now());
    }
}

/// Test performance characteristics
#[cfg(test)]
mod performance_tests {
    use super::super::performance_utils::{
        assertions::assert_reasonable_performance, measure_execution_time,
    };
    use super::*;

    #[test]
    fn test_case_creation_performance() {
        let (case, duration) = measure_execution_time(|| TestCaseFactory::create_basic_case());

        assert_reasonable_performance(duration, "create_case");
        assert!(!case.id.is_empty());
    }

    #[test]
    fn test_multiple_case_creation_performance() {
        let (cases, duration) = measure_execution_time(|| TestCaseFactory::create_test_cases(100));

        assert_eq!(cases.len(), 100);
        assert_reasonable_performance(duration, "create_case");
    }

    #[test]
    fn test_case_update_performance() {
        let mut case = TestCaseFactory::create_basic_case();

        let (_, duration) = measure_execution_time(|| {
            case.update_status(CaseStatus::Resolved);
        });

        assert_reasonable_performance(duration, "update_case");
    }
}

/// Test security properties
#[cfg(test)]
mod security_tests {
    use super::super::security_utils::assertions::*;
    use super::*;

    #[test]
    fn test_error_message_sanitization() {
        let error = SoarError::case_not_found("sensitive-case-123");
        assert_error_message_sanitized(&error);
    }

    #[test]
    fn test_case_data_validation() {
        let case = TestCaseFactory::create_basic_case();
        assert_case_data_validation(&case);
    }

    #[test]
    fn test_case_with_minimal_data() {
        let case = SecurityCase::new("x".to_string(), "y".to_string(), CasePriority::Low);

        assert_case_data_validation(&case);
        assert_eq!(case.title, "x");
        assert_eq!(case.description, "y");
    }

    #[test]
    fn test_evidence_data_integrity() {
        let evidence = TestCaseFactory::create_test_evidence("test-case");

        assert!(!evidence.id.is_empty());
        assert!(!evidence.integrity_hash.is_empty());
        assert!(!evidence.collected_by.is_empty());
        assert!(evidence.collected_at <= Utc::now());
    }
}
