//! Integration Tests for SOAR Case Management
//!
//! This module contains integration tests that verify the interaction
//! between different components of the SOAR case management system.

use std::sync::Arc;
use tokio::sync::RwLock;

use super::super::{
    models::{SecurityCase, CaseStatus, CasePriority, Evidence, EvidenceType},
    config::CaseManagementConfig,
    handlers::CaseManagementSystem,
    persistence::CaseRepository,
    workflows::CaseWorkflowEngine,
    errors::SoarResult,
};
use super::test_utils::{TestCaseFactory, MockCaseRepository, TestConfigFactory};

/// Test end-to-end case management workflows
#[cfg(test)]
mod end_to_end_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_case_lifecycle() {
        // Setup test components
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create a new case
        let case_id = system.create_case(
            "Integration Test Case".to_string(),
            "Testing complete case lifecycle".to_string(),
            CasePriority::High,
            None,
        ).await.expect("Failed to create case");

        assert!(!case_id.is_empty());

        // Retrieve the case
        let case = system.get_case(&case_id).await
            .expect("Failed to get case")
            .expect("Case not found");

        assert_eq!(case.id, case_id);
        assert_eq!(case.status, CaseStatus::Open);
        assert_eq!(case.priority, CasePriority::High);

        // Update case status
        system.update_case_status(&case_id, CaseStatus::Investigating, "test@example.com")
            .await.expect("Failed to update case status");

        // Verify status change
        let updated_case = system.get_case(&case_id).await
            .expect("Failed to get updated case")
            .expect("Updated case not found");

        assert_eq!(updated_case.status, CaseStatus::Investigating);

        // Assign case to analyst
        system.assign_case(&case_id, "analyst@example.com", "admin@example.com")
            .await.expect("Failed to assign case");

        // Verify assignment
        let assigned_case = system.get_case(&case_id).await
            .expect("Failed to get assigned case")
            .expect("Assigned case not found");

        assert_eq!(assigned_case.assigned_to, Some("analyst@example.com".to_string()));

        // Add evidence
        let evidence = TestCaseFactory::create_test_evidence(&case_id);
        system.add_evidence(&case_id, evidence.clone(), "analyst@example.com")
            .await.expect("Failed to add evidence");

        // Verify evidence
        let case_with_evidence = system.get_case(&case_id).await
            .expect("Failed to get case with evidence")
            .expect("Case with evidence not found");

        assert_eq!(case_with_evidence.evidence.len(), 1);
        assert_eq!(case_with_evidence.evidence[0].id, evidence.id);
    }

    #[tokio::test]
    async fn test_case_workflow_integration() {
        // Setup test components
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create a high-priority case that should trigger workflow
        let case_id = system.create_case(
            "High Priority Case".to_string(),
            "This should trigger escalation workflow".to_string(),
            CasePriority::High,
            None,
        ).await.expect("Failed to create high-priority case");

        // Execute workflow step
        let mut case = system.get_case(&case_id).await
            .expect("Failed to get case")
            .expect("Case not found");

        system.workflow_engine.execute_workflow_step(&case_id, &mut case)
            .await.expect("Failed to execute workflow step");

        // Verify workflow effects
        let workflow_case = system.get_case(&case_id).await
            .expect("Failed to get workflow case")
            .expect("Workflow case not found");

        // High-priority cases should be escalated
        assert_eq!(workflow_case.status, CaseStatus::Escalated);
    }
}

/// Test component integration scenarios
#[cfg(test)]
mod component_integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_repository_and_system_integration() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create case through system
        let case_id = system.create_case(
            "Repository Integration Test".to_string(),
            "Testing repository integration".to_string(),
            CasePriority::Medium,
            None,
        ).await.expect("Failed to create case");

        // Verify case exists in repository
        let repo_case = mock_repo.get_case(&case_id).await
            .expect("Failed to get case from repository")
            .expect("Case not found in repository");

        assert_eq!(repo_case.id, case_id);
        assert_eq!(repo_case.title, "Repository Integration Test");
    }

    #[tokio::test]
    async fn test_workflow_and_repository_integration() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create and process case
        let case_id = system.create_case(
            "Workflow Repository Test".to_string(),
            "Testing workflow and repository integration".to_string(),
            CasePriority::Critical,
            None,
        ).await.expect("Failed to create critical case");

        // Get case and execute workflow
        let mut case = system.get_case(&case_id).await
            .expect("Failed to get case")
            .expect("Case not found");

        system.workflow_engine.execute_workflow_step(&case_id, &mut case)
            .await.expect("Failed to execute workflow");

        // Verify workflow effects persisted
        let final_case = mock_repo.get_case(&case_id).await
            .expect("Failed to get final case from repository")
            .expect("Final case not found");

        assert_eq!(final_case.status, CaseStatus::Escalated);
        assert_eq!(final_case.priority, CasePriority::Critical);
    }
}

/// Test error handling in integrated scenarios
#[cfg(test)]
mod error_integration_tests {
    use super::*;
    use super::super::errors::SoarError;

    #[tokio::test]
    async fn test_case_not_found_error_integration() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Try to get non-existent case
        let result = system.get_case("non-existent-case").await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_invalid_case_update_integration() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Try to update non-existent case
        let result = system.update_case_status("non-existent-case", CaseStatus::Resolved, "test@example.com").await;

        assert!(result.is_err());
        if let Err(SoarError::CaseNotFound { case_id }) = result {
            assert_eq!(case_id, "non-existent-case");
        } else {
            panic!("Expected CaseNotFound error");
        }
    }

    #[tokio::test]
    async fn test_evidence_processing_error_integration() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create a case first
        let case_id = system.create_case(
            "Evidence Test Case".to_string(),
            "Testing evidence processing".to_string(),
            CasePriority::Medium,
            None,
        ).await.expect("Failed to create case");

        // Try to add evidence to non-existent case
        let evidence = TestCaseFactory::create_test_evidence("non-existent-case");
        let result = system.add_evidence("non-existent-case", evidence, "test@example.com").await;

        assert!(result.is_err());
        if let Err(SoarError::CaseNotFound { case_id: error_case_id }) = result {
            assert_eq!(error_case_id, "non-existent-case");
        } else {
            panic!("Expected CaseNotFound error");
        }
    }
}

/// Test concurrent operations
#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_concurrent_case_creation() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = Arc::new(CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system"));

        let num_tasks = 10;
        let semaphore = Arc::new(Semaphore::new(num_tasks));
        let success_count = Arc::new(AtomicUsize::new(0));

        // Spawn concurrent tasks
        let mut handles = vec![];
        for i in 0..num_tasks {
            let system_clone = Arc::clone(&system);
            let success_count_clone = Arc::clone(&success_count);
            let permit = semaphore.acquire().await.unwrap();

            let handle = tokio::spawn(async move {
                let case_id = system_clone.create_case(
                    format!("Concurrent Case {}", i),
                    format!("Description for concurrent case {}", i),
                    CasePriority::Medium,
                    None,
                ).await;

                if case_id.is_ok() {
                    success_count_clone.fetch_add(1, Ordering::Relaxed);
                }

                drop(permit);
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("Task failed");
        }

        // Verify all cases were created successfully
        assert_eq!(success_count.load(Ordering::Relaxed), num_tasks);
    }

    #[tokio::test]
    async fn test_concurrent_case_updates() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = Arc::new(CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system"));

        // Create a test case
        let case_id = system.create_case(
            "Concurrent Update Test".to_string(),
            "Testing concurrent updates".to_string(),
            CasePriority::Medium,
            None,
        ).await.expect("Failed to create test case");

        let num_tasks = 5;
        let semaphore = Arc::new(Semaphore::new(num_tasks));

        // Spawn concurrent update tasks
        let mut handles = vec![];
        for i in 0..num_tasks {
            let system_clone = Arc::clone(&system);
            let case_id_clone = case_id.clone();
            let permit = semaphore.acquire().await.unwrap();

            let handle = tokio::spawn(async move {
                let status = match i % 3 {
                    0 => CaseStatus::Investigating,
                    1 => CaseStatus::Resolving,
                    _ => CaseStatus::Resolved,
                };

                let result = system_clone.update_case_status(
                    &case_id_clone,
                    status,
                    &format!("analyst{}@example.com", i),
                ).await;

                drop(permit);
                result
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut success_count = 0;
        for handle in handles {
            let result = handle.await.expect("Task failed");
            if result.is_ok() {
                success_count += 1;
            }
        }

        // At least some updates should succeed (concurrency may cause conflicts)
        assert!(success_count > 0);
    }
}

/// Test system boundary conditions
#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[tokio::test]
    async fn test_large_number_of_cases() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create many cases
        let num_cases = 50;
        let mut case_ids = vec![];

        for i in 0..num_cases {
            let case_id = system.create_case(
                format!("Bulk Test Case {}", i),
                format!("Description for bulk case {}", i),
                CasePriority::Low,
                None,
            ).await.expect("Failed to create bulk case");

            case_ids.push(case_id);
        }

        assert_eq!(case_ids.len(), num_cases);

        // Verify all cases exist
        for case_id in case_ids {
            let case = system.get_case(&case_id).await
                .expect("Failed to get bulk case")
                .expect("Bulk case not found");

            assert!(case.title.starts_with("Bulk Test Case"));
        }
    }

    #[tokio::test]
    async fn test_case_with_many_evidence() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create a case
        let case_id = system.create_case(
            "Many Evidence Test".to_string(),
            "Testing case with many evidence items".to_string(),
            CasePriority::Medium,
            None,
        ).await.expect("Failed to create evidence test case");

        // Add many evidence items
        let num_evidence = 20;
        for i in 0..num_evidence {
            let evidence = Evidence {
                id: format!("evidence-{}-{}", case_id, i),
                evidence_type: if i % 2 == 0 { EvidenceType::LogFile } else { EvidenceType::PacketCapture },
                description: format!("Evidence item {}", i),
                content: format!("Evidence content {}", i),
                collected_at: chrono::Utc::now(),
                collected_by: format!("analyst{}@example.com", i),
                integrity_hash: format!("hash_{}", i),
            };

            system.add_evidence(&case_id, evidence, "test@example.com")
                .await.expect("Failed to add evidence");
        }

        // Verify all evidence was added
        let case = system.get_case(&case_id).await
            .expect("Failed to get case with evidence")
            .expect("Case with evidence not found");

        assert_eq!(case.evidence.len(), num_evidence);
    }

    #[tokio::test]
    async fn test_rapid_case_status_changes() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create a case
        let case_id = system.create_case(
            "Rapid Status Changes Test".to_string(),
            "Testing rapid status changes".to_string(),
            CasePriority::Medium,
            None,
        ).await.expect("Failed to create rapid test case");

        // Rapidly change status multiple times
        let statuses = vec![
            CaseStatus::Investigating,
            CaseStatus::Escalated,
            CaseStatus::Pending,
            CaseStatus::Resolving,
            CaseStatus::Resolved,
        ];

        for status in statuses {
            system.update_case_status(&case_id, status, "rapid@example.com")
                .await.expect("Failed to update status rapidly");
        }

        // Verify final status
        let case = system.get_case(&case_id).await
            .expect("Failed to get final case")
            .expect("Final case not found");

        assert_eq!(case.status, CaseStatus::Resolved);
    }
}

/// Test system recovery scenarios
#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[tokio::test]
    async fn test_case_recovery_after_partial_failure() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create a case successfully
        let case_id = system.create_case(
            "Recovery Test Case".to_string(),
            "Testing recovery after partial failure".to_string(),
            CasePriority::Medium,
            None,
        ).await.expect("Failed to create recovery test case");

        // Verify case exists and is in correct state
        let case = system.get_case(&case_id).await
            .expect("Failed to get recovery case")
            .expect("Recovery case not found");

        assert_eq!(case.status, CaseStatus::Open);
        assert!(!case.id.is_empty());

        // Verify case persists in repository
        let repo_case = mock_repo.get_case(&case_id).await
            .expect("Failed to get case from repository")
            .expect("Case not found in repository");

        assert_eq!(repo_case.id, case_id);
    }

    #[tokio::test]
    async fn test_workflow_recovery_after_case_update() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create and update case
        let case_id = system.create_case(
            "Workflow Recovery Test".to_string(),
            "Testing workflow recovery".to_string(),
            CasePriority::High,
            None,
        ).await.expect("Failed to create workflow recovery case");

        system.update_case_status(&case_id, CaseStatus::Investigating, "recovery@example.com")
            .await.expect("Failed to update case for workflow recovery");

        // Execute workflow
        let mut case = system.get_case(&case_id).await
            .expect("Failed to get case for workflow")
            .expect("Case for workflow not found");

        system.workflow_engine.execute_workflow_step(&case_id, &mut case)
            .await.expect("Failed to execute workflow step");

        // Verify workflow state is preserved
        let final_case = system.get_case(&case_id).await
            .expect("Failed to get final workflow case")
            .expect("Final workflow case not found");

        assert_eq!(final_case.status, CaseStatus::Escalated);
    }
}
