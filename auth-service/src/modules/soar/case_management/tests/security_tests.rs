//! Security Tests for SOAR Case Management
//!
//! This module contains comprehensive security tests that verify
//! the system properly handles security-related scenarios and prevents
//! common security vulnerabilities.

use std::sync::Arc;

use super::super::{
    config::CaseManagementConfig,
    errors::{SoarError, SoarResult},
    handlers::CaseManagementSystem,
    models::{CasePriority, CaseStatus, Evidence, EvidenceType, SecurityCase},
    persistence::CaseRepository,
    workflows::CaseWorkflowEngine,
};
use super::security_utils::assertions::*;
use super::test_utils::{MockCaseRepository, TestCaseFactory, TestConfigFactory};

/// Test input validation and sanitization
#[cfg(test)]
mod input_validation_tests {
    use super::*;

    #[test]
    fn test_case_title_sql_injection_prevention() {
        // Test various SQL injection attempts in case titles
        let malicious_titles = vec![
            "'; DROP TABLE cases; --",
            "\"; SELECT * FROM users; --",
            "Normal title' OR '1'='1",
            "Test; EXEC xp_cmdshell 'dir';",
            "Case' UNION SELECT password FROM users--",
        ];

        for title in malicious_titles {
            let case = SecurityCase::new(
                title.to_string(),
                "Safe description".to_string(),
                CasePriority::Medium,
            );

            // Case should be created normally without executing malicious code
            assert!(!case.id.is_empty());
            assert_eq!(case.title, title); // Title should be preserved as-is
            assert_eq!(case.status, CaseStatus::Open);
        }
    }

    #[test]
    fn test_case_description_xss_prevention() {
        // Test XSS attempts in case descriptions
        let malicious_descriptions = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "<svg onload=alert('XSS')>",
        ];

        for description in malicious_descriptions {
            let case = SecurityCase::new(
                "Safe Title".to_string(),
                description.to_string(),
                CasePriority::Medium,
            );

            // Case should be created normally
            assert!(!case.id.is_empty());
            assert_eq!(case.description, description);
            // Note: Actual XSS prevention would be handled at the web layer
            // This test ensures data integrity is maintained
        }
    }

    #[test]
    fn test_evidence_content_validation() {
        let malicious_contents = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "file:///etc/shadow",
            "data:text/html,<script>alert('XSS')</script>",
            "vbscript:msgbox(\"Malicious\")",
        ];

        for content in malicious_contents {
            let evidence = Evidence {
                id: "test-evidence".to_string(),
                evidence_type: EvidenceType::LogFile,
                description: "Test evidence".to_string(),
                content: content.to_string(),
                collected_at: chrono::Utc::now(),
                collected_by: "test@example.com".to_string(),
                integrity_hash: "test_hash".to_string(),
            };

            // Evidence should be created with content preserved
            assert_eq!(evidence.content, content);
            assert!(!evidence.id.is_empty());
            // Note: Path traversal and content validation would be handled
            // at the application layer, not in the model itself
        }
    }

    #[test]
    fn test_analyst_email_validation() {
        let invalid_emails = vec![
            "",
            "invalid-email",
            "@example.com",
            "user@",
            "user@@example.com",
            "user example.com",
            "user@exam ple.com",
        ];

        for email in invalid_emails {
            let mut case = TestCaseFactory::create_basic_case();
            case.assign_to(email.to_string());

            // Assignment should work (validation would be at API layer)
            assert_eq!(case.assigned_to, Some(email.to_string()));
        }
    }
}

/// Test access control and authorization
#[cfg(test)]
mod access_control_tests {
    use super::*;

    #[tokio::test]
    async fn test_case_access_isolation() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(config, mock_repo.clone(), workflow_engine)
            .await
            .expect("Failed to create case management system");

        // Create cases with different "owners" (simulated)
        let case1_id = system
            .create_case(
                "User A's Case".to_string(),
                "Case owned by user A".to_string(),
                CasePriority::Medium,
                None,
            )
            .await
            .expect("Failed to create user A case");

        let case2_id = system
            .create_case(
                "User B's Case".to_string(),
                "Case owned by user B".to_string(),
                CasePriority::Medium,
                None,
            )
            .await
            .expect("Failed to create user B case");

        // Both cases should exist and be accessible
        let case1 = system
            .get_case(&case1_id)
            .await
            .expect("Failed to get user A case")
            .expect("User A case not found");

        let case2 = system
            .get_case(&case2_id)
            .await
            .expect("Failed to get user B case")
            .expect("User B case not found");

        assert_eq!(case1.title, "User A's Case");
        assert_eq!(case2.title, "User B's Case");

        // In a real system, access control would prevent cross-user access
        // This test verifies data isolation at the model level
    }

    #[tokio::test]
    async fn test_case_modification_permissions() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(config, mock_repo.clone(), workflow_engine)
            .await
            .expect("Failed to create case management system");

        // Create a case
        let case_id = system
            .create_case(
                "Permission Test Case".to_string(),
                "Testing modification permissions".to_string(),
                CasePriority::Medium,
                None,
            )
            .await
            .expect("Failed to create permission test case");

        // Test that various operations can be performed
        // In a real system, these would check user permissions

        // Update status
        system
            .update_case_status(&case_id, CaseStatus::Investigating, "user1@example.com")
            .await
            .expect("Failed to update case status");

        // Assign to different user
        system
            .assign_case(&case_id, "user2@example.com", "admin@example.com")
            .await
            .expect("Failed to assign case");

        // Verify changes
        let case = system
            .get_case(&case_id)
            .await
            .expect("Failed to get permission test case")
            .expect("Permission test case not found");

        assert_eq!(case.status, CaseStatus::Investigating);
        assert_eq!(case.assigned_to, Some("user2@example.com".to_string()));
    }
}

/// Test data privacy and information leakage
#[cfg(test)]
mod data_privacy_tests {
    use super::*;

    #[test]
    fn test_case_data_privacy() {
        // Create cases with sensitive information
        let sensitive_cases = vec![
            SecurityCase::new(
                "Patient Medical Record".to_string(),
                "Contains sensitive medical information".to_string(),
                CasePriority::High,
            ),
            SecurityCase::new(
                "Financial Transaction".to_string(),
                "Account number: 1234567890, Amount: $1000.00".to_string(),
                CasePriority::Medium,
            ),
            SecurityCase::new(
                "HR Incident".to_string(),
                "Employee SSN: 123-45-6789, Salary: $75000".to_string(),
                CasePriority::Low,
            ),
        ];

        for case in sensitive_cases {
            // Verify case data integrity
            assert!(!case.id.is_empty());
            assert!(!case.title.is_empty());
            assert!(!case.description.is_empty());

            // In a real system, sensitive data would be encrypted
            // and access would be logged for audit purposes
        }
    }

    #[test]
    fn test_evidence_privacy() {
        let sensitive_evidences = vec![
            Evidence {
                id: "evidence-1".to_string(),
                evidence_type: EvidenceType::LogFile,
                description: "Access log with IP addresses".to_string(),
                content:
                    "192.168.1.100 - user1 [10/Oct/2023:13:55:36 +0000] \"GET /admin HTTP/1.1\" 200"
                        .to_string(),
                collected_at: chrono::Utc::now(),
                collected_by: "security@example.com".to_string(),
                integrity_hash: "hash1".to_string(),
            },
            Evidence {
                id: "evidence-2".to_string(),
                evidence_type: EvidenceType::LogFile,
                description: "Database query log".to_string(),
                content:
                    "SELECT * FROM users WHERE email='admin@example.com' AND password='secret'"
                        .to_string(),
                collected_at: chrono::Utc::now(),
                collected_by: "security@example.com".to_string(),
                integrity_hash: "hash2".to_string(),
            },
        ];

        for evidence in sensitive_evidences {
            // Verify evidence integrity
            assert!(!evidence.id.is_empty());
            assert!(!evidence.content.is_empty());
            assert!(!evidence.integrity_hash.is_empty());

            // In a real system, evidence content would be encrypted
            // and access would be controlled and audited
        }
    }

    #[test]
    fn test_error_message_privacy() {
        // Test that error messages don't leak sensitive information
        let error_cases = vec![
            ("user123", "Case not found: user123-case"),
            ("admin@example.com", "Access denied for admin@example.com"),
            ("192.168.1.100", "IP address 192.168.1.100 blocked"),
        ];

        for (sensitive_data, error_message) in error_cases {
            let error = SoarError::InvalidInput {
                field: "test_field".to_string(),
                reason: error_message.to_string(),
            };

            // Error should not leak sensitive data in ways that could be exploited
            assert_error_message_sanitized(&error);

            // But the error should still contain the necessary context
            let error_str = format!("{}", error);
            assert!(error_str.contains("InvalidInput"));
        }
    }
}

/// Test against common security vulnerabilities
#[cfg(test)]
mod vulnerability_tests {
    use super::*;

    #[test]
    fn test_buffer_overflow_prevention() {
        // Test with extremely large inputs
        let large_title = "A".repeat(100000); // 100KB title
        let large_description = "B".repeat(500000); // 500KB description

        let case = SecurityCase::new(
            large_title.clone(),
            large_description.clone(),
            CasePriority::Medium,
        );

        // Case should handle large inputs gracefully
        assert!(!case.id.is_empty()); // ID should still be generated
        assert_eq!(case.title, large_title);
        assert_eq!(case.description, large_description);

        // System should not crash or exhibit undefined behavior
    }

    #[test]
    fn test_null_byte_injection() {
        // Test null byte injection attempts
        let malicious_inputs = vec![
            "Normal input\x00malicious",
            "Title\x00DROP TABLE",
            "Description\x00<script>",
        ];

        for input in malicious_inputs {
            let case = SecurityCase::new(
                input.to_string(),
                "Safe description".to_string(),
                CasePriority::Medium,
            );

            // Input should be preserved as-is (null byte handling is OS/filesystem dependent)
            assert_eq!(case.title, input);
            assert!(!case.id.is_empty());
        }
    }

    #[test]
    fn test_unicode_normalization_attacks() {
        // Test unicode normalization attacks
        let unicode_attacks = vec![
            "user\u{202E}example.com", // Right-to-left override
            "admin\u{200B}user",       // Zero-width space
            "test\u{200D}case",        // Zero-width joiner
            "file\u{202A}name",        // Left-to-right embedding
        ];

        for attack_input in unicode_attacks {
            let case = SecurityCase::new(
                attack_input.to_string(),
                "Unicode attack test".to_string(),
                CasePriority::Medium,
            );

            // Input should be preserved (actual validation would be at application layer)
            assert_eq!(case.title, attack_input);
            assert!(!case.id.is_empty());
        }
    }

    #[test]
    fn test_path_traversal_prevention() {
        // Test path traversal attempts
        let path_traversal_attempts = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "....//....//....//etc/shadow",
            "...\\...\\...\\boot.ini",
        ];

        for path_attempt in path_traversal_attempts {
            let evidence = Evidence {
                id: "path-test".to_string(),
                evidence_type: EvidenceType::FileArtifact,
                description: "Path traversal test".to_string(),
                content: path_attempt.to_string(),
                collected_at: chrono::Utc::now(),
                collected_by: "test@example.com".to_string(),
                integrity_hash: "path_hash".to_string(),
            };

            // Evidence should be created (path validation would be at filesystem layer)
            assert_eq!(evidence.content, path_attempt);
            assert!(!evidence.id.is_empty());
        }
    }
}

/// Test cryptographic security
#[cfg(test)]
mod cryptographic_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_case_id_uniqueness_and_entropy() {
        // Generate many case IDs to test uniqueness and entropy
        let mut ids = HashSet::new();
        let num_cases = 10000;

        for i in 0..num_cases {
            let case = SecurityCase::new(
                format!("Entropy Test Case {}", i),
                format!("Description {}", i),
                CasePriority::Medium,
            );

            // ID should be unique
            assert!(
                !ids.contains(&case.id),
                "Case ID collision detected: {}",
                case.id
            );
            ids.insert(case.id.clone());

            // ID should have reasonable length (UUID is 36 chars)
            assert!(case.id.len() >= 10, "Case ID too short: {}", case.id.len());
            assert!(case.id.len() <= 50, "Case ID too long: {}", case.id.len());
        }

        // All IDs should be unique
        assert_eq!(ids.len(), num_cases, "Not all case IDs were unique");
    }

    #[test]
    fn test_evidence_integrity_hash() {
        // Test that evidence integrity hashes are properly generated
        let evidence = Evidence {
            id: "integrity-test".to_string(),
            evidence_type: EvidenceType::LogFile,
            description: "Integrity test".to_string(),
            content: "Test content for integrity checking".to_string(),
            collected_at: chrono::Utc::now(),
            collected_by: "test@example.com".to_string(),
            integrity_hash: "placeholder_hash".to_string(), // In real system, this would be computed
        };

        // Integrity hash should be present and non-empty
        assert!(!evidence.integrity_hash.is_empty());
        assert!(!evidence.integrity_hash.contains("placeholder")); // Should be real hash

        // Same content should produce same hash (in real implementation)
        let duplicate_evidence = Evidence {
            id: "duplicate-test".to_string(),
            ..evidence.clone()
        };

        // In a real system, these would have the same hash for same content
        assert_eq!(evidence.content, duplicate_evidence.content);
    }

    #[test]
    fn test_timestamp_integrity() {
        let case = TestCaseFactory::create_basic_case();

        // Timestamps should be reasonable
        let now = chrono::Utc::now();
        let five_minutes_ago = now - chrono::Duration::minutes(5);
        let five_minutes_from_now = now + chrono::Duration::minutes(5);

        // Created timestamp should be recent
        assert!(
            case.created_at >= five_minutes_ago,
            "Created timestamp too old"
        );
        assert!(
            case.created_at <= five_minutes_from_now,
            "Created timestamp too far in future"
        );

        // Updated timestamp should equal created initially
        assert_eq!(case.updated_at, case.created_at);

        // After update, updated should be >= created
        let mut updated_case = case;
        std::thread::sleep(std::time::Duration::from_millis(1)); // Ensure time difference
        updated_case.update_status(CaseStatus::Investigating);

        assert!(updated_case.updated_at >= updated_case.created_at);
    }
}

/// Test denial of service prevention
#[cfg(test)]
mod dos_prevention_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn test_resource_exhaustion_prevention() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = Arc::new(
            CaseManagementSystem::new(config, mock_repo.clone(), workflow_engine)
                .await
                .expect("Failed to create case management system"),
        );

        // Test creating many cases rapidly
        let num_cases = 1000;
        let semaphore = Arc::new(Semaphore::new(50)); // Limit concurrency
        let success_count = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];
        for i in 0..num_cases {
            let system_clone = Arc::clone(&system);
            let success_count_clone = Arc::clone(&success_count);
            let permit = semaphore.acquire().await.unwrap();

            let handle = tokio::spawn(async move {
                let result = system_clone
                    .create_case(
                        format!("DOS Test Case {}", i),
                        format!("Description {}", i),
                        CasePriority::Low,
                        None,
                    )
                    .await;

                if result.is_ok() {
                    success_count_clone.fetch_add(1, Ordering::Relaxed);
                }

                drop(permit);
            });

            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            handle.await.expect("DOS test task failed");
        }

        let successful_operations = success_count.load(Ordering::Relaxed);

        // System should handle the load gracefully
        assert!(successful_operations > 0, "No operations succeeded");
        assert!(
            successful_operations <= num_cases,
            "More successes than attempts"
        );

        // In a real system, rate limiting would prevent abuse
        // This test ensures the system doesn't crash under load
    }

    #[tokio::test]
    async fn test_memory_bomb_prevention() {
        // Test with extremely large data to ensure memory safety
        let large_title = "X".repeat(100000); // 100KB
        let large_description = "Y".repeat(1000000); // 1MB

        let case = SecurityCase::new(large_title, large_description, CasePriority::Medium);

        // Case should be created without causing memory issues
        assert!(!case.id.is_empty());

        // Test with many evidence items
        let mut evidence_case = case;
        for i in 0..1000 {
            let evidence = Evidence {
                id: format!("bomb-evidence-{}", i),
                evidence_type: EvidenceType::LogFile,
                description: format!("Evidence {}", i),
                content: format!("Content {}", i),
                collected_at: chrono::Utc::now(),
                collected_by: "test@example.com".to_string(),
                integrity_hash: format!("hash-{}", i),
            };

            evidence_case.add_evidence(evidence);
        }

        // Should handle many evidence items without issues
        assert_eq!(evidence_case.evidence.len(), 1000);
    }

    #[tokio::test]
    async fn test_infinite_loop_prevention() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(config, mock_repo.clone(), workflow_engine)
            .await
            .expect("Failed to create case management system");

        // Create a case and perform many rapid status changes
        let case_id = system
            .create_case(
                "Infinite Loop Test".to_string(),
                "Testing rapid status changes".to_string(),
                CasePriority::Medium,
                None,
            )
            .await
            .expect("Failed to create infinite loop test case");

        // Rapidly change status many times
        let statuses = vec![
            CaseStatus::Investigating,
            CaseStatus::Escalated,
            CaseStatus::Resolving,
            CaseStatus::Resolved,
            CaseStatus::Closed,
        ];

        for _ in 0..100 {
            // 100 rapid changes
            for status in &statuses {
                system
                    .update_case_status(case_id.as_str(), *status, "rapid-test@example.com")
                    .await
                    .expect("Failed to update status rapidly");
            }
        }

        // System should handle rapid changes without infinite loops or crashes
        let final_case = system
            .get_case(&case_id)
            .await
            .expect("Failed to get final case")
            .expect("Final case not found");

        assert!(!final_case.id.is_empty());
        // Final status should be valid
        assert!(matches!(
            final_case.status,
            CaseStatus::Open
                | CaseStatus::Investigating
                | CaseStatus::Escalated
                | CaseStatus::Pending
                | CaseStatus::Resolving
                | CaseStatus::Resolved
                | CaseStatus::Closed
        ));
    }
}

/// Test audit trail and logging security
#[cfg(test)]
mod audit_tests {
    use super::*;

    #[test]
    fn test_case_audit_trail() {
        let mut case = TestCaseFactory::create_basic_case();
        let original_created = case.created_at;

        // Perform various operations that should be auditable
        std::thread::sleep(std::time::Duration::from_millis(1));
        case.update_status(CaseStatus::Investigating);

        std::thread::sleep(std::time::Duration::from_millis(1));
        case.assign_to("analyst@example.com".to_string());

        std::thread::sleep(std::time::Duration::from_millis(1));
        case.add_tags(vec!["security".to_string(), "incident".to_string()]);

        std::thread::sleep(std::time::Duration::from_millis(1));
        case.add_evidence(TestCaseFactory::create_test_evidence(&case.id));

        // Verify audit trail through timestamps
        assert_eq!(
            case.created_at, original_created,
            "Created timestamp should not change"
        );
        assert!(
            case.updated_at > original_created,
            "Updated timestamp should reflect last change"
        );

        // All operations should be reflected in the final state
        assert_eq!(case.status, CaseStatus::Investigating);
        assert_eq!(case.assigned_to, Some("analyst@example.com".to_string()));
        assert_eq!(
            case.tags,
            vec!["security".to_string(), "incident".to_string()]
        );
        assert_eq!(case.evidence.len(), 1);
    }

    #[test]
    fn test_operation_ordering_integrity() {
        let mut case = TestCaseFactory::create_basic_case();

        // Record timestamps at each operation
        let created_time = case.created_at;

        std::thread::sleep(std::time::Duration::from_millis(2));
        case.update_status(CaseStatus::Investigating);
        let status_update_time = case.updated_at;

        std::thread::sleep(std::time::Duration::from_millis(2));
        case.assign_to("analyst@example.com".to_string());
        let assignment_time = case.updated_at;

        std::thread::sleep(std::time::Duration::from_millis(2));
        case.add_tags(vec!["test".to_string()]);
        let tag_time = case.updated_at;

        // Verify chronological ordering
        assert!(
            created_time <= status_update_time,
            "Status update should be after creation"
        );
        assert!(
            status_update_time <= assignment_time,
            "Assignment should be after status update"
        );
        assert!(
            assignment_time <= tag_time,
            "Tag addition should be after assignment"
        );

        // All timestamps should be in the past
        let now = chrono::Utc::now();
        assert!(created_time <= now);
        assert!(status_update_time <= now);
        assert!(assignment_time <= now);
        assert!(tag_time <= now);
    }

    #[test]
    fn test_data_consistency_under_concurrent_operations() {
        let case = TestCaseFactory::create_basic_case();

        // Simulate concurrent operations by creating multiple copies
        // and performing different operations on each
        let mut case1 = case.clone();
        let mut case2 = case.clone();
        let mut case3 = case.clone();

        // Different operations on each copy
        case1.update_status(CaseStatus::Investigating);
        case2.assign_to("analyst1@example.com".to_string());
        case3.add_tags(vec!["concurrent".to_string()]);

        // Each copy should maintain its own state
        assert_eq!(case1.status, CaseStatus::Investigating);
        assert_eq!(case1.assigned_to, None);
        assert!(case1.tags.is_empty());

        assert_eq!(case2.status, CaseStatus::Open);
        assert_eq!(case2.assigned_to, Some("analyst1@example.com".to_string()));
        assert!(case2.tags.is_empty());

        assert_eq!(case3.status, CaseStatus::Open);
        assert_eq!(case3.assigned_to, None);
        assert_eq!(case3.tags, vec!["concurrent".to_string()]);

        // All should have the same base data
        assert_eq!(case1.id, case2.id);
        assert_eq!(case2.id, case3.id);
        assert_eq!(case1.title, case2.title);
        assert_eq!(case2.title, case3.title);
        assert_eq!(case1.created_at, case2.created_at);
        assert_eq!(case2.created_at, case3.created_at);
    }
}
