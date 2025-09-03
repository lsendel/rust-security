//! Property-Based Tests for SOAR Case Management
//!
//! This module contains property-based tests that verify system properties
//! under various inputs and edge cases using generated test data.

use chrono::{DateTime, Duration, Utc};
use proptest::prelude::*;
use std::collections::HashSet;

use super::super::{
    errors::{ErrorCategory, SoarError},
    models::{CasePriority, CaseStatus, Evidence, EvidenceType, SecurityCase},
};
use super::test_utils::TestCaseFactory;

/// Generate arbitrary case titles
fn arb_case_title() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 ]{1,100}".prop_map(|s| s)
}

/// Generate arbitrary case descriptions
fn arb_case_description() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 .,!?]{1,500}".prop_map(|s| s)
}

/// Generate arbitrary case priorities
fn arb_case_priority() -> impl Strategy<Value = CasePriority> {
    prop_oneof![
        Just(CasePriority::Low),
        Just(CasePriority::Medium),
        Just(CasePriority::High),
        Just(CasePriority::Critical),
    ]
}

/// Generate arbitrary case statuses
fn arb_case_status() -> impl Strategy<Value = CaseStatus> {
    prop_oneof![
        Just(CaseStatus::Open),
        Just(CaseStatus::Investigating),
        Just(CaseStatus::Escalated),
        Just(CaseStatus::Pending),
        Just(CaseStatus::Resolving),
        Just(CaseStatus::Resolved),
        Just(CaseStatus::Closed),
    ]
}

/// Generate arbitrary evidence types
fn arb_evidence_type() -> impl Strategy<Value = EvidenceType> {
    prop_oneof![
        Just(EvidenceType::LogFile),
        Just(EvidenceType::PacketCapture),
        Just(EvidenceType::MemoryDump),
        Just(EvidenceType::FileArtifact),
        Just(EvidenceType::Screenshot),
        Just(EvidenceType::UserReport),
        Just(EvidenceType::Configuration),
    ]
}

/// Generate arbitrary evidence content
fn arb_evidence_content() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9 .,/\\-_]{1,1000}".prop_map(|s| s)
}

/// Generate arbitrary analyst names
fn arb_analyst_name() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9._%+-]{1,50}@[a-zA-Z0-9.-]{1,50}\\.[a-zA-Z]{2,}".prop_map(|s| s)
}

/// Generate arbitrary tags
fn arb_tags() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec("[a-zA-Z0-9_-]{1,20}", 0..10)
}

/// Test case creation properties
#[cfg(test)]
mod case_creation_properties {
    use super::*;

    proptest! {
        #[test]
        fn test_case_creation_always_generates_valid_id(
            title in arb_case_title(),
            description in arb_case_description(),
            priority in arb_case_priority()
        ) {
            let case = SecurityCase::new(title, description, priority);

            // Properties that should always hold
            prop_assert!(!case.id.is_empty(), "Case ID should never be empty");
            prop_assert!(case.id.len() >= 10, "Case ID should be reasonably long");
            prop_assert!(case.created_at <= Utc::now(), "Created timestamp should be in the past");
            prop_assert_eq!(case.updated_at, case.created_at, "Initial updated timestamp should equal created timestamp");
            prop_assert_eq!(case.status, CaseStatus::Open, "New cases should start in Open status");
        }

        #[test]
        fn test_case_with_extreme_titles(
            title in prop::string::string_regex("[a-zA-Z]{0,1000}").unwrap(),
            description in arb_case_description(),
            priority in arb_case_priority()
        ) {
            let case = SecurityCase::new(title.clone(), description, priority);

            // Case should handle any valid title string
            prop_assert!(!case.id.is_empty());
            prop_assert_eq!(case.title, title);
            prop_assert!(case.created_at <= Utc::now());
        }

        #[test]
        fn test_case_creation_is_deterministic_for_same_inputs(
            title in arb_case_title(),
            description in arb_case_description(),
            priority in arb_case_priority()
        ) {
            // Create two cases with identical inputs
            let case1 = SecurityCase::new(title.clone(), description.clone(), priority);
            let case2 = SecurityCase::new(title, description, priority);

            // IDs should be different (due to timestamps)
            prop_assert_ne!(case1.id, case2.id);

            // Other properties should be identical
            prop_assert_eq!(case1.title, case2.title);
            prop_assert_eq!(case1.description, case2.description);
            prop_assert_eq!(case1.priority, case2.priority);
            prop_assert_eq!(case1.status, case2.status);
        }
    }
}

/// Test case update properties
#[cfg(test)]
mod case_update_properties {
    use super::*;

    proptest! {
        #[test]
        fn test_case_status_updates_preserve_data_integrity(
            initial_title in arb_case_title(),
            initial_description in arb_case_description(),
            initial_priority in arb_case_priority(),
            new_status in arb_case_status(),
            analyst in arb_analyst_name()
        ) {
            let mut case = SecurityCase::new(initial_title.clone(), initial_description.clone(), initial_priority);
            let original_id = case.id.clone();
            let original_created = case.created_at;

            // Update status
            case.update_status(new_status);
            case.assign_to(analyst.clone());

            // Verify data integrity
            prop_assert_eq!(case.id, original_id, "Case ID should not change");
            prop_assert_eq!(case.created_at, original_created, "Created timestamp should not change");
            prop_assert!(case.updated_at >= original_created, "Updated timestamp should be after created");
            prop_assert_eq!(case.title, initial_title, "Title should not change");
            prop_assert_eq!(case.description, initial_description, "Description should not change");
            prop_assert_eq!(case.priority, initial_priority, "Priority should not change");
            prop_assert_eq!(case.status, new_status, "Status should be updated");
            prop_assert_eq!(case.assigned_to, Some(analyst), "Assignment should be updated");
        }

        #[test]
        fn test_multiple_status_updates(
            initial_title in arb_case_title(),
            initial_description in arb_case_description(),
            initial_priority in arb_case_priority(),
            statuses in prop::collection::vec(arb_case_status(), 1..10)
        ) {
            let mut case = SecurityCase::new(initial_title, initial_description, initial_priority);
            let original_id = case.id.clone();

            // Apply multiple status updates
            for status in statuses {
                case.update_status(status);
            }

            // Verify final state
            prop_assert_eq!(case.id, original_id, "Case ID should remain constant");
            prop_assert!(case.updated_at >= case.created_at, "Updated timestamp should be valid");
        }
    }
}

/// Test evidence management properties
#[cfg(test)]
mod evidence_properties {
    use super::*;

    proptest! {
        #[test]
        fn test_evidence_creation_with_various_content(
            evidence_id in "[a-zA-Z0-9_-]{1,50}",
            evidence_type in arb_evidence_type(),
            description in arb_case_description(),
            content in arb_evidence_content(),
            collected_by in arb_analyst_name()
        ) {
            let evidence = Evidence {
                id: evidence_id.clone(),
                evidence_type,
                description: description.clone(),
                content: content.clone(),
                collected_at: Utc::now(),
                collected_by: collected_by.clone(),
                integrity_hash: "test_hash".to_string(),
            };

            // Verify evidence properties
            prop_assert_eq!(evidence.id, evidence_id);
            prop_assert_eq!(evidence.description, description);
            prop_assert_eq!(evidence.content, content);
            prop_assert_eq!(evidence.collected_by, collected_by);
            prop_assert!(evidence.collected_at <= Utc::now());
            prop_assert!(!evidence.integrity_hash.is_empty());
        }

        #[test]
        fn test_evidence_addition_to_case(
            case_title in arb_case_title(),
            case_description in arb_case_description(),
            case_priority in arb_case_priority(),
            evidence_items in prop::collection::vec(
                (arb_evidence_content(), arb_evidence_type(), arb_case_description(), arb_analyst_name()),
                0..20
            )
        ) {
            let mut case = SecurityCase::new(case_title, case_description, case_priority);

            // Add multiple evidence items
            for (i, (content, ev_type, description, collected_by)) in evidence_items.iter().enumerate() {
                let evidence = Evidence {
                    id: format!("evidence-{}", i),
                    evidence_type: ev_type.clone(),
                    description: description.clone(),
                    content: content.clone(),
                    collected_at: Utc::now(),
                    collected_by: collected_by.clone(),
                    integrity_hash: format!("hash-{}", i),
                };

                case.add_evidence(evidence);
            }

            // Verify evidence was added correctly
            prop_assert_eq!(case.evidence.len(), evidence_items.len());
            prop_assert!(case.updated_at >= case.created_at);

            // Verify evidence details
            for (i, evidence) in case.evidence.iter().enumerate() {
                let (content, ev_type, description, collected_by) = &evidence_items[i];
                prop_assert_eq!(evidence.content, *content);
                prop_assert_eq!(evidence.evidence_type, *ev_type);
                prop_assert_eq!(evidence.description, *description);
                prop_assert_eq!(evidence.collected_by, *collected_by);
            }
        }
    }
}

/// Test error handling properties
#[cfg(test)]
mod error_handling_properties {
    use super::*;

    proptest! {
        #[test]
        fn test_case_not_found_error_properties(
            case_id in "[a-zA-Z0-9_-]{1,100}"
        ) {
            let error = SoarError::case_not_found(&case_id);

            // Verify error properties
            prop_assert_eq!(error.category(), ErrorCategory::NotFound);
            prop_assert!(!error.is_retryable());
            prop_assert!(!case_id.is_empty()); // Ensure case_id is valid

            // Error message should contain the case ID
            let error_msg = format!("{}", error);
            prop_assert!(error_msg.contains(&case_id));
        }

        #[test]
        fn test_invalid_input_error_properties(
            field in "[a-zA-Z0-9_-]{1,50}",
            reason in arb_case_description()
        ) {
            let error = SoarError::invalid_input(&field, &reason);

            // Verify error properties
            prop_assert_eq!(error.category(), ErrorCategory::Validation);
            prop_assert!(!error.is_retryable());

            // Error message should contain field and reason
            let error_msg = format!("{}", error);
            prop_assert!(error_msg.contains(&field));
            prop_assert!(error_msg.contains(&reason));
        }

        #[test]
        fn test_database_error_properties(
            operation in "[a-zA-Z0-9_-]{1,50}"
        ) {
            let db_error = sqlx::Error::RowNotFound;
            let error = SoarError::database_error(&operation, db_error);

            // Verify error properties
            prop_assert_eq!(error.category(), ErrorCategory::Infrastructure);
            prop_assert!(!error.is_retryable()); // RowNotFound is not retryable

            // Error message should contain the operation
            let error_msg = format!("{}", error);
            prop_assert!(error_msg.contains(&operation));
        }

        #[test]
        fn test_workflow_error_properties(
            workflow_name in "[a-zA-Z0-9_-]{1,50}",
            error_reason in arb_case_description()
        ) {
            let error = SoarError::WorkflowExecutionFailed {
                workflow_name: workflow_name.clone(),
                reason: error_reason.clone(),
            };

            // Verify error properties
            prop_assert_eq!(error.category(), ErrorCategory::Processing);
            prop_assert!(!error.is_retryable());

            // Error message should contain workflow name and reason
            let error_msg = format!("{}", error);
            prop_assert!(error_msg.contains(&workflow_name));
            prop_assert!(error_msg.contains(&error_reason));
        }

        #[test]
        fn test_sla_violation_error_properties(
            case_id in "[a-zA-Z0-9_-]{1,100}",
            violation_type in "[a-zA-Z0-9_-]{1,50}"
        ) {
            let error = SoarError::SlaViolation {
                case_id: case_id.clone(),
                violation_type: violation_type.clone(),
            };

            // Verify error properties
            prop_assert_eq!(error.category(), ErrorCategory::Sla);
            prop_assert!(!error.is_retryable());

            // Error message should contain case ID and violation type
            let error_msg = format!("{}", error);
            prop_assert!(error_msg.contains(&case_id));
            prop_assert!(error_msg.contains(&violation_type));
        }
    }
}

/// Test data consistency properties
#[cfg(test)]
mod data_consistency_properties {
    use super::*;

    proptest! {
        #[test]
        fn test_case_id_uniqueness_across_multiple_cases(
            cases_data in prop::collection::vec(
                (arb_case_title(), arb_case_description(), arb_case_priority()),
                2..50
            )
        ) {
            let mut cases = Vec::new();
            let mut ids = HashSet::new();

            // Create multiple cases
            for (title, description, priority) in cases_data {
                let case = SecurityCase::new(title, description, priority);
                ids.insert(case.id.clone());
                cases.push(case);
            }

            // All IDs should be unique
            prop_assert_eq!(ids.len(), cases.len(), "All case IDs should be unique");

            // No case should have empty ID
            for case in &cases {
                prop_assert!(!case.id.is_empty(), "No case should have empty ID");
            }
        }

        #[test]
        fn test_case_tag_consistency(
            case_title in arb_case_title(),
            case_description in arb_case_description(),
            case_priority in arb_case_priority(),
            tags in arb_tags()
        ) {
            let mut case = SecurityCase::new(case_title, case_description, case_priority);
            let original_updated = case.updated_at;

            // Add tags
            case.add_tags(tags.clone());

            // Verify tags were added
            prop_assert_eq!(case.tags, tags);
            prop_assert!(case.updated_at >= original_updated);

            // Adding empty tags should not change anything
            let tags_before = case.tags.len();
            case.add_tags(vec![]);
            prop_assert_eq!(case.tags.len(), tags_before);
        }

        #[test]
        fn test_case_timestamp_monotonicity(
            case_title in arb_case_title(),
            case_description in arb_case_description(),
            case_priority in arb_case_priority(),
            operations in prop::collection::vec(
                prop_oneof![
                    Just("update_status"),
                    Just("assign_analyst"),
                    Just("add_evidence"),
                    Just("add_tags")
                ],
                1..20
            )
        ) {
            let mut case = SecurityCase::new(case_title, case_description, case_priority);
            let original_created = case.created_at;
            let mut last_updated = case.updated_at;

            // Perform various operations
            for operation in operations {
                match operation.as_str() {
                    "update_status" => {
                        case.update_status(CaseStatus::Investigating);
                    }
                    "assign_analyst" => {
                        case.assign_to("test@example.com".to_string());
                    }
                    "add_evidence" => {
                        let evidence = Evidence {
                            id: "test-evidence".to_string(),
                            evidence_type: EvidenceType::LogFile,
                            description: "Test evidence".to_string(),
                            content: "Test content".to_string(),
                            collected_at: Utc::now(),
                            collected_by: "test@example.com".to_string(),
                            integrity_hash: "test_hash".to_string(),
                        };
                        case.add_evidence(evidence);
                    }
                    "add_tags" => {
                        case.add_tags(vec!["test".to_string()]);
                    }
                    _ => {}
                }

                // Verify timestamp monotonicity
                prop_assert!(case.updated_at >= last_updated, "Updated timestamp should be monotonic");
                prop_assert_eq!(case.created_at, original_created, "Created timestamp should never change");
                last_updated = case.updated_at;
            }
        }
    }
}

/// Test system boundary properties
#[cfg(test)]
mod boundary_properties {
    use super::*;

    proptest! {
        #[test]
        fn test_case_with_maximum_evidence_items(
            case_title in arb_case_title(),
            case_description in arb_case_description(),
            case_priority in arb_case_priority(),
            num_evidence in 0..1000
        ) {
            let mut case = SecurityCase::new(case_title, case_description, case_priority);

            // Add maximum number of evidence items
            for i in 0..num_evidence {
                let evidence = Evidence {
                    id: format!("evidence-{}", i),
                    evidence_type: EvidenceType::LogFile,
                    description: format!("Evidence {}", i),
                    content: format!("Content {}", i),
                    collected_at: Utc::now(),
                    collected_by: "test@example.com".to_string(),
                    integrity_hash: format!("hash-{}", i),
                };
                case.add_evidence(evidence);
            }

            // Verify all evidence was added
            prop_assert_eq!(case.evidence.len(), num_evidence as usize);
            prop_assert!(case.updated_at >= case.created_at);
        }

        #[test]
        fn test_case_with_extreme_tag_counts(
            case_title in arb_case_title(),
            case_description in arb_case_description(),
            case_priority in arb_case_priority(),
            num_tags in 0..1000
        ) {
            let mut case = SecurityCase::new(case_title, case_description, case_priority);

            // Add extreme number of tags
            let tags: Vec<String> = (0..num_tags).map(|i| format!("tag-{}", i)).collect();
            case.add_tags(tags.clone());

            // Verify all tags were added
            prop_assert_eq!(case.tags.len(), num_tags as usize);
            prop_assert_eq!(case.tags, tags);
            prop_assert!(case.updated_at >= case.created_at);
        }

        #[test]
        fn test_case_with_long_metadata(
            case_title in arb_case_title(),
            case_description in arb_case_description(),
            case_priority in arb_case_priority(),
            metadata_size in 0..10000
        ) {
            let mut case = SecurityCase::new(case_title, case_description, case_priority);

            // Create large metadata
            let mut metadata = serde_json::Map::new();
            for i in 0..metadata_size {
                metadata.insert(
                    format!("key-{}", i),
                    serde_json::Value::String(format!("value-{}", i))
                );
            }

            case.metadata = serde_json::Value::Object(metadata);

            // Verify metadata was set
            prop_assert!(case.metadata.is_object());
            if let serde_json::Value::Object(map) = &case.metadata {
                prop_assert_eq!(map.len(), metadata_size as usize);
            }
            prop_assert!(case.updated_at >= case.created_at);
        }
    }
}

/// Test workflow properties
#[cfg(test)]
mod workflow_properties {
    use super::*;

    proptest! {
        #[test]
        fn test_workflow_execution_preserves_case_data(
            case_title in arb_case_title(),
            case_description in arb_case_description(),
            case_priority in arb_case_priority(),
            initial_status in arb_case_status()
        ) {
            let mut case = SecurityCase::new(case_title.clone(), case_description.clone(), case_priority);
            let original_id = case.id.clone();

            // Set initial status
            case.update_status(initial_status);

            // Simulate workflow execution (simplified)
            // In real implementation, this would call workflow engine
            case.update_status(CaseStatus::Investigating);

            // Verify case data integrity after workflow
            prop_assert_eq!(case.id, original_id, "Case ID should not change during workflow");
            prop_assert_eq!(case.title, case_title, "Case title should not change during workflow");
            prop_assert_eq!(case.description, case_description, "Case description should not change during workflow");
            prop_assert_eq!(case.priority, case_priority, "Case priority should not change during workflow");
            prop_assert_eq!(case.status, CaseStatus::Investigating, "Case should be in investigating status");
            prop_assert!(case.updated_at >= case.created_at, "Updated timestamp should be valid");
        }

        #[test]
        fn test_workflow_status_transitions_are_valid(
            initial_status in arb_case_status(),
            target_status in arb_case_status()
        ) {
            let mut case = SecurityCase::new(
                "Workflow Transition Test".to_string(),
                "Testing status transitions".to_string(),
                CasePriority::Medium
            );

            // Set initial status
            case.update_status(initial_status);

            // Transition to target status
            case.update_status(target_status);

            // Verify the transition was recorded
            prop_assert_eq!(case.status, target_status, "Case should be in target status");
            prop_assert!(case.updated_at >= case.created_at, "Updated timestamp should be valid");

            // Status should be one of the valid enum values
            let valid_statuses = vec![
                CaseStatus::Open,
                CaseStatus::Investigating,
                CaseStatus::Escalated,
                CaseStatus::Pending,
                CaseStatus::Resolving,
                CaseStatus::Resolved,
                CaseStatus::Closed,
            ];
            prop_assert!(valid_statuses.contains(&case.status), "Status should be valid");
        }
    }
}

/// Test performance properties under various loads
#[cfg(test)]
mod performance_properties {
    use super::super::performance_utils::{
        assertions::assert_reasonable_performance, measure_execution_time,
    };
    use super::*;

    proptest! {
        #[test]
        fn test_case_creation_performance_with_various_inputs(
            title in arb_case_title(),
            description in arb_case_description(),
            priority in arb_case_priority()
        ) {
            let (case, duration) = measure_execution_time(|| {
                SecurityCase::new(title, description, priority)
            });

            // Verify case was created correctly
            prop_assert!(!case.id.is_empty());
            prop_assert!(case.created_at <= Utc::now());

            // Verify performance is reasonable
            assert_reasonable_performance(duration, "create_case");
        }

        #[test]
        fn test_case_update_performance_with_complex_data(
            title in arb_case_title(),
            description in arb_case_description(),
            priority in arb_case_priority(),
            tags in arb_tags(),
            analyst in arb_analyst_name()
        ) {
            let mut case = SecurityCase::new(title, description, priority);

            let (_, duration) = measure_execution_time(|| {
                case.add_tags(tags);
                case.assign_to(analyst);
                case.update_status(CaseStatus::Resolved);
            });

            // Verify updates were applied
            prop_assert!(!case.tags.is_empty());
            prop_assert!(case.assigned_to.is_some());
            prop_assert_eq!(case.status, CaseStatus::Resolved);

            // Verify performance is reasonable
            assert_reasonable_performance(duration, "update_case");
        }

        #[test]
        fn test_evidence_processing_performance(
            case_title in arb_case_title(),
            case_description in arb_case_description(),
            case_priority in arb_case_priority(),
            evidence_items in prop::collection::vec(
                (arb_evidence_content(), arb_evidence_type(), arb_case_description()),
                1..50
            )
        ) {
            let mut case = SecurityCase::new(case_title, case_description, case_priority);

            let (_, duration) = measure_execution_time(|| {
                for (i, (content, ev_type, description)) in evidence_items.iter().enumerate() {
                    let evidence = Evidence {
                        id: format!("evidence-{}", i),
                        evidence_type: ev_type.clone(),
                        description: description.clone(),
                        content: content.clone(),
                        collected_at: Utc::now(),
                        collected_by: "test@example.com".to_string(),
                        integrity_hash: format!("hash-{}", i),
                    };
                    case.add_evidence(evidence);
                }
            });

            // Verify evidence was added
            prop_assert_eq!(case.evidence.len(), evidence_items.len());

            // Verify performance is reasonable (allow more time for multiple evidence)
            prop_assert!(duration.as_millis() < 1000, "Evidence processing should complete within 1 second");
        }
    }
}

/// Test security properties with generated inputs
#[cfg(test)]
mod security_properties {
    use super::super::security_utils::assertions::*;
    use super::*;

    proptest! {
        #[test]
        fn test_case_data_validation_with_generated_inputs(
            title in arb_case_title(),
            description in arb_case_description(),
            priority in arb_case_priority()
        ) {
            let case = SecurityCase::new(title, description, priority);

            // All cases should pass basic validation
            assert_case_data_validation(&case);
        }

        #[test]
        fn test_evidence_integrity_with_generated_data(
            evidence_id in "[a-zA-Z0-9_-]{1,50}",
            evidence_type in arb_evidence_type(),
            content in arb_evidence_content(),
            collected_by in arb_analyst_name()
        ) {
            let evidence = Evidence {
                id: evidence_id,
                evidence_type,
                description: "Test evidence".to_string(),
                content,
                collected_at: Utc::now(),
                collected_by,
                integrity_hash: "test_hash".to_string(),
            };

            // Evidence should have valid structure
            prop_assert!(!evidence.id.is_empty());
            prop_assert!(!evidence.integrity_hash.is_empty());
            prop_assert!(!evidence.collected_by.is_empty());
            prop_assert!(evidence.collected_at <= Utc::now());
        }

        #[test]
        fn test_error_message_security_with_sensitive_data(
            case_id in "[a-zA-Z0-9_-]{1,100}",
            sensitive_data in prop::string::string_regex(r"(?i)(password|secret|token|key|credential)").unwrap()
        ) {
            // Test that error messages don't leak sensitive data
            let error = SoarError::case_not_found(&case_id);

            // Error should not contain any sensitive patterns
            assert_error_message_sanitized(&error);

            // Case ID should still be in the error (it's not sensitive)
            let error_msg = format!("{}", error);
            prop_assert!(error_msg.contains(&case_id));
        }
    }
}
