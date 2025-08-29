//! Comprehensive Test Suite for SOAR Case Management
//!
//! This module provides comprehensive testing coverage for the SOAR case management system.
//!
//! ## Test Categories
//!
//! - **Unit Tests**: Test individual components in isolation
//! - **Integration Tests**: Test component interactions
//! - **Property-Based Tests**: Test with generated inputs
//! - **Error Handling Tests**: Test error scenarios and recovery
//! - **Performance Tests**: Test under load and stress conditions
//! - **Security Tests**: Test security-related functionality

pub mod error_handling_tests;
pub mod integration_tests;
pub mod performance_tests;
pub mod property_tests;
pub mod security_tests;
pub mod unit_tests;

// Re-export test utilities for easy access
pub use integration_tests::*;
pub use property_tests::*;
pub use unit_tests::*;

/// Test configuration and utilities
pub mod test_utils {
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use crate::modules::soar::case_management::{
        config::CaseManagementConfig,
        errors::{SoarError, SoarResult},
        handlers::{CaseManagementSystem, EvidenceManager, SlaTracker},
        models::{CasePriority, CaseStatus, Evidence, EvidenceType, SecurityCase},
        persistence::CaseRepository,
        workflows::CaseWorkflowEngine,
    };

    /// Test case factory for creating test data
    pub struct TestCaseFactory;

    impl TestCaseFactory {
        /// Create a basic security case for testing
        pub fn create_basic_case() -> SecurityCase {
            SecurityCase::new(
                "Test Security Incident".to_string(),
                "A test security incident for testing purposes".to_string(),
                CasePriority::Medium,
            )
        }

        /// Create a high-priority security case
        pub fn create_high_priority_case() -> SecurityCase {
            SecurityCase::new(
                "Critical Security Breach".to_string(),
                "A critical security breach requiring immediate attention".to_string(),
                CasePriority::Critical,
            )
        }

        /// Create a resolved case
        pub fn create_resolved_case() -> SecurityCase {
            let mut case = Self::create_basic_case();
            case.update_status(CaseStatus::Resolved);
            case
        }

        /// Create an escalated case
        pub fn create_escalated_case() -> SecurityCase {
            let mut case = Self::create_high_priority_case();
            case.update_status(CaseStatus::Escalated);
            case
        }

        /// Create test evidence
        pub fn create_test_evidence(case_id: &str) -> Evidence {
            Evidence {
                id: format!("evidence-{}-001", case_id),
                evidence_type: EvidenceType::LogFile,
                description: "Test log file evidence".to_string(),
                content: "/var/log/auth.log".to_string(),
                collected_at: Utc::now(),
                collected_by: "test_analyst".to_string(),
                integrity_hash: "test_hash_123".to_string(),
            }
        }

        /// Create multiple test cases
        pub fn create_test_cases(count: usize) -> Vec<SecurityCase> {
            (0..count)
                .map(|i| {
                    let mut case = SecurityCase::new(
                        format!("Test Case {}", i),
                        format!("Description for test case {}", i),
                        match i % 4 {
                            0 => CasePriority::Low,
                            1 => CasePriority::Medium,
                            2 => CasePriority::High,
                            3 => CasePriority::Critical,
                            _ => CasePriority::Medium,
                        },
                    );
                    case
                })
                .collect()
        }
    }

    /// Mock repository for testing
    pub struct MockCaseRepository {
        cases: Arc<RwLock<HashMap<String, SecurityCase>>>,
    }

    impl MockCaseRepository {
        /// Create a new mock repository
        pub fn new() -> Self {
            Self {
                cases: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        /// Add a case to the mock repository
        pub async fn add_case(&self, case: SecurityCase) {
            self.cases.write().await.insert(case.id.clone(), case);
        }

        /// Get a case from the mock repository
        pub async fn get_case(&self, case_id: &str) -> SoarResult<Option<SecurityCase>> {
            Ok(self.cases.read().await.get(case_id).cloned())
        }

        /// Clear all cases
        pub async fn clear(&self) {
            self.cases.write().await.clear();
        }
    }

    /// Test configuration factory
    pub struct TestConfigFactory;

    impl TestConfigFactory {
        /// Create a default test configuration
        pub fn default_config() -> CaseManagementConfig {
            CaseManagementConfig::default()
        }

        /// Create a configuration optimized for testing
        pub fn test_config() -> CaseManagementConfig {
            CaseManagementConfig {
                max_active_cases: 100,
                retention_days: 30,
                ..Default::default()
            }
        }
    }

    /// Test helpers for assertions
    pub mod assertions {
        use super::*;

        /// Assert that a case has the expected status
        pub fn assert_case_status(case: &SecurityCase, expected: CaseStatus) {
            assert_eq!(case.status, expected, "Case status mismatch");
        }

        /// Assert that a case has the expected priority
        pub fn assert_case_priority(case: &SecurityCase, expected: CasePriority) {
            assert_eq!(case.priority, expected, "Case priority mismatch");
        }

        /// Assert that a case has evidence
        pub fn assert_case_has_evidence(case: &SecurityCase, expected_count: usize) {
            assert_eq!(
                case.evidence.len(),
                expected_count,
                "Evidence count mismatch"
            );
        }

        /// Assert that a case is assigned to an analyst
        pub fn assert_case_assigned_to(case: &SecurityCase, expected_analyst: &str) {
            assert_eq!(
                case.assigned_to.as_deref(),
                Some(expected_analyst),
                "Case assignment mismatch"
            );
        }

        /// Assert that an error is of the expected type
        pub fn assert_error_type<T>(result: &SoarResult<T>, expected_error: &SoarError) {
            if let Err(actual_error) = result {
                assert_eq!(
                    std::mem::discriminant(actual_error),
                    std::mem::discriminant(expected_error),
                    "Error type mismatch"
                );
            } else {
                panic!("Expected error but got success");
            }
        }
    }
}

/// Performance testing utilities
pub mod performance_utils {
    use std::time::{Duration, Instant};

    /// Measure execution time of a function
    pub fn measure_execution_time<F, R>(f: F) -> (R, Duration)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let duration = start.elapsed();
        (result, duration)
    }

    /// Measure async execution time
    pub async fn measure_async_execution_time<F, Fut, R>(f: F) -> (R, Duration)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = R>,
    {
        let start = Instant::now();
        let result = f().await;
        let duration = start.elapsed();
        (result, duration)
    }

    /// Performance assertion helpers
    pub mod assertions {
        use super::*;
        use std::time::Duration;

        /// Assert that execution time is within acceptable limits
        pub fn assert_performance_within_limit(duration: Duration, limit_ms: u64) {
            let limit = Duration::from_millis(limit_ms);
            assert!(
                duration <= limit,
                "Performance violation: {}ms > {}ms limit",
                duration.as_millis(),
                limit_ms
            );
        }

        /// Assert that execution time is reasonable for the operation
        pub fn assert_reasonable_performance(duration: Duration, operation: &str) {
            let max_reasonable = match operation {
                "create_case" => 100,  // 100ms
                "get_case" => 50,      // 50ms
                "update_case" => 75,   // 75ms
                "search_cases" => 200, // 200ms
                _ => 500,              // 500ms default
            };

            assert_performance_within_limit(duration, max_reasonable);
        }
    }
}

/// Security testing utilities
pub mod security_utils {
    use super::*;

    /// Security test helpers
    pub mod assertions {
        use super::*;

        /// Assert that sensitive data is not leaked in error messages
        pub fn assert_no_sensitive_data_leak(error: &SoarError, sensitive_patterns: &[&str]) {
            let error_msg = format!("{}", error);
            for pattern in sensitive_patterns {
                assert!(
                    !error_msg.contains(pattern),
                    "Sensitive data leaked in error message: {}",
                    pattern
                );
            }
        }

        /// Assert that error messages are sanitized
        pub fn assert_error_message_sanitized(error: &SoarError) {
            let sensitive_patterns = [
                "password",
                "secret",
                "token",
                "key",
                "credential",
                "private",
            ];

            assert_no_sensitive_data_leak(error, &sensitive_patterns);
        }

        /// Assert that case data is properly validated
        pub fn assert_case_data_validation(case: &SecurityCase) {
            assert!(!case.title.is_empty(), "Case title should not be empty");
            assert!(
                !case.description.is_empty(),
                "Case description should not be empty"
            );
            assert!(!case.id.is_empty(), "Case ID should not be empty");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_factory() {
        let case = test_utils::TestCaseFactory::create_basic_case();
        assert_eq!(case.priority, CasePriority::Medium);
        assert_eq!(case.status, CaseStatus::Open);
    }

    #[test]
    fn test_high_priority_case() {
        let case = test_utils::TestCaseFactory::create_high_priority_case();
        assert_eq!(case.priority, CasePriority::Critical);
        assert!(case.title.contains("Critical"));
    }

    #[test]
    fn test_resolved_case() {
        let case = test_utils::TestCaseFactory::create_resolved_case();
        assert_eq!(case.status, CaseStatus::Resolved);
    }

    #[test]
    fn test_escalated_case() {
        let case = test_utils::TestCaseFactory::create_escalated_case();
        assert_eq!(case.status, CaseStatus::Escalated);
        assert_eq!(case.priority, CasePriority::Critical);
    }

    #[test]
    fn test_multiple_cases_creation() {
        let cases = test_utils::TestCaseFactory::create_test_cases(5);
        assert_eq!(cases.len(), 5);
        assert!(cases.iter().all(|c| !c.id.is_empty()));
    }
}
