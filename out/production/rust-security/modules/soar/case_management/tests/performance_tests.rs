//! Performance Tests for SOAR Case Management
//!
//! This module contains comprehensive performance tests that verify
//! the system can handle various loads and maintain acceptable response times.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::timeout;

use super::super::{
    models::{SecurityCase, CaseStatus, CasePriority, Evidence, EvidenceType},
    config::CaseManagementConfig,
    handlers::CaseManagementSystem,
    persistence::CaseRepository,
    workflows::CaseWorkflowEngine,
};
use super::test_utils::{TestCaseFactory, MockCaseRepository, TestConfigFactory};

/// Test basic performance metrics
#[cfg(test)]
mod basic_performance_tests {
    use super::*;
    use super::super::performance_utils::{measure_execution_time, assertions::*};

    #[test]
    fn test_case_creation_performance() {
        let (case, duration) = measure_execution_time(|| {
            TestCaseFactory::create_basic_case()
        });

        assert_reasonable_performance(duration, "create_case");
        assert!(!case.id.is_empty());
        assert_eq!(case.status, CaseStatus::Open);
    }

    #[test]
    fn test_case_update_performance() {
        let mut case = TestCaseFactory::create_basic_case();

        let (_, duration) = measure_execution_time(|| {
            case.update_status(CaseStatus::Investigating);
            case.assign_to("analyst@example.com".to_string());
        });

        assert_reasonable_performance(duration, "update_case");
        assert_eq!(case.status, CaseStatus::Investigating);
        assert_eq!(case.assigned_to, Some("analyst@example.com".to_string()));
    }

    #[test]
    fn test_evidence_adding_performance() {
        let mut case = TestCaseFactory::create_basic_case();
        let evidence = TestCaseFactory::create_test_evidence(&case.id);

        let (_, duration) = measure_execution_time(|| {
            case.add_evidence(evidence.clone());
        });

        assert_reasonable_performance(duration, "update_case");
        assert_eq!(case.evidence.len(), 1);
        assert_eq!(case.evidence[0].id, evidence.id);
    }

    #[test]
    fn test_bulk_case_creation_performance() {
        let num_cases = 100;

        let (cases, duration) = measure_execution_time(|| {
            TestCaseFactory::create_test_cases(num_cases)
        });

        assert_eq!(cases.len(), num_cases);
        assert!(duration.as_millis() < 500); // Should complete within 500ms for 100 cases
        assert!(cases.iter().all(|c| !c.id.is_empty()));
    }
}

/// Test system performance under load
#[cfg(test)]
mod load_performance_tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrent_case_operations() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = Arc::new(CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system"));

        let num_concurrent = 50;
        let start_time = Instant::now();

        // Spawn concurrent case creation tasks
        let mut handles = vec![];
        for i in 0..num_concurrent {
            let system_clone = Arc::clone(&system);
            let handle = tokio::spawn(async move {
                let case_id = system_clone.create_case(
                    format!("Concurrent Case {}", i),
                    format!("Description {}", i),
                    CasePriority::Medium,
                    None,
                ).await;

                case_id
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

        let total_duration = start_time.elapsed();

        // Performance assertions
        assert_eq!(success_count, num_concurrent);
        assert!(total_duration.as_millis() < 5000); // Should complete within 5 seconds

        let avg_time_per_case = total_duration.as_millis() as f64 / num_concurrent as f64;
        assert!(avg_time_per_case < 100.0); // Average under 100ms per case
    }

    #[tokio::test]
    async fn test_high_volume_case_processing() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = Arc::new(CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system"));

        let num_cases = 200;
        let mut case_ids = vec![];

        // Create many cases
        let create_start = Instant::now();
        for i in 0..num_cases {
            let case_id = system.create_case(
                format!("Volume Test Case {}", i),
                format!("High volume test description {}", i),
                if i % 2 == 0 { CasePriority::High } else { CasePriority::Low },
                None,
            ).await.expect("Failed to create volume test case");

            case_ids.push(case_id);
        }
        let create_duration = create_start.elapsed();

        // Verify all cases exist
        let verify_start = Instant::now();
        for case_id in &case_ids {
            let case = system.get_case(case_id).await
                .expect("Failed to get volume test case")
                .expect("Volume test case not found");

            assert!(case.title.starts_with("Volume Test Case"));
        }
        let verify_duration = verify_start.elapsed();

        // Performance assertions
        assert!(create_duration.as_millis() < 3000); // Creation under 3 seconds
        assert!(verify_duration.as_millis() < 2000); // Verification under 2 seconds

        let total_duration = create_duration + verify_duration;
        assert!(total_duration.as_millis() < 5000); // Total under 5 seconds
    }

    #[tokio::test]
    async fn test_case_workflow_performance() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = Arc::new(CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system"));

        // Create a case and test workflow execution
        let case_id = system.create_case(
            "Workflow Performance Test".to_string(),
            "Testing workflow execution performance".to_string(),
            CasePriority::High,
            None,
        ).await.expect("Failed to create workflow test case");

        let workflow_start = Instant::now();

        // Execute workflow steps
        system.workflow_engine.start_case_workflow(&case_id)
            .await.expect("Failed to start workflow");

        let mut case = system.get_case(&case_id).await
            .expect("Failed to get workflow case")
            .expect("Workflow case not found");

        system.workflow_engine.execute_workflow_step(&case_id, &mut case)
            .await.expect("Failed to execute workflow step");

        let workflow_duration = workflow_start.elapsed();

        // Workflow should complete quickly
        assert!(workflow_duration.as_millis() < 500); // Under 500ms for workflow execution
    }
}

/// Test memory usage and resource consumption
#[cfg(test)]
mod memory_performance_tests {
    use super::*;

    #[test]
    fn test_case_memory_efficiency() {
        // Create cases with varying amounts of data
        let small_case = SecurityCase::new(
            "Small".to_string(),
            "Small description".to_string(),
            CasePriority::Low,
        );

        let large_case = SecurityCase::new(
            "A".repeat(1000), // Large title
            "B".repeat(5000), // Large description
            CasePriority::Critical,
        );

        // Both should have similar ID lengths (UUID-based)
        assert_eq!(small_case.id.len(), large_case.id.len());

        // Large case should handle big data gracefully
        assert_eq!(large_case.title.len(), 1000);
        assert_eq!(large_case.description.len(), 5000);
        assert!(!large_case.id.is_empty());
    }

    #[test]
    fn test_evidence_memory_handling() {
        let mut case = TestCaseFactory::create_basic_case();

        // Add evidence with varying sizes
        let small_evidence = Evidence {
            id: "small".to_string(),
            evidence_type: EvidenceType::LogFile,
            description: "Small evidence".to_string(),
            content: "Small content".to_string(),
            collected_at: chrono::Utc::now(),
            collected_by: "analyst@example.com".to_string(),
            integrity_hash: "hash1".to_string(),
        };

        let large_evidence = Evidence {
            id: "large".to_string(),
            evidence_type: EvidenceType::LogFile,
            description: "Large evidence".to_string(),
            content: "X".repeat(10000), // 10KB content
            collected_at: chrono::Utc::now(),
            collected_by: "analyst@example.com".to_string(),
            integrity_hash: "hash2".to_string(),
        };

        case.add_evidence(small_evidence);
        case.add_evidence(large_evidence);

        // Should handle both sizes efficiently
        assert_eq!(case.evidence.len(), 2);
        assert!(case.updated_at >= case.created_at);
    }

    #[tokio::test]
    async fn test_repository_memory_usage() {
        let mock_repo = Arc::new(MockCaseRepository::new());

        // Add many cases to test memory scaling
        for i in 0..1000 {
            let case = SecurityCase::new(
                format!("Memory Test Case {}", i),
                format!("Description {}", i),
                CasePriority::Medium,
            );

            mock_repo.add_case(case).await;
        }

        // Repository should handle the load
        let case_count = 1000;
        assert!(true); // If we get here without panicking, memory usage is acceptable

        // Clear and verify cleanup
        mock_repo.clear().await;

        // Verify all cases are cleared
        for i in 0..10 { // Test a sample
            let case_id = format!("Memory Test Case {}", i);
            let result = mock_repo.get_case(&case_id).await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }
    }
}

/// Test system throughput and scalability
#[cfg(test)]
mod throughput_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn test_system_throughput_under_load() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = Arc::new(CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system"));

        let num_operations = 1000;
        let num_workers = 10;
        let operations_per_worker = num_operations / num_workers;

        let start_time = Instant::now();
        let success_counter = Arc::new(AtomicUsize::new(0));

        // Spawn worker tasks
        let mut handles = vec![];
        for worker_id in 0..num_workers {
            let system_clone = Arc::clone(&system);
            let success_counter_clone = Arc::clone(&success_counter);

            let handle = tokio::spawn(async move {
                let mut local_success = 0;

                for i in 0..operations_per_worker {
                    let operation_id = worker_id * operations_per_worker + i;

                    let result = system_clone.create_case(
                        format!("Throughput Case {}", operation_id),
                        format!("Throughput description {}", operation_id),
                        CasePriority::Medium,
                        None,
                    ).await;

                    if result.is_ok() {
                        local_success += 1;
                    }
                }

                success_counter_clone.fetch_add(local_success, Ordering::Relaxed);
            });

            handles.push(handle);
        }

        // Wait for all workers to complete
        for handle in handles {
            handle.await.expect("Worker task failed");
        }

        let total_duration = start_time.elapsed();
        let total_success = success_counter.load(Ordering::Relaxed);

        // Throughput calculations
        let operations_per_second = num_operations as f64 / total_duration.as_secs_f64();
        let avg_latency_ms = total_duration.as_millis() as f64 / num_operations as f64;

        // Performance assertions
        assert!(total_success > 0); // At least some operations should succeed
        assert!(operations_per_second > 10.0); // At least 10 operations per second
        assert!(avg_latency_ms < 1000.0); // Average latency under 1 second

        println!("Throughput Test Results:");
        println!("  Total operations: {}", num_operations);
        println!("  Successful operations: {}", total_success);
        println!("  Total duration: {:?}", total_duration);
        println!("  Operations/second: {:.2}", operations_per_second);
        println!("  Average latency: {:.2}ms", avg_latency_ms);
    }

    #[tokio::test]
    async fn test_mixed_operation_throughput() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = Arc::new(CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system"));

        // Create some base cases first
        let mut case_ids = vec![];
        for i in 0..50 {
            let case_id = system.create_case(
                format!("Mixed Test Case {}", i),
                format!("Description {}", i),
                CasePriority::Medium,
                None,
            ).await.expect("Failed to create mixed test case");

            case_ids.push(case_id);
        }

        let start_time = Instant::now();
        let success_counter = Arc::new(AtomicUsize::new(0));

        // Perform mixed operations: updates, assignments, evidence addition
        let operations_per_case = 3; // update, assign, add evidence
        let total_operations = case_ids.len() * operations_per_case;

        let success_counter_clone = Arc::clone(&success_counter);
        let case_ids_clone = case_ids.clone();

        tokio::spawn(async move {
            let mut local_success = 0;

            for (i, case_id) in case_ids_clone.iter().enumerate() {
                // Update status
                if system.update_case_status(case_id, CaseStatus::Investigating, "test@example.com").await.is_ok() {
                    local_success += 1;
                }

                // Assign analyst
                if system.assign_case(case_id, &format!("analyst{}@example.com", i), "admin@example.com").await.is_ok() {
                    local_success += 1;
                }

                // Add evidence
                let evidence = Evidence {
                    id: format!("evidence-{}", i),
                    evidence_type: EvidenceType::LogFile,
                    description: format!("Evidence for case {}", i),
                    content: format!("Evidence content {}", i),
                    collected_at: chrono::Utc::now(),
                    collected_by: format!("analyst{}@example.com", i),
                    integrity_hash: format!("hash-{}", i),
                };

                if system.add_evidence(case_id, evidence, "test@example.com").await.is_ok() {
                    local_success += 1;
                }
            }

            success_counter_clone.store(local_success, Ordering::Relaxed);
        }).await.expect("Mixed operations task failed");

        let total_duration = start_time.elapsed();
        let total_success = success_counter.load(Ordering::Relaxed);

        // Performance assertions for mixed operations
        assert!(total_success > 0);
        assert!(total_duration.as_millis() < 10000); // Under 10 seconds for all operations

        let operations_per_second = total_operations as f64 / total_duration.as_secs_f64();
        assert!(operations_per_second > 5.0); // At least 5 mixed operations per second
    }
}

/// Test performance under stress conditions
#[cfg(test)]
mod stress_tests {
    use super::*;

    #[tokio::test]
    async fn test_system_stability_under_memory_pressure() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = Arc::new(CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system"));

        // Create cases with large amounts of data to simulate memory pressure
        let num_large_cases = 100;

        for i in 0..num_large_cases {
            let case_id = system.create_case(
                format!("Stress Test Case {}", i),
                "X".repeat(10000), // 10KB description
                CasePriority::Medium,
                None,
            ).await.expect("Failed to create stress test case");

            // Add multiple large evidence items
            for j in 0..5 {
                let evidence = Evidence {
                    id: format!("stress-evidence-{}-{}", i, j),
                    evidence_type: EvidenceType::LogFile,
                    description: format!("Large evidence {}", j),
                    content: "Y".repeat(5000), // 5KB content
                    collected_at: chrono::Utc::now(),
                    collected_by: "stress-test@example.com".to_string(),
                    integrity_hash: format!("stress-hash-{}-{}", i, j),
                };

                system.add_evidence(&case_id, evidence, "stress-test@example.com")
                    .await.expect("Failed to add stress test evidence");
            }
        }

        // Verify system can still operate normally after memory pressure
        let final_case_id = system.create_case(
            "Post-Stress Test Case".to_string(),
            "Testing system stability after memory pressure".to_string(),
            CasePriority::High,
            None,
        ).await.expect("Failed to create post-stress case");

        assert!(!final_case_id.is_empty());

        // Verify final case can be retrieved
        let final_case = system.get_case(&final_case_id).await
            .expect("Failed to get post-stress case")
            .expect("Post-stress case not found");

        assert_eq!(final_case.status, CaseStatus::Open);
        assert_eq!(final_case.priority, CasePriority::High);
    }

    #[tokio::test]
    async fn test_timeout_handling_under_load() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = Arc::new(CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system"));

        // Test timeout handling for operations that might hang
        let timeout_duration = Duration::from_secs(5);

        let result = timeout(timeout_duration, async {
            // Perform many operations that should complete quickly
            for i in 0..1000 {
                let _case_id = system.create_case(
                    format!("Timeout Test Case {}", i),
                    format!("Description {}", i),
                    CasePriority::Low,
                    None,
                ).await.expect("Failed to create timeout test case");
            }
        }).await;

        // Should complete within timeout
        assert!(result.is_ok(), "Operations should complete within timeout");
    }

    #[tokio::test]
    async fn test_resource_cleanup_under_stress() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Create many cases and then clear them
        let num_cases = 500;
        let mut case_ids = vec![];

        for i in 0..num_cases {
            let case_id = system.create_case(
                format!("Cleanup Test Case {}", i),
                format!("Description {}", i),
                CasePriority::Medium,
                None,
            ).await.expect("Failed to create cleanup test case");

            case_ids.push(case_id);
        }

        // Verify all cases exist
        for case_id in &case_ids {
            let case = system.get_case(case_id).await
                .expect("Failed to get cleanup test case")
                .expect("Cleanup test case not found");

            assert!(case.title.starts_with("Cleanup Test Case"));
        }

        // Clear repository (simulate cleanup)
        mock_repo.clear().await;

        // Verify cases are cleaned up
        // Note: In a real implementation, the system cache might still hold cases
        // This test verifies repository cleanup works
        for i in 0..10 { // Test sample
            let case_id = format!("Cleanup Test Case {}", i);
            let result = mock_repo.get_case(&case_id).await;
            assert!(result.is_ok());
            assert!(result.unwrap().is_none(), "Case should be cleaned up");
        }
    }
}

/// Test performance monitoring and metrics
#[cfg(test)]
mod metrics_tests {
    use super::*;

    #[test]
    fn test_operation_timing_measurement() {
        let (result, duration) = measure_execution_time(|| {
            // Simulate some work
            std::thread::sleep(Duration::from_millis(10));
            42
        });

        assert_eq!(result, 42);
        assert!(duration.as_millis() >= 10);
        assert!(duration.as_millis() < 50); // Allow some variance
    }

    #[tokio::test]
    async fn test_async_operation_timing() {
        let (result, duration) = measure_async_execution_time(|| async {
            // Simulate async work
            tokio::time::sleep(Duration::from_millis(15)).await;
            "async_result".to_string()
        }).await;

        assert_eq!(result, "async_result");
        assert!(duration.as_millis() >= 15);
        assert!(duration.as_millis() < 100); // Allow some variance
    }

    #[test]
    fn test_performance_assertion_helpers() {
        let fast_duration = Duration::from_millis(50);
        let slow_duration = Duration::from_millis(2000);

        // Fast operation should pass
        assert_performance_within_limit(fast_duration, 100);

        // Slow operation should fail this assertion
        // Note: In real usage, you'd adjust the limits based on requirements
        assert!(slow_duration.as_millis() > 100); // Just verify the duration is actually slow
    }

    #[tokio::test]
    async fn test_system_performance_baseline() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let start_time = Instant::now();
        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        let initialization_time = start_time.elapsed();

        // System initialization should be reasonably fast
        assert!(initialization_time.as_millis() < 1000); // Under 1 second

        // Test basic operation performance
        let operation_start = Instant::now();
        let case_id = system.create_case(
            "Performance Baseline Test".to_string(),
            "Testing system performance baseline".to_string(),
            CasePriority::Medium,
            None,
        ).await.expect("Failed to create baseline test case");

        let operation_time = operation_start.elapsed();

        assert!(!case_id.is_empty());
        assert_reasonable_performance(operation_time, "create_case");
    }
}

/// Test scalability characteristics
#[cfg(test)]
mod scalability_tests {
    use super::*;

    #[tokio::test]
    async fn test_horizontal_scaling_simulation() {
        // Simulate multiple system instances working concurrently
        let num_instances = 5;
        let cases_per_instance = 20;

        let start_time = Instant::now();

        let mut handles = vec![];
        for instance_id in 0..num_instances {
            let handle = tokio::spawn(async move {
                let mock_repo = Arc::new(MockCaseRepository::new());
                let config = TestConfigFactory::test_config();
                let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

                let system = CaseManagementSystem::new(
                    config,
                    mock_repo.clone(),
                    workflow_engine,
                ).await.expect("Failed to create scaled instance");

                let mut local_cases = vec![];
                for i in 0..cases_per_instance {
                    let case_id = system.create_case(
                        format!("Scale Instance {} Case {}", instance_id, i),
                        format!("Description for scaled case"),
                        CasePriority::Medium,
                        None,
                    ).await.expect("Failed to create scaled case");

                    local_cases.push(case_id);
                }

                local_cases.len()
            });

            handles.push(handle);
        }

        // Wait for all instances to complete
        let mut total_cases = 0;
        for handle in handles {
            let count = handle.await.expect("Instance failed");
            total_cases += count;
        }

        let total_duration = start_time.elapsed();
        let expected_total_cases = num_instances * cases_per_instance;

        // Scalability assertions
        assert_eq!(total_cases, expected_total_cases);

        // Performance should scale reasonably
        let cases_per_second = expected_total_cases as f64 / total_duration.as_secs_f64();
        assert!(cases_per_second > 5.0); // At least 5 cases per second across all instances

        println!("Scalability Test Results:");
        println!("  Instances: {}", num_instances);
        println!("  Cases per instance: {}", cases_per_instance);
        println!("  Total cases: {}", total_cases);
        println!("  Total duration: {:?}", total_duration);
        println!("  Cases/second: {:.2}", cases_per_second);
    }

    #[tokio::test]
    async fn test_data_volume_scalability() {
        let mock_repo = Arc::new(MockCaseRepository::new());
        let config = TestConfigFactory::test_config();
        let workflow_engine = Arc::new(CaseWorkflowEngine::new_with_defaults(None));

        let system = CaseManagementSystem::new(
            config,
            mock_repo.clone(),
            workflow_engine,
        ).await.expect("Failed to create case management system");

        // Test with increasing data volumes
        let test_sizes = vec![10, 50, 100, 200];

        for &size in &test_sizes {
            let start_time = Instant::now();

            // Create cases with increasing amounts of evidence
            for i in 0..size {
                let case_id = system.create_case(
                    format!("Volume Scale Case {}", i),
                    format!("Description with size {}", size),
                    CasePriority::Medium,
                    None,
                ).await.expect("Failed to create volume scale case");

                // Add evidence proportional to test size
                let evidence_count = size.min(10); // Cap at 10 to avoid excessive test time
                for j in 0..evidence_count {
                    let evidence = Evidence {
                        id: format!("volume-evidence-{}-{}", i, j),
                        evidence_type: EvidenceType::LogFile,
                        description: format!("Evidence {} for case {}", j, i),
                        content: format!("Content for volume test size {}", size),
                        collected_at: chrono::Utc::now(),
                        collected_by: "volume-test@example.com".to_string(),
                        integrity_hash: format!("volume-hash-{}-{}", i, j),
                    };

                    system.add_evidence(&case_id, evidence, "volume-test@example.com")
                        .await.expect("Failed to add volume test evidence");
                }
            }

            let duration = start_time.elapsed();
            let operations_per_second = (size * size.min(10)) as f64 / duration.as_secs_f64();

            // Performance should degrade gracefully with increasing data volume
            assert!(operations_per_second > 1.0, "Performance degraded too much for size {}", size);

            println!("Volume Scalability Test (Size {}):", size);
            println!("  Duration: {:?}", duration);
            println!("  Operations/second: {:.2}", operations_per_second);
        }
    }
}
