//! Integration tests for the Cedar policy engine
//!
//! These tests validate policy evaluation, entity management,
//! and authorization decision workflows.

use std::collections::HashMap;
use std::time::Duration;
use reqwest::Client;
use serde_json::json;

#[derive(Debug)]
struct TestEntity {
    entity_type: String,
    entity_id: String,
    attributes: HashMap<String, serde_json::Value>,
}

impl TestEntity {
    fn new(entity_type: &str, entity_id: &str) -> Self {
        Self {
            entity_type: entity_type.to_string(),
            entity_id: entity_id.to_string(),
            attributes: HashMap::new(),
        }
    }

    fn with_attribute(mut self, key: &str, value: serde_json::Value) -> Self {
        self.attributes.insert(key.to_string(), value);
        self
    }
}

/// Test basic policy evaluation
#[tokio::test]
async fn test_basic_policy_evaluation() {
    let client = Client::new();

    // Test allow policy
    let request_data = json!({
        "principal": {
            "type": "User",
            "id": "alice"
        },
        "action": "Document::read",
        "resource": {
            "type": "Document",
            "id": "doc1"
        },
        "context": {},
        "request_id": "test-001"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&request_data)
        .send()
        .await
        .expect("Policy evaluation request should succeed");

    assert!(response.status().is_success(), "Policy evaluation should succeed");

    let response_body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(response_body["decision"], "Allow", "Policy should allow the action");

    // Test deny policy
    let deny_request = json!({
        "principal": {
            "type": "User",
            "id": "bob"
        },
        "action": "Document::delete",
        "resource": {
            "type": "Document",
            "id": "sensitive-doc"
        },
        "context": {},
        "request_id": "test-002"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&deny_request)
        .send()
        .await
        .expect("Policy evaluation request should succeed");

    let response_body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(response_body["decision"], "Deny", "Policy should deny the action");
}

/// Test role-based access control (RBAC)
#[tokio::test]
async fn test_rbac_policy_evaluation() {
    let client = Client::new();

    // Test admin role permissions
    let admin_request = json!({
        "principal": {
            "type": "User",
            "id": "admin"
        },
        "action": "System::admin",
        "resource": {
            "type": "System",
            "id": "rust-security"
        },
        "context": {},
        "request_id": "test-admin-001"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&admin_request)
        .send()
        .await
        .expect("Admin policy evaluation should succeed");

    let response_body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(response_body["decision"], "Allow", "Admin should have system access");

    // Test regular user denied admin access
    let user_request = json!({
        "principal": {
            "type": "User",
            "id": "regular_user"
        },
        "action": "System::admin",
        "resource": {
            "type": "System",
            "id": "rust-security"
        },
        "context": {},
        "request_id": "test-admin-002"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&user_request)
        .send()
        .await
        .expect("User admin policy evaluation should succeed");

    let response_body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(response_body["decision"], "Deny", "Regular user should not have admin access");
}

/// Test attribute-based access control (ABAC)
#[tokio::test]
async fn test_abac_policy_evaluation() {
    let client = Client::new();

    // Test document ownership
    let owner_request = json!({
        "principal": {
            "type": "User",
            "id": "alice"
        },
        "action": "Document::edit",
        "resource": {
            "type": "Document",
            "id": "my-document",
            "owner": "alice"
        },
        "context": {},
        "request_id": "test-owner-001"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&owner_request)
        .send()
        .await
        .expect("Owner policy evaluation should succeed");

    let response_body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(response_body["decision"], "Allow", "Owner should be able to edit document");

    // Test non-owner denied access
    let non_owner_request = json!({
        "principal": {
            "type": "User",
            "id": "bob"
        },
        "action": "Document::edit",
        "resource": {
            "type": "Document",
            "id": "my-document",
            "owner": "alice"
        },
        "context": {},
        "request_id": "test-owner-002"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&non_owner_request)
        .send()
        .await
        .expect("Non-owner policy evaluation should succeed");

    let response_body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(response_body["decision"], "Deny", "Non-owner should not be able to edit document");
}

/// Test context-aware policies
#[tokio::test]
async fn test_context_aware_policies() {
    let client = Client::new();

    // Test time-based access
    let business_hours_request = json!({
        "principal": {
            "type": "User",
            "id": "employee"
        },
        "action": "System::access",
        "resource": {
            "type": "System",
            "id": "corporate-system"
        },
        "context": {
            "time": "14:30",
            "day": "monday",
            "location": "office"
        },
        "request_id": "test-context-001"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&business_hours_request)
        .send()
        .await
        .expect("Context-aware policy evaluation should succeed");

    let response_body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(response_body["decision"], "Allow", "Access should be allowed during business hours");

    // Test after-hours denial
    let after_hours_request = json!({
        "principal": {
            "type": "User",
            "id": "employee"
        },
        "action": "System::access",
        "resource": {
            "type": "System",
            "id": "corporate-system"
        },
        "context": {
            "time": "22:30",
            "day": "monday",
            "location": "remote"
        },
        "request_id": "test-context-002"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&after_hours_request)
        .send()
        .await
        .expect("After-hours policy evaluation should succeed");

    let response_body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(response_body["decision"], "Deny", "Access should be denied after hours");
}

/// Test policy evaluation performance
#[tokio::test]
async fn test_policy_evaluation_performance() {
    let client = Client::new();

    let request_data = json!({
        "principal": {
            "type": "User",
            "id": "perf-test-user"
        },
        "action": "Document::read",
        "resource": {
            "type": "Document",
            "id": "perf-test-doc"
        },
        "context": {},
        "request_id": "perf-test"
    });

    let mut response_times = vec![];

    // Measure response times for multiple requests
    for i in 0..100 {
        let start = std::time::Instant::now();

        let response = client
            .post("http://localhost:8081/v1/authorize")
            .json(&request_data)
            .send()
            .await
            .expect("Performance test request should succeed");

        assert!(response.status().is_success(), "Performance test request should succeed");

        let duration = start.elapsed();
        response_times.push(duration.as_millis() as f64);

        // Small delay to avoid overwhelming
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let avg_response_time: f64 = response_times.iter().sum::<f64>() / response_times.len() as f64;
    let p95_response_time = percentile(&response_times, 95.0);

    println!("Policy evaluation performance:");
    println!("  Average response time: {:.2}ms", avg_response_time);
    println!("  P95 response time: {:.2}ms", p95_response_time);
    println!("  Total requests: {}", response_times.len());

    // Performance assertions
    assert!(avg_response_time < 10.0, "Average response time should be < 10ms");
    assert!(p95_response_time < 50.0, "P95 response time should be < 50ms");
}

/// Test policy evaluation under load
#[tokio::test]
async fn test_policy_evaluation_under_load() {
    let client = Client::new();

    // Simulate concurrent policy evaluations
    let mut handles = vec![];

    for user_id in 0..20 {
        let client_clone = client.clone();
        let handle = tokio::spawn(async move {
            for doc_id in 0..10 {
                let request_data = json!({
                    "principal": {
                        "type": "User",
                        "id": format!("user_{}", user_id)
                    },
                    "action": "Document::read",
                    "resource": {
                        "type": "Document",
                        "id": format!("doc_{}", doc_id)
                    },
                    "context": {},
                    "request_id": format!("load-test-{}-{}", user_id, doc_id)
                });

                let response = client_clone
                    .post("http://localhost:8081/v1/authorize")
                    .json(&request_data)
                    .send()
                    .await;

                match response {
                    Ok(resp) => {
                        assert!(resp.status().is_success(), "Concurrent request should succeed");
                    }
                    Err(e) => {
                        panic!("Concurrent request failed: {}", e);
                    }
                }

                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        handles.push(handle);
    }

    // Wait for all concurrent evaluations to complete
    for handle in handles {
        handle.await.expect("Concurrent policy evaluation should complete");
    }

    println!("Concurrent policy evaluation load test completed successfully");
}

/// Test policy error handling
#[tokio::test]
async fn test_policy_error_handling() {
    let client = Client::new();

    // Test invalid principal
    let invalid_principal_request = json!({
        "principal": "invalid-principal-format",
        "action": "Document::read",
        "resource": {
            "type": "Document",
            "id": "test-doc"
        },
        "context": {},
        "request_id": "error-test-001"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&invalid_principal_request)
        .send()
        .await
        .expect("Invalid principal request should not fail at HTTP level");

    assert_eq!(response.status(), 400, "Invalid principal should return 400");

    // Test invalid action
    let invalid_action_request = json!({
        "principal": {
            "type": "User",
            "id": "test-user"
        },
        "action": "Invalid::Action",
        "resource": {
            "type": "Document",
            "id": "test-doc"
        },
        "context": {},
        "request_id": "error-test-002"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&invalid_action_request)
        .send()
        .await
        .expect("Invalid action request should not fail at HTTP level");

    assert_eq!(response.status(), 400, "Invalid action should return 400");

    // Test invalid resource
    let invalid_resource_request = json!({
        "principal": {
            "type": "User",
            "id": "test-user"
        },
        "action": "Document::read",
        "resource": "invalid-resource-format",
        "context": {},
        "request_id": "error-test-003"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&invalid_resource_request)
        .send()
        .await
        .expect("Invalid resource request should not fail at HTTP level");

    assert_eq!(response.status(), 400, "Invalid resource should return 400");
}

/// Test policy caching behavior
#[tokio::test]
async fn test_policy_caching_behavior() {
    let client = Client::new();

    // Make multiple identical requests to test caching
    let request_data = json!({
        "principal": {
            "type": "User",
            "id": "cache-test-user"
        },
        "action": "Document::read",
        "resource": {
            "type": "Document",
            "id": "cache-test-doc"
        },
        "context": {},
        "request_id": "cache-test"
    });

    let mut response_times = vec![];

    for i in 0..10 {
        let start = std::time::Instant::now();

        let response = client
            .post("http://localhost:8081/v1/authorize")
            .json(&request_data)
            .send()
            .await
            .expect("Cache test request should succeed");

        assert!(response.status().is_success(), "Cache test request should succeed");

        let duration = start.elapsed();
        response_times.push(duration.as_millis() as f64);

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Check if response times are consistent (indicating caching)
    let avg_response_time: f64 = response_times.iter().sum::<f64>() / response_times.len() as f64;
    let variance: f64 = response_times.iter()
        .map(|t| (t - avg_response_time).powi(2))
        .sum::<f64>() / response_times.len() as f64;

    println!("Cache behavior test:");
    println!("  Average response time: {:.2}ms", avg_response_time);
    println!("  Response time variance: {:.2}ms²", variance);

    // Low variance would indicate consistent caching behavior
    // In practice, you might want to set a threshold for acceptable variance
}

/// Test policy evaluation with complex entity hierarchies
#[tokio::test]
async fn test_complex_entity_hierarchies() {
    let client = Client::new();

    // Test with nested groups and roles
    let complex_request = json!({
        "principal": {
            "type": "User",
            "id": "complex-user",
            "groups": ["developers", "admins"],
            "department": "engineering",
            "clearance_level": 3
        },
        "action": "Document::access",
        "resource": {
            "type": "Document",
            "id": "classified-doc",
            "classification": "confidential",
            "department": "engineering",
            "required_clearance": 2
        },
        "context": {
            "current_time": "10:00",
            "access_location": "office"
        },
        "request_id": "complex-entity-test"
    });

    let response = client
        .post("http://localhost:8081/v1/authorize")
        .json(&complex_request)
        .send()
        .await
        .expect("Complex entity hierarchy test should succeed");

    let response_body: serde_json::Value = response.json().await.unwrap();

    // The decision depends on the actual policy implementation
    // This test validates that complex entities are processed correctly
    assert!(response_body["decision"].is_string(), "Decision should be present");
    assert!(matches!(response_body["decision"].as_str(),
                     Some("Allow") | Some("Deny")),
             "Decision should be Allow or Deny");
}

/// Test policy evaluation metrics collection
#[tokio::test]
async fn test_policy_metrics_collection() {
    let client = Client::new();

    // Make several requests to generate metrics
    for i in 0..5 {
        let request_data = json!({
            "principal": {
                "type": "User",
                "id": format!("metrics-user-{}", i)
            },
            "action": "Document::read",
            "resource": {
                "type": "Document",
                "id": format!("metrics-doc-{}", i)
            },
            "context": {},
            "request_id": format!("metrics-test-{}", i)
        });

        let response = client
            .post("http://localhost:8081/v1/authorize")
            .json(&request_data)
            .send()
            .await
            .expect("Metrics collection request should succeed");

        assert!(response.status().is_success(), "Metrics request should succeed");

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Check metrics endpoint
    let response = client
        .get("http://localhost:8081/metrics")
        .send()
        .await
        .expect("Metrics endpoint request should succeed");

    assert!(response.status().is_success(), "Metrics endpoint should be accessible");

    let metrics_body = response.text().await.unwrap();

    // Verify key metrics are present
    assert!(metrics_body.contains("authz_requests_total"), "Authorization requests metric should be present");
    assert!(metrics_body.contains("authz_allow_total"), "Authorization allow metric should be present");
    assert!(metrics_body.contains("authz_deny_total"), "Authorization deny metric should be present");
    assert!(metrics_body.contains("authz_duration_seconds"), "Authorization duration metric should be present");

    println!("Policy metrics collection test completed successfully");
}

// Helper function to calculate percentile
fn percentile(data: &[f64], p: f64) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut sorted_data = data.to_vec();
    sorted_data.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let index = (p / 100.0 * (sorted_data.len() - 1) as f64) as usize;
    sorted_data[index]
}
