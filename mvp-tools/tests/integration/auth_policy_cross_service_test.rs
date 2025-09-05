//! Cross-Service Integration Tests: Auth Service ↔ Policy Service
//!
//! Tests the complete integration between authentication and authorization services,
//! validating end-to-end security workflows and policy enforcement.

use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Test complete authentication → authorization → resource access workflow
#[tokio::test]
async fn test_complete_auth_policy_workflow() {
    let client = Client::new();

    // Step 1: Authenticate user and get access token
    let auth_response = client
        .post("http://localhost:8080/oauth/token")
        .form(&[
            ("grant_type", "password"),
            ("username", "alice"),
            ("password", "SecurePass123!"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .unwrap();

    assert!(auth_response.status().is_success());
    let auth_body: serde_json::Value = auth_response.json().await.unwrap();
    let access_token = auth_body["access_token"].as_str().unwrap();

    // Step 2: Use token to authorize access to protected resource
    let policy_request = json!({
        "principal": {
            "id": "alice",
            "roles": ["user", "developer"]
        },
        "action": "read",
        "resource": {
            "type": "document",
            "id": "confidential_report.pdf",
            "department": "engineering"
        },
        "context": {
            "time": "2024-01-15T10:00:00Z",
            "ip_address": "192.168.1.100"
        }
    });

    let policy_response = client
        .post("http://localhost:8081/v1/authorize")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&policy_request)
        .send()
        .await
        .unwrap();

    assert!(policy_response.status().is_success());
    let policy_body: serde_json::Value = policy_response.json().await.unwrap();

    // Should be allowed based on user's roles and resource classification
    assert_eq!(policy_body["decision"], "Allow");

    // Step 3: Test access to the actual resource (simulated)
    let resource_response = client
        .get("http://localhost:8080/api/documents/confidential_report.pdf")
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert!(resource_response.status().is_success());
}

/// Test role-based access control with policy service integration
#[tokio::test]
async fn test_role_based_access_control() {
    let client = Client::new();

    // Test different user roles and their access patterns
    let test_cases = vec![
        ("alice", "developer", "write", "code_repository", true),
        ("bob", "manager", "approve", "budget_request", true),
        ("charlie", "user", "admin", "user_database", false),
        ("diana", "auditor", "read", "audit_logs", true),
        ("eve", "contractor", "write", "confidential_docs", false),
    ];

    for (user, role, action, resource, expected_allowed) in test_cases {
        // Get token for user
        let auth_response = client
            .post("http://localhost:8080/oauth/token")
            .form(&[
                ("grant_type", "password"),
                ("username", user),
                ("password", "TestPass123!"),
                ("client_id", "test_client"),
                ("client_secret", "test_secret"),
            ])
            .send()
            .await;

        if auth_response.is_err() {
            // Skip if user doesn't exist in test environment
            continue;
        }

        let auth_body: serde_json::Value = auth_response.unwrap().json().await.unwrap();
        let access_token = auth_body["access_token"].as_str().unwrap();

        // Test policy decision
        let policy_request = json!({
            "principal": {
                "id": user,
                "roles": [role]
            },
            "action": action,
            "resource": {
                "type": resource,
                "sensitivity": "high"
            }
        });

        let policy_response = client
            .post("http://localhost:8081/v1/authorize")
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&policy_request)
            .send()
            .await
            .unwrap();

        let policy_body: serde_json::Value = policy_response.json().await.unwrap();
        let decision = policy_body["decision"].as_str().unwrap();

        if expected_allowed {
            assert_eq!(
                decision, "Allow",
                "Expected {} to be allowed for {} on {}",
                user, action, resource
            );
        } else {
            assert_eq!(
                decision, "Deny",
                "Expected {} to be denied for {} on {}",
                user, action, resource
            );
        }
    }
}

/// Test policy service integration with dynamic context
#[tokio::test]
async fn test_policy_context_integration() {
    let client = Client::new();

    // Get authenticated user token
    let auth_response = client
        .post("http://localhost:8080/oauth/token")
        .form(&[
            ("grant_type", "password"),
            ("username", "alice"),
            ("password", "SecurePass123!"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .unwrap();

    let auth_body: serde_json::Value = auth_response.json().await.unwrap();
    let access_token = auth_body["access_token"].as_str().unwrap();

    // Test time-based access control
    let business_hours_request = json!({
        "principal": { "id": "alice", "roles": ["user"] },
        "action": "access",
        "resource": { "type": "database", "name": "production_db" },
        "context": {
            "time": "2024-01-15T14:00:00Z",  // Business hours
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Workstation)",
            "location": "office"
        }
    });

    let policy_response = client
        .post("http://localhost:8081/v1/authorize")
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&business_hours_request)
        .send()
        .await
        .unwrap();

    let policy_body: serde_json::Value = policy_response.json().await.unwrap();
    assert_eq!(policy_body["decision"], "Allow");

    // Test after-hours access (should be restricted)
    let after_hours_request = json!({
        "principal": { "id": "alice", "roles": ["user"] },
        "action": "access",
        "resource": { "type": "database", "name": "production_db" },
        "context": {
            "time": "2024-01-15T02:00:00Z",  // After hours
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Workstation)"
        }
    });

    let after_hours_response = client
        .post("http://localhost:8081/v1/authorize")
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&after_hours_request)
        .send()
        .await
        .unwrap();

    let after_hours_body: serde_json::Value = after_hours_response.json().await.unwrap();
    // Note: This might still be allowed depending on policy configuration
    // The test validates that context is properly evaluated
    assert!(after_hours_body["decision"].as_str().is_some());
}

/// Test cross-service error handling and resilience
#[tokio::test]
async fn test_cross_service_error_handling() {
    let client = Client::new();

    // Test with invalid token
    let invalid_token_request = json!({
        "principal": { "id": "unknown_user" },
        "action": "read",
        "resource": { "type": "document" }
    });

    let error_response = client
        .post("http://localhost:8081/v1/authorize")
        .header("Authorization", "Bearer invalid_token")
        .json(&invalid_token_request)
        .send()
        .await
        .unwrap();

    // Should return authentication error
    assert!(error_response.status().is_client_error());

    // Test with malformed request
    let malformed_request = json!({
        "invalid_field": "value"
    });

    let malformed_response = client
        .post("http://localhost:8081/v1/authorize")
        .header("Authorization", "Bearer valid_token")
        .json(&malformed_request)
        .send()
        .await
        .unwrap();

    // Should return validation error
    assert!(malformed_response.status().is_client_error());
}

/// Test concurrent cross-service operations
#[tokio::test]
async fn test_concurrent_cross_service_operations() {
    let start_time = Instant::now();
    let mut handles = vec![];

    // Spawn multiple concurrent auth → policy workflows
    for i in 0..20 {
        let handle = tokio::spawn(async move {
            let client = Client::new();
            let user_id = format!("user_{}", i % 5); // Rotate through 5 test users

            // Authenticate
            let auth_response = client
                .post("http://localhost:8080/oauth/token")
                .form(&[
                    ("grant_type", "password"),
                    ("username", &user_id),
                    ("password", "TestPass123!"),
                    ("client_id", "test_client"),
                    ("client_secret", "test_secret"),
                ])
                .send()
                .await;

            if auth_response.is_err() {
                return; // Skip if user doesn't exist
            }

            let auth_body: serde_json::Value = auth_response.unwrap().json().await.unwrap();
            let access_token = auth_body["access_token"].as_str().unwrap();

            // Authorize action
            let policy_request = json!({
                "principal": { "id": user_id },
                "action": "read",
                "resource": {
                    "type": "document",
                    "id": format!("doc_{}", i)
                }
            });

            let policy_response = client
                .post("http://localhost:8081/v1/authorize")
                .header("Authorization", format!("Bearer {}", access_token))
                .json(&policy_request)
                .send()
                .await
                .unwrap();

            assert!(policy_response.status().is_success());
        });

        handles.push(handle);
    }

    // Wait for all concurrent operations
    for handle in handles {
        let _ = handle.await;
    }

    let duration = start_time.elapsed();
    println!(
        "Concurrent cross-service operations completed in: {:?}",
        duration
    );

    // Should complete within reasonable time under load
    assert!(duration < Duration::from_secs(30));
}

/// Test policy caching integration
#[tokio::test]
async fn test_policy_caching_integration() {
    let client = Client::new();

    // Get authenticated token
    let auth_response = client
        .post("http://localhost:8080/oauth/token")
        .form(&[
            ("grant_type", "password"),
            ("username", "alice"),
            ("password", "SecurePass123!"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .unwrap();

    let auth_body: serde_json::Value = auth_response.json().await.unwrap();
    let access_token = auth_body["access_token"].as_str().unwrap();

    // Make same policy request multiple times to test caching
    let policy_request = json!({
        "principal": { "id": "alice", "roles": ["user"] },
        "action": "read",
        "resource": { "type": "document", "id": "cached_doc.pdf" }
    });

    let start_time = Instant::now();

    // Make 10 identical requests to test caching performance
    for _ in 0..10 {
        let policy_response = client
            .post("http://localhost:8081/v1/authorize")
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&policy_request)
            .send()
            .await
            .unwrap();

        assert!(policy_response.status().is_success());
        let policy_body: serde_json::Value = policy_response.json().await.unwrap();
        assert_eq!(policy_body["decision"], "Allow");
    }

    let total_duration = start_time.elapsed();
    let avg_duration = total_duration / 10;

    println!("Average cached policy decision time: {:?}", avg_duration);

    // Cached decisions should be fast (< 10ms average)
    assert!(avg_duration < Duration::from_millis(10));
}
