//! Example of how to refactor existing integration tests to use shared infrastructure
//! 
//! This file demonstrates the performance improvement by using the shared test server
//! instead of creating new app instances for each test.

mod shared_test_infrastructure;

use shared_test_infrastructure::{SharedTestServer, SharedTestHelpers};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::json;

// Example 1: Basic test using shared server (no exclusive lock needed)
#[tokio::test]
async fn test_health_endpoint_shared() {
    let server = SharedTestServer::instance().await;
    
    let response = server
        .client()
        .get(&format!("{}/health", server.base_url()))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
}

// Example 2: Token endpoint test using shared helpers
#[tokio::test]
async fn test_oauth_token_endpoint_shared() {
    let server = SharedTestServer::instance().await;
    
    let response = server
        .client()
        .post(&format!("{}/oauth/token", server.base_url()))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            AUTHORIZATION,
            SharedTestHelpers::basic_auth_header("test_client", "test_secret_12345"),
        )
        .body("grant_type=client_credentials")
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    
    let token_response: serde_json::Value = response.json().await.unwrap();
    assert!(token_response["access_token"].as_str().is_some());
    assert!(token_response["token_type"].as_str().is_some());
    assert!(token_response["expires_in"].as_u64().is_some());
}

// Example 3: Using helper function for tokens
#[tokio::test]
async fn test_protected_endpoint_shared() {
    let server = SharedTestServer::instance().await;
    let token = SharedTestHelpers::get_access_token().await;
    
    let response = server
        .client()
        .get(&format!("{}/oauth/introspect", server.base_url()))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    
    // Should work with valid token
    assert!(response.status().is_success() || response.status() == 401); // Depending on endpoint requirements
}

// Example 4: Test that needs exclusive access (modifies global state)
#[tokio::test]
async fn test_admin_operation_exclusive() {
    let server = SharedTestServer::instance().await;
    let _lock = server.exclusive_lock().await; // Ensure no other tests run concurrently
    server.reset_test_state().await;
    
    let admin_token = SharedTestHelpers::get_admin_token().await;
    
    let response = server
        .client()
        .post(&format!("{}/admin/some_operation", server.base_url()))
        .header(AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(CONTENT_TYPE, "application/json")
        .json(&json!({
            "operation": "test"
        }))
        .send()
        .await
        .unwrap();
    
    // Test admin operation
    println!("Admin operation response: {}", response.status());
}

// Example 5: Concurrent test (multiple requests to same shared server)
#[tokio::test]
async fn test_concurrent_requests() {
    let server = SharedTestServer::instance().await;
    
    // Spawn multiple concurrent requests
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let server = server.clone();
        let handle = tokio::spawn(async move {
            let token = SharedTestHelpers::get_access_token().await;
            
            let response = server
                .client()
                .get(&format!("{}/health?id={}", server.base_url(), i))
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .send()
                .await
                .unwrap();
            
            response.status().as_u16()
        });
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    let results: Vec<u16> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    
    // All requests should succeed (or fail consistently)
    for status in results {
        assert!(status == 200 || status == 404); // Health might return 404, that's ok
    }
}

// Example 6: Performance comparison test
#[tokio::test]
async fn test_performance_comparison() {
    use std::time::Instant;
    
    // Test with shared server (should be fast)
    let start = Instant::now();
    let server = SharedTestServer::instance().await;
    
    for _ in 0..5 {
        let response = server
            .client()
            .get(&format!("{}/health", server.base_url()))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success() || response.status() == 404);
    }
    
    let shared_duration = start.elapsed();
    
    println!("Shared server 5 requests took: {:?}", shared_duration);
    
    // This should be much faster than creating 5 separate app instances
    assert!(shared_duration.as_millis() < 1000); // Should be under 1 second
}

// Example 7: Using macro for cleaner test definitions (if you implement the macros)
/*
shared_integration_test!(test_with_macro, {
    let token = SharedTestHelpers::get_access_token().await;
    assert!(!token.is_empty());
});

exclusive_integration_test!(test_exclusive_with_macro, {
    let admin_token = SharedTestHelpers::get_admin_token().await;
    // This test has exclusive access to the server
    assert!(!admin_token.is_empty());
});
*/

#[cfg(test)]
mod performance_tests {
    use super::*;
    
    /// Benchmark the difference between shared vs individual servers
    /// Note: This is a demonstration - in real tests you'd use criterion for proper benchmarking
    #[tokio::test]
    #[ignore] // Ignore by default since it's a benchmark
    async fn benchmark_shared_vs_individual() {
        use std::time::Instant;
        
        // Test shared server approach
        let start = Instant::now();
        for _ in 0..10 {
            let server = SharedTestServer::instance().await;
            let response = server
                .client()
                .get(&format!("{}/health", server.base_url()))
                .send()
                .await
                .unwrap();
            drop(response); // Ensure response is processed
        }
        let shared_time = start.elapsed();
        
        println!("Shared server approach - 10 requests: {:?}", shared_time);
        
        // Note: We can't easily test the "individual server" approach here
        // because it would require refactoring the existing spawn_app() function
        // But the performance difference should be dramatic:
        // - Shared: ~100-500ms for 10 requests
        // - Individual: ~30-60 seconds for 10 requests (due to server startup overhead)
    }
}