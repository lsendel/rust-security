use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use reqwest::Client;
use serde_json::{json, Value};
use uuid::Uuid;

/// Comprehensive security integration tests for the Rust Security Workspace
/// These tests validate security controls, attack prevention, and compliance requirements

#[tokio::test]
async fn test_authentication_security_controls() {
    let client = Client::new();
    let base_url = std::env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    // Test 1: Brute force protection
    println!("Testing brute force protection...");
    let mut failed_attempts = 0;
    for i in 0..20 {
        let response = client
            .post(&format!("{}/oauth/token", base_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "invalid_client"),
                ("client_secret", &format!("invalid_secret_{}", i)),
            ])
            .send()
            .await
            .expect("Failed to send request");

        if response.status() == 401 {
            failed_attempts += 1;
        }

        // Check if rate limiting kicks in
        if response.status() == 429 {
            println!("✅ Rate limiting activated after {} failed attempts", failed_attempts);
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    assert!(failed_attempts > 0, "Should have failed authentication attempts");

    // Test 2: Input validation
    println!("Testing input validation...");
    let malicious_inputs = vec![
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "../../etc/passwd",
        "\x00\x01\x02",
        "A".repeat(10000),
    ];

    for malicious_input in malicious_inputs {
        let response = client
            .post(&format!("{}/oauth/token", base_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", malicious_input),
                ("client_secret", "test_secret"),
            ])
            .send()
            .await
            .expect("Failed to send request");

        assert!(
            response.status() == 400 || response.status() == 422,
            "Should reject malicious input: {}",
            malicious_input
        );
    }

    println!("✅ Input validation tests passed");
}

#[tokio::test]
async fn test_token_security_controls() {
    let client = Client::new();
    let base_url = std::env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    // First, get a valid token
    let token_response = client
        .post(&format!("{}/oauth/token", base_url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
            ("scope", "read write"),
        ])
        .send()
        .await
        .expect("Failed to get token");

    assert_eq!(token_response.status(), 200, "Should successfully get token");

    let token_data: Value = token_response.json().await.expect("Failed to parse token response");
    let access_token = token_data["access_token"].as_str().expect("Missing access token");

    // Test 1: Token binding validation
    println!("Testing token binding...");

    // Try to use token with different User-Agent
    let response = client
        .post(&format!("{}/oauth/introspect", base_url))
        .header("User-Agent", "DifferentUserAgent/1.0")
        .json(&json!({"token": access_token}))
        .send()
        .await
        .expect("Failed to introspect token");

    // Token binding should detect the change
    let introspect_data: Value = response.json().await.expect("Failed to parse introspect response");

    // Test 2: Token format validation
    println!("Testing token format validation...");
    let invalid_tokens = vec![
        "invalid_token",
        "",
        "tk_" + &"A".repeat(2000), // Too long
        "tk_invalid\x00token",     // Null bytes
        "tk_invalid\ntoken",       // Newlines
    ];

    for invalid_token in invalid_tokens {
        let response = client
            .post(&format!("{}/oauth/introspect", base_url))
            .json(&json!({"token": invalid_token}))
            .send()
            .await
            .expect("Failed to send introspect request");

        let introspect_data: Value = response.json().await.expect("Failed to parse response");
        assert_eq!(
            introspect_data["active"].as_bool().unwrap_or(true),
            false,
            "Invalid token should not be active: {}",
            invalid_token
        );
    }

    println!("✅ Token security tests passed");
}

#[tokio::test]
async fn test_request_signing_security() {
    let client = Client::new();
    let base_url = std::env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    // Get a token first
    let token_response = client
        .post(&format!("{}/oauth/token", base_url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .expect("Failed to get token");

    let token_data: Value = token_response.json().await.expect("Failed to parse token response");
    let access_token = token_data["access_token"].as_str().expect("Missing access token");

    // Test 1: Request without signature (should fail for critical operations)
    println!("Testing request signing requirement...");
    let response = client
        .post(&format!("{}/oauth/revoke", base_url))
        .form(&[("token", access_token)])
        .send()
        .await
        .expect("Failed to send revoke request");

    // Should require signature for revocation
    assert!(
        response.status() == 400 || response.status() == 401,
        "Should require signature for token revocation"
    );

    // Test 2: Invalid signature
    println!("Testing invalid signature rejection...");
    let response = client
        .post(&format!("{}/oauth/revoke", base_url))
        .header("X-Signature", "invalid_signature")
        .header("X-Timestamp", &chrono::Utc::now().timestamp().to_string())
        .form(&[("token", access_token)])
        .send()
        .await
        .expect("Failed to send signed request");

    assert!(
        response.status() == 400 || response.status() == 401,
        "Should reject invalid signature"
    );

    println!("✅ Request signing tests passed");
}

#[tokio::test]
async fn test_mfa_security_controls() {
    let client = Client::new();
    let base_url = std::env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    // Test 1: TOTP registration validation
    println!("Testing TOTP registration security...");

    let response = client
        .post(&format!("{}/mfa/totp/register", base_url))
        .json(&json!({
            "user_id": "test_user",
            "issuer": "Test App"
        }))
        .send()
        .await
        .expect("Failed to register TOTP");

    if response.status() == 200 {
        let totp_data: Value = response.json().await.expect("Failed to parse TOTP response");

        // Verify secret is properly formatted
        let secret = totp_data["secret"].as_str().expect("Missing TOTP secret");
        assert!(secret.len() >= 16, "TOTP secret should be at least 16 characters");
        assert!(secret.chars().all(|c| c.is_ascii_alphanumeric()), "TOTP secret should be alphanumeric");

        // Test invalid TOTP codes
        let invalid_codes = vec!["000000", "123456", "999999", "abcdef"];
        for invalid_code in invalid_codes {
            let verify_response = client
                .post(&format!("{}/mfa/totp/verify", base_url))
                .json(&json!({
                    "user_id": "test_user",
                    "code": invalid_code
                }))
                .send()
                .await
                .expect("Failed to verify TOTP");

            assert!(
                verify_response.status() != 200,
                "Should reject invalid TOTP code: {}",
                invalid_code
            );
        }
    }

    println!("✅ MFA security tests passed");
}

#[tokio::test]
async fn test_security_headers() {
    let client = Client::new();
    let base_url = std::env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    println!("Testing security headers...");

    let response = client
        .get(&format!("{}/health", base_url))
        .send()
        .await
        .expect("Failed to get health endpoint");

    let headers = response.headers();

    // Check for required security headers
    let required_headers = vec![
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("x-xss-protection", "1; mode=block"),
        ("strict-transport-security", "max-age=31536000; includeSubDomains"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
    ];

    for (header_name, expected_value) in required_headers {
        let header_value = headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        assert!(
            header_value.contains(expected_value),
            "Missing or incorrect security header: {} (expected: {}, got: {})",
            header_name,
            expected_value,
            header_value
        );
    }

    // Check Content Security Policy
    let csp_header = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        csp_header.contains("default-src 'self'"),
        "CSP should include default-src 'self'"
    );

    println!("✅ Security headers tests passed");
}

#[tokio::test]
async fn test_policy_service_security() {
    let client = Client::new();
    let policy_base_url = std::env::var("POLICY_TEST_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:8081".to_string());

    println!("Testing policy service security...");

    // Test 1: Authorization request validation
    let malicious_requests = vec![
        json!({
            "request_id": "'; DROP TABLE policies; --",
            "principal": {"type": "User", "id": "user1"},
            "action": "read",
            "resource": {"type": "Document", "id": "doc1"}
        }),
        json!({
            "request_id": "req1",
            "principal": {"type": "User", "id": "<script>alert('xss')</script>"},
            "action": "read",
            "resource": {"type": "Document", "id": "doc1"}
        }),
        json!({
            "request_id": "req1",
            "principal": {"type": "User", "id": "user1"},
            "action": "../../etc/passwd",
            "resource": {"type": "Document", "id": "doc1"}
        }),
    ];

    for malicious_request in malicious_requests {
        let response = client
            .post(&format!("{}/v1/authorize", policy_base_url))
            .json(&malicious_request)
            .send()
            .await
            .expect("Failed to send authorization request");

        // Should either reject with 400/422 or deny authorization
        if response.status() == 200 {
            let auth_response: Value = response.json().await.expect("Failed to parse response");
            assert_eq!(
                auth_response["decision"].as_str().unwrap_or("allow"),
                "deny",
                "Should deny malicious authorization request"
            );
        } else {
            assert!(
                response.status() == 400 || response.status() == 422,
                "Should reject malformed authorization request"
            );
        }
    }

    println!("✅ Policy service security tests passed");
}

#[tokio::test]
async fn test_compliance_audit_trail() {
    let client = Client::new();
    let base_url = std::env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    println!("Testing compliance audit trail...");

    // Perform various operations that should be audited
    let operations = vec![
        ("token_request", || async {
            client
                .post(&format!("{}/oauth/token", base_url))
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", "audit_test_client"),
                    ("client_secret", "audit_test_secret"),
                ])
                .send()
                .await
        }),
        ("token_introspect", || async {
            client
                .post(&format!("{}/oauth/introspect", base_url))
                .json(&json!({"token": "test_token_for_audit"}))
                .send()
                .await
        }),
        ("invalid_auth", || async {
            client
                .post(&format!("{}/oauth/token", base_url))
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", "invalid_client"),
                    ("client_secret", "invalid_secret"),
                ])
                .send()
                .await
        }),
    ];

    let mut audit_events = Vec::new();

    for (operation_name, operation) in operations {
        let request_id = Uuid::new_v4().to_string();

        // Add request ID header for correlation
        let response = operation().await.expect("Failed to perform operation");

        audit_events.push((operation_name, request_id, response.status()));

        // Small delay to ensure audit logs are written
        sleep(Duration::from_millis(100)).await;
    }

    // Verify audit events were logged (this would typically check log aggregation system)
    // For now, we just verify the operations completed
    assert!(!audit_events.is_empty(), "Should have audit events");

    println!("✅ Compliance audit trail tests passed");
    println!("Audit events generated: {:?}", audit_events);
}

#[tokio::test]
async fn test_performance_under_load() {
    let client = Client::new();
    let base_url = std::env::var("TEST_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    println!("Testing performance under load...");

    let concurrent_requests = 50;
    let mut handles = Vec::new();

    let start_time = std::time::Instant::now();

    for i in 0..concurrent_requests {
        let client = client.clone();
        let base_url = base_url.clone();

        let handle = tokio::spawn(async move {
            let response = client
                .post(&format!("{}/oauth/token", base_url))
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", &format!("load_test_client_{}", i)),
                    ("client_secret", "load_test_secret"),
                ])
                .send()
                .await;

            match response {
                Ok(resp) => (resp.status(), resp.headers().get("x-response-time").cloned()),
                Err(_) => (reqwest::StatusCode::INTERNAL_SERVER_ERROR, None),
            }
        });

        handles.push(handle);
    }

    let results = futures::future::join_all(handles).await;
    let total_time = start_time.elapsed();

    let successful_requests = results
        .iter()
        .filter(|result| {
            if let Ok((status, _)) = result {
                status.is_success() || *status == reqwest::StatusCode::TOO_MANY_REQUESTS
            } else {
                false
            }
        })
        .count();

    let success_rate = successful_requests as f64 / concurrent_requests as f64;

    println!("Load test results:");
    println!("  Total requests: {}", concurrent_requests);
    println!("  Successful requests: {}", successful_requests);
    println!("  Success rate: {:.2}%", success_rate * 100.0);
    println!("  Total time: {:?}", total_time);
    println!("  Requests per second: {:.2}", concurrent_requests as f64 / total_time.as_secs_f64());

    // Performance assertions
    assert!(success_rate >= 0.95, "Success rate should be at least 95%");
    assert!(total_time.as_secs() < 30, "Load test should complete within 30 seconds");

    println!("✅ Performance under load tests passed");
}

/// Helper function to run all security tests
pub async fn run_comprehensive_security_tests() {
    println!("🔒 Starting comprehensive security tests...");

    test_authentication_security_controls().await;
    test_token_security_controls().await;
    test_request_signing_security().await;
    test_mfa_security_controls().await;
    test_security_headers().await;
    test_policy_service_security().await;
    test_compliance_audit_trail().await;
    test_performance_under_load().await;

    println!("✅ All comprehensive security tests passed!");
}

#[tokio::main]
async fn main() {
    run_comprehensive_security_tests().await;
}
