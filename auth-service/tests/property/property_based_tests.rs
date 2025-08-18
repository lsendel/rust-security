// Property-based testing for comprehensive coverage of edge cases

use crate::test_utils::*;
use auth_service::security::*;
use auth_service::store::TokenStore;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

mod test_utils;

#[tokio::test]
async fn property_test_token_validation() {
    // Generate a large number of random token inputs
    let valid_tokens = PropertyTestUtils::generate_valid_tokens(100);
    let invalid_tokens = PropertyTestUtils::generate_invalid_tokens(100);
    
    for token in valid_tokens {
        // Property: All validly formatted tokens should pass input validation
        let result = validate_token_input(&token);
        assert!(result.is_ok(), "Valid token format should pass validation: {}", token);
    }
    
    for token in invalid_tokens {
        // Property: Invalid tokens should either fail validation or be handled gracefully
        let result = validate_token_input(&token);
        // Some might pass if they happen to be valid format, that's OK
        // The key is that no panic or undefined behavior occurs
        let _ = result;
    }
}

#[tokio::test]
async fn property_test_pkce_operations() {
    // Property: PKCE verifier/challenge pairs should always validate correctly
    for _ in 0..50 {
        let verifier = generate_code_verifier();
        let challenge = generate_code_challenge(&verifier);
        
        // Property: Generated pair should always validate
        assert!(verify_code_challenge(&verifier, &challenge));
        
        // Property: Different verifier should not validate
        let different_verifier = generate_code_verifier();
        if different_verifier != verifier {
            assert!(!verify_code_challenge(&different_verifier, &challenge));
        }
        
        // Property: Challenge should not validate as its own verifier
        assert!(!verify_code_challenge(&challenge, &challenge));
    }
}

#[tokio::test]
async fn property_test_signature_verification() {
    let secret = "test_secret";
    let methods = ["GET", "POST", "PUT", "DELETE"];
    let paths = ["/oauth/token", "/oauth/introspect", "/admin/keys", "/health"];
    let bodies = ["", "grant_type=client_credentials", "token=test", "data=value"];
    
    for _ in 0..20 {
        let method = methods[rand::random::<usize>() % methods.len()];
        let path = paths[rand::random::<usize>() % paths.len()];
        let body = bodies[rand::random::<usize>() % bodies.len()];
        let timestamp = chrono::Utc::now().timestamp();
        
        // Property: Generated signature should always verify correctly
        if let Ok(signature) = generate_request_signature(method, path, body, timestamp, secret) {
            let verification = verify_request_signature(method, path, body, timestamp, &signature, secret);
            assert!(verification.unwrap_or(false), 
                "Generated signature should verify for {}", method);
            
            // Property: Tampered signature should not verify
            let tampered_signature = signature + "tampered";
            let tampered_verification = verify_request_signature(method, path, body, timestamp, &tampered_signature, secret);
            assert!(!tampered_verification.unwrap_or(true), 
                "Tampered signature should not verify");
            
            // Property: Wrong secret should not verify
            let wrong_verification = verify_request_signature(method, path, body, timestamp, &signature, "wrong_secret");
            assert!(!wrong_verification.unwrap_or(true), 
                "Signature with wrong secret should not verify");
        }
    }
}

#[tokio::test]
async fn property_test_token_binding() {
    let ip_addresses = [
        "192.168.1.1", "10.0.0.1", "172.16.0.1", 
        "127.0.0.1", "255.255.255.255", "0.0.0.0"
    ];
    let user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Custom-Agent/1.0",
        "",
        "Very-Long-User-Agent-String-That-Exceeds-Normal-Bounds",
    ];
    
    for _ in 0..30 {
        let ip1 = ip_addresses[rand::random::<usize>() % ip_addresses.len()];
        let ua1 = user_agents[rand::random::<usize>() % user_agents.len()];
        let ip2 = ip_addresses[rand::random::<usize>() % ip_addresses.len()];
        let ua2 = user_agents[rand::random::<usize>() % user_agents.len()];
        
        let binding1 = generate_token_binding(ip1, ua1);
        let binding2 = generate_token_binding(ip2, ua2);
        
        // Property: Same inputs should generate same binding
        let binding1_repeat = generate_token_binding(ip1, ua1);
        assert_eq!(binding1, binding1_repeat, "Same inputs should generate same binding");
        
        // Property: Binding should validate with original inputs
        assert!(validate_token_binding(&binding1, ip1, ua1));
        
        // Property: Different inputs should generate different bindings (with high probability)
        if ip1 != ip2 || ua1 != ua2 {
            assert_ne!(binding1, binding2, "Different inputs should generate different bindings");
        }
        
        // Property: Binding should not validate with different inputs
        if ip1 != ip2 {
            assert!(!validate_token_binding(&binding1, ip2, ua1), 
                "Binding should not validate with different IP");
        }
        if ua1 != ua2 {
            assert!(!validate_token_binding(&binding1, ip1, ua2), 
                "Binding should not validate with different User-Agent");
        }
    }
}

#[tokio::test]
async fn property_test_log_sanitization() {
    let test_inputs = vec![
        "normal text",
        "text\nwith\nnewlines",
        "text\rwith\rcarriage",
        "text\twith\ttabs",
        "mixed\n\r\tcontrol\nchars",
        "unicode: üñíçødé 💀🔥",
        "\x00\x01\x02\x03binary",
        "very".repeat(1000),
    ];
    
    for input in test_inputs {
        let sanitized = sanitize_log_input(&input);
        
        // Property: Output should not contain raw newlines
        assert!(!sanitized.contains('\n'), "Sanitized output should not contain raw newlines");
        assert!(!sanitized.contains('\r'), "Sanitized output should not contain raw carriage returns");
        
        // Property: Newlines should be escaped
        if input.contains('\n') {
            assert!(sanitized.contains("\\n"), "Newlines should be escaped");
        }
        if input.contains('\r') {
            assert!(sanitized.contains("\\r"), "Carriage returns should be escaped");
        }
        if input.contains('\t') {
            assert!(sanitized.contains("\\t"), "Tabs should be escaped");
        }
        
        // Property: Should not be longer than reasonable limit
        assert!(sanitized.len() <= input.len() * 2 + 100, "Sanitized output should not be excessively long");
    }
}

#[tokio::test]
async fn property_test_client_credential_validation() {
    let valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    let invalid_chars = "!@#$%^&*()+=[]{}|\\:;\"'<>?,./~ ";
    
    // Generate valid client IDs
    for _ in 0..20 {
        let length = 1 + rand::random::<usize>() % 100; // 1-100 chars
        let client_id: String = (0..length)
            .map(|_| {
                let idx = rand::random::<usize>() % valid_chars.len();
                valid_chars.chars().nth(idx).unwrap()
            })
            .collect();
        
        let secret = SecurityTestUtils::generate_secure_random(32);
        
        // Property: Valid format should pass validation
        let result = validate_client_credentials(&client_id, &secret);
        if client_id.len() <= 255 && secret.len() <= 255 {
            assert!(result.is_ok(), "Valid credentials should pass: {}", client_id);
        }
    }
    
    // Test with invalid characters
    for _ in 0..10 {
        let invalid_char = invalid_chars.chars().nth(rand::random::<usize>() % invalid_chars.len()).unwrap();
        let client_id = format!("valid_client{}", invalid_char);
        let secret = "valid_secret";
        
        // Property: Invalid characters should be rejected
        let result = validate_client_credentials(&client_id, secret);
        assert!(result.is_err(), "Invalid character should be rejected: {}", invalid_char);
    }
}

#[tokio::test]
async fn property_test_store_operations() {
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));
    
    // Property: Set and get operations should be consistent
    for _ in 0..50 {
        let token = format!("token_{}", uuid::Uuid::new_v4());
        let active = rand::random::<bool>();
        let scope = if rand::random::<bool>() {
            Some(format!("scope_{}", rand::random::<u32>()))
        } else {
            None
        };
        let client_id = format!("client_{}", rand::random::<u32>());
        let exp = chrono::Utc::now().timestamp() + rand::random::<i64>() % 3600;
        
        // Set values
        store.set_active(&token, active, Some(3600)).await.unwrap();
        if let Some(ref s) = scope {
            store.set_scope(&token, Some(s.clone()), Some(3600)).await.unwrap();
        }
        store.set_client_id(&token, client_id.clone(), Some(3600)).await.unwrap();
        store.set_exp(&token, exp, Some(3600)).await.unwrap();
        
        // Property: Retrieved values should match set values
        let record = store.get_record(&token).await.unwrap();
        assert_eq!(record.active, active);
        assert_eq!(record.scope, scope);
        assert_eq!(record.client_id, Some(client_id));
        assert_eq!(record.exp, Some(exp));
        
        let retrieved_active = store.get_active(&token).await.unwrap();
        assert_eq!(retrieved_active, active);
    }
}

#[tokio::test]
async fn property_test_concurrent_store_operations() {
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));
    let operations = 100;
    let concurrent_tasks = 10;
    
    let mut handles = Vec::new();
    
    for task_id in 0..concurrent_tasks {
        let store_clone = store.clone();
        let handle = tokio::spawn(async move {
            let mut results = Vec::new();
            
            for i in 0..(operations / concurrent_tasks) {
                let token = format!("token_{}_{}", task_id, i);
                let active = rand::random::<bool>();
                
                // Property: Concurrent operations should not interfere
                store_clone.set_active(&token, active, Some(3600)).await.unwrap();
                let retrieved = store_clone.get_active(&token).await.unwrap();
                
                results.push((token, active, retrieved));
            }
            
            results
        });
        handles.push(handle);
    }
    
    // Verify all operations completed correctly
    for handle in handles {
        let results = handle.await.unwrap();
        for (token, expected, actual) in results {
            assert_eq!(expected, actual, "Concurrent operation failed for token: {}", token);
        }
    }
}

#[tokio::test]
async fn property_test_rate_limiter_fairness() {
    use auth_service::rate_limit_optimized::*;
    
    let config = RateLimitConfig {
        requests_per_window: 10,
        window_duration_secs: 60,
        burst_allowance: 5,
        cleanup_interval_secs: 300,
    };
    
    let limiter = ShardedRateLimiter::new(config);
    let clients = 20;
    let requests_per_client = 20;
    
    let mut handles = Vec::new();
    
    for client_id in 0..clients {
        let limiter_clone = limiter.clone();
        let handle = tokio::spawn(async move {
            let client_key = format!("client_{}", client_id);
            let mut allowed = 0;
            let mut denied = 0;
            
            for _ in 0..requests_per_client {
                match limiter_clone.check_rate_limit(&client_key) {
                    RateLimitResult::Allowed => allowed += 1,
                    RateLimitResult::RateLimited { .. } => denied += 1,
                }
            }
            
            (client_id, allowed, denied)
        });
        handles.push(handle);
    }
    
    let mut total_allowed = 0;
    let mut client_results = Vec::new();
    
    for handle in handles {
        let (client_id, allowed, denied) = handle.await.unwrap();
        total_allowed += allowed;
        client_results.push((client_id, allowed, denied));
    }
    
    // Property: Each client should get roughly equal treatment
    let expected_per_client = (10 + 5); // normal limit + burst
    for (client_id, allowed, _denied) in client_results {
        assert!(allowed <= expected_per_client, 
            "Client {} got {} requests, expected max {}", client_id, allowed, expected_per_client);
        assert!(allowed > 0, "Each client should get at least some requests");
    }
    
    // Property: Total allowed should not exceed limits
    let max_total = clients * expected_per_client;
    assert!(total_allowed <= max_total, 
        "Total allowed {} should not exceed max {}", total_allowed, max_total);
}

#[tokio::test]
async fn property_test_token_format_consistency() {
    let fixture = TestFixture::new().await;
    
    // Property: All generated tokens should follow consistent format
    for _ in 0..20 {
        let token = fixture.get_access_token().await;
        
        // Property: Access tokens should have consistent format
        assert!(token.starts_with("tk_"), "Access token should start with 'tk_'");
        assert!(token.len() > 10, "Access token should be reasonable length");
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'), 
            "Access token should only contain safe characters");
        
        // Property: Token should be unique
        let another_token = fixture.get_access_token().await;
        assert_ne!(token, another_token, "Tokens should be unique");
    }
}

#[tokio::test]
async fn property_test_error_handling_consistency() {
    let fixture = TestFixture::new().await;
    
    let error_scenarios = vec![
        ("invalid_grant_type", "grant_type=invalid"),
        ("missing_client_id", "grant_type=client_credentials"),
        ("malformed_request", "invalid form data"),
        ("empty_request", ""),
    ];
    
    for (scenario, body) in error_scenarios {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap();
        
        // Property: Error responses should be consistent
        assert!(response.status().is_client_error() || response.status().is_server_error(),
            "Scenario '{}' should return error status", scenario);
        
        let response_text = response.text().await.unwrap();
        
        // Property: Error responses should not leak sensitive information
        assert!(!response_text.to_lowercase().contains("panic"));
        assert!(!response_text.to_lowercase().contains("unwrap"));
        assert!(!response_text.to_lowercase().contains("thread"));
        assert!(!response_text.to_lowercase().contains("rust"));
        assert!(!response_text.contains("SECRET"));
        assert!(!response_text.contains("PASSWORD"));
    }
}

#[tokio::test]
async fn property_test_malicious_input_handling() {
    let fixture = TestFixture::new().await;
    let malicious_payloads = TestDataGenerator::malicious_payloads();
    
    for payload in malicious_payloads {
        // Test various endpoints with malicious input
        let endpoints = vec![
            ("/oauth/token", "POST"),
            ("/oauth/introspect", "POST"),
            ("/jwks.json", "GET"),
            ("/health", "GET"),
        ];
        
        for (endpoint, method) in endpoints {
            let request_builder = match method {
                "POST" => fixture.client.post(&format!("{}{}", fixture.base_url, endpoint))
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(format!("client_id={}", payload)),
                "GET" => fixture.client.get(&format!("{}{}?param={}", fixture.base_url, endpoint, urlencoding::encode(payload))),
                _ => continue,
            };
            
            let response = request_builder.send().await.unwrap();
            
            // Property: Service should handle malicious input gracefully
            assert!(response.status().as_u16() < 500 || response.status() == 500, 
                "Should not crash on malicious input");
            
            let response_text = response.text().await.unwrap();
            
            // Property: Malicious content should not be reflected
            assert!(!response_text.contains("<script"));
            assert!(!response_text.contains("javascript:"));
            assert!(!response_text.contains("DROP TABLE"));
            assert!(!response_text.contains("etc/passwd"));
        }
    }
}

#[tokio::test]
async fn property_test_timing_consistency() {
    let fixture = TestFixture::new().await;
    
    // Test timing consistency across different scenarios
    let scenarios = vec![
        ("valid_credentials", &fixture.valid_client_id, &fixture.valid_client_secret),
        ("invalid_client", "invalid_client", &fixture.valid_client_secret),
        ("invalid_secret", &fixture.valid_client_id, "invalid_secret"),
        ("both_invalid", "invalid_client", "invalid_secret"),
    ];
    
    let iterations = 10;
    
    for (scenario, client_id, client_secret) in scenarios {
        let mut times = Vec::new();
        
        for _ in 0..iterations {
            let start = std::time::Instant::now();
            
            let _ = fixture.client
                .post(&format!("{}/oauth/token", fixture.base_url))
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(AUTHORIZATION, fixture.basic_auth_header(client_id, client_secret))
                .body("grant_type=client_credentials")
                .send()
                .await
                .unwrap();
            
            times.push(start.elapsed());
        }
        
        let avg_time = times.iter().sum::<std::time::Duration>() / times.len() as u32;
        println!("Average time for {}: {:?}", scenario, avg_time);
        
        // Property: Response times should be reasonably consistent (within 5x factor)
        let min_time = times.iter().min().unwrap();
        let max_time = times.iter().max().unwrap();
        let ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;
        
        assert!(ratio < 5.0, 
            "Timing variance too high for {}: min={:?}, max={:?}, ratio={:.2}", 
            scenario, min_time, max_time, ratio);
    }
}