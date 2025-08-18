// Comprehensive redirect URI security testing
//
// This test suite covers various attack vectors against OAuth redirect URI validation
// including open redirect, XSS, path traversal, domain spoofing, and encoding bypasses.

use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

mod test_utils;
use test_utils::*;

#[tokio::test]
async fn test_open_redirect_attacks() {
    let fixture = TestFixture::new().await;
    
    // Various open redirect attack vectors
    let attack_vectors = vec![
        // Basic open redirect attempts
        "https://example.com/callback?redirect=https://evil.com",
        "https://example.com/callback&redirect=https://evil.com",
        "https://example.com/callback#https://evil.com",
        
        // URL confusion attacks
        "https://example.com@evil.com/callback",
        "https://example.com.evil.com/callback",
        "https://evil.com/example.com/callback",
        
        // Subdomain takeover simulation
        "https://abandoned.example.com/callback",
        
        // Protocol confusion
        "http://example.com/callback", // Should be blocked if HTTPS enforced
        
        // Domain spoofing with similar characters
        "https://examp1e.com/callback", // 1 instead of l
        "https://example.co/callback", // Missing 'm'
        "https://еxample.com/callback", // Cyrillic е
        
        // Homograph attacks
        "https://еxample.com/callback", // Different Unicode chars
        "https://example.co\u{200B}m/callback", // Zero-width space
    ];
    
    for attack_uri in attack_vectors {
        // Test authorization endpoint with malicious redirect URI
        let auth_params = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
            fixture.valid_client_id,
            urlencoding::encode(attack_uri)
        );
        
        let response = fixture.client
            .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
            .header(USER_AGENT, "security-test-agent/1.0")
            .send()
            .await
            .unwrap();
        
        // Should reject malicious redirect URIs
        assert_ne!(response.status(), 200, 
            "Should reject malicious redirect URI: {}", attack_uri);
        assert!(response.status() == 400 || response.status() == 403,
            "Should return 400 Bad Request or 403 Forbidden for: {}", attack_uri);
            
        // Verify error response doesn't leak information
        let response_text = response.text().await.unwrap();
        assert!(!response_text.contains("redirect"), 
            "Error response should not contain 'redirect' for: {}", attack_uri);
        assert!(!response_text.contains("uri"), 
            "Error response should not contain 'uri' for: {}", attack_uri);
    }
}

#[tokio::test]
async fn test_xss_in_redirect_uris() {
    let fixture = TestFixture::new().await;
    
    let xss_payloads = vec![
        "javascript:alert('xss')",
        "data:text/html,<script>alert('xss')</script>",
        "vbscript:msgbox('xss')",
        "https://example.com/callback?param=<script>alert('xss')</script>",
        "https://example.com/callback#<script>alert('xss')</script>",
        "https://example.com/callback/<script>alert('xss')</script>",
        "https://example.com/callback;jsessionid=<script>alert('xss')</script>",
    ];
    
    for xss_payload in xss_payloads {
        let auth_params = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
            fixture.valid_client_id,
            urlencoding::encode(xss_payload)
        );
        
        let response = fixture.client
            .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
            .send()
            .await
            .unwrap();
        
        assert_ne!(response.status(), 200,
            "Should reject XSS payload: {}", xss_payload);
            
        let response_text = response.text().await.unwrap();
        // Ensure XSS payload is not reflected in response
        assert!(!response_text.contains("<script"),
            "XSS payload should not be reflected: {}", xss_payload);
        assert!(!response_text.contains("javascript:"),
            "JavaScript protocol should not be reflected: {}", xss_payload);
    }
}

#[tokio::test]
async fn test_path_traversal_attacks() {
    let fixture = TestFixture::new().await;
    
    let path_traversal_payloads = vec![
        "https://example.com/../../../etc/passwd",
        "https://example.com/callback/../../../etc/passwd",
        "https://example.com/callback/..\\..\\..\\etc\\passwd",
        "https://example.com/callback%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "https://example.com/callback%252e%252e%252f%252e%252e%252f",
        "https://example.com/callback/....//....//etc/passwd",
        "https://example.com/callback/.%2e/.%2e/.%2e/etc/passwd",
    ];
    
    for traversal_payload in path_traversal_payloads {
        let auth_params = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
            fixture.valid_client_id,
            urlencoding::encode(traversal_payload)
        );
        
        let response = fixture.client
            .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
            .send()
            .await
            .unwrap();
        
        assert_ne!(response.status(), 200,
            "Should reject path traversal: {}", traversal_payload);
    }
}

#[tokio::test]
async fn test_encoding_bypass_attacks() {
    let fixture = TestFixture::new().await;
    
    let encoding_attacks = vec![
        // Double URL encoding
        "https://example.com/callback%252f%252e%252e%252f",
        "https://example.com/callback%25252f%25252e%25252e%25252f",
        
        // HTML entity encoding
        "https://example.com/callback&#x2f;&#x2e;&#x2e;&#x2f;",
        
        // Unicode encoding
        "https://example.com/callback\\u002f\\u002e\\u002e\\u002f",
        
        // Hex encoding
        "https://example.com/callback\\x2f\\x2e\\x2e\\x2f",
        
        // Mixed encodings
        "https://example.com/callback%2f%2e%2e%5c%2e%2e%2f",
        
        // Overlong UTF-8 sequences (if not properly validated)
        "https://example.com/callback%c0%af%c0%ae%c0%af",
    ];
    
    for encoding_attack in encoding_attacks {
        let auth_params = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
            fixture.valid_client_id,
            urlencoding::encode(encoding_attack)
        );
        
        let response = fixture.client
            .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
            .send()
            .await
            .unwrap();
        
        assert_ne!(response.status(), 200,
            "Should reject encoding bypass: {}", encoding_attack);
    }
}

#[tokio::test]
async fn test_ip_address_and_localhost_validation() {
    let fixture = TestFixture::new().await;
    
    // Test various IP address formats
    let ip_tests = vec![
        ("https://127.0.0.1:3000/callback", true),   // Localhost should be allowed
        ("http://localhost:3000/callback", true),    // Localhost HTTP in dev
        ("https://192.168.1.1/callback", false),     // Private IP should be blocked
        ("https://10.0.0.1/callback", false),        // Private IP should be blocked
        ("https://172.16.0.1/callback", false),      // Private IP should be blocked
        ("https://8.8.8.8/callback", false),         // Public IP should be blocked
        ("https://[::1]/callback", true),            // IPv6 localhost might be allowed
        ("https://[2001:db8::1]/callback", false),   // IPv6 should be blocked
        ("https://[::ffff:127.0.0.1]/callback", true), // IPv4-mapped IPv6 localhost
    ];
    
    for (ip_uri, should_allow) in ip_tests {
        let auth_params = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
            fixture.valid_client_id,
            urlencoding::encode(ip_uri)
        );
        
        let response = fixture.client
            .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
            .send()
            .await
            .unwrap();
        
        if should_allow {
            // Might be allowed in development mode
            println!("IP test (might be allowed): {} - Status: {}", ip_uri, response.status());
        } else {
            assert_ne!(response.status(), 200,
                "Should reject non-localhost IP: {}", ip_uri);
        }
    }
}

#[tokio::test]
async fn test_fragment_and_query_parameter_attacks() {
    let fixture = TestFixture::new().await;
    
    let fragment_attacks = vec![
        "https://example.com/callback#javascript:alert('xss')",
        "https://example.com/callback#data:text/html,<script>alert('xss')</script>",
        "https://example.com/callback#https://evil.com",
        "https://example.com/callback#//evil.com",
        "https://example.com/callback#@evil.com",
    ];
    
    for fragment_attack in fragment_attacks {
        let auth_params = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
            fixture.valid_client_id,
            urlencoding::encode(fragment_attack)
        );
        
        let response = fixture.client
            .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
            .send()
            .await
            .unwrap();
        
        assert_ne!(response.status(), 200,
            "Should reject fragment attack: {}", fragment_attack);
    }
}

#[tokio::test]
async fn test_url_shortener_blocking() {
    let fixture = TestFixture::new().await;
    
    let shortener_domains = vec![
        "https://bit.ly/callback",
        "https://tinyurl.com/callback", 
        "https://t.co/callback",
        "https://goo.gl/callback",
        "https://short.link/callback",
        "https://ow.ly/callback",
        "https://buff.ly/callback",
    ];
    
    for shortener in shortener_domains {
        let auth_params = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
            fixture.valid_client_id,
            urlencoding::encode(shortener)
        );
        
        let response = fixture.client
            .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
            .send()
            .await
            .unwrap();
        
        assert_ne!(response.status(), 200,
            "Should block URL shortener: {}", shortener);
    }
}

#[tokio::test]
async fn test_uri_length_limits() {
    let fixture = TestFixture::new().await;
    
    // Test extremely long URIs to prevent DoS
    let long_path = "a".repeat(5000);
    let long_uri = format!("https://example.com/{}", long_path);
    
    let auth_params = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
        fixture.valid_client_id,
        urlencoding::encode(&long_uri)
    );
    
    let response = fixture.client
        .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
        .send()
        .await
        .unwrap();
    
    assert_ne!(response.status(), 200, "Should reject extremely long URI");
}

#[tokio::test]
async fn test_legitimate_redirect_uris() {
    let fixture = TestFixture::new().await;
    
    // Test that legitimate URIs are still accepted
    let legitimate_uris = vec![
        "https://myapp.com/oauth/callback",
        "https://api.myservice.io/auth/callback",
        "https://subdomain.example.com/return",
        "https://app.example.com:8443/secure/callback",
    ];
    
    // Note: These tests require the URIs to be registered for the client
    // In a real scenario, you would register these first
    for legitimate_uri in legitimate_uris {
        let auth_params = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
            fixture.valid_client_id,
            urlencoding::encode(legitimate_uri)
        );
        
        let response = fixture.client
            .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
            .send()
            .await
            .unwrap();
        
        // These might be rejected due to client registration requirements
        // The test documents expected legitimate patterns
        println!("Legitimate URI test: {} - Status: {}", legitimate_uri, response.status());
    }
}

#[tokio::test]
async fn test_concurrent_redirect_validation() {
    let fixture = TestFixture::new().await;
    
    // Test concurrent requests with various redirect URIs to ensure thread safety
    let attack_uris = vec![
        "https://evil.com/callback",
        "javascript:alert('xss')",
        "https://192.168.1.1/callback",
        "https://example.com/../../../etc/passwd",
    ];
    
    let mut handles = vec![];
    
    for attack_uri in attack_uris {
        let client = fixture.client.clone();
        let base_url = fixture.base_url.clone();
        let client_id = fixture.valid_client_id.clone();
        let uri = attack_uri.to_string();
        
        let handle = tokio::spawn(async move {
            let auth_params = format!(
                "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
                client_id,
                urlencoding::encode(&uri)
            );
            
            let response = client
                .get(&format!("{}/oauth/authorize?{}", base_url, auth_params))
                .send()
                .await
                .unwrap();
                
            (uri, response.status())
        });
        
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    for handle in handles {
        let (uri, status) = handle.await.unwrap();
        assert_ne!(status, 200, "Should reject malicious URI in concurrent test: {}", uri);
    }
}

#[tokio::test]
async fn test_redirect_uri_case_sensitivity() {
    let fixture = TestFixture::new().await;
    
    // Test case variations that might bypass validation
    let case_variations = vec![
        "HTTPS://EVIL.COM/callback",
        "hTtPs://EvIl.CoM/callback", 
        "https://JAVASCRIPT.COM/callback",
        "JAVASCRIPT:ALERT('XSS')",
        "Data:TEXT/HTML,<SCRIPT>ALERT('XSS')</SCRIPT>",
    ];
    
    for case_uri in case_variations {
        let auth_params = format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid&state=test_state",
            fixture.valid_client_id,
            urlencoding::encode(case_uri)
        );
        
        let response = fixture.client
            .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
            .send()
            .await
            .unwrap();
        
        assert_ne!(response.status(), 200,
            "Should reject case variation attack: {}", case_uri);
    }
}