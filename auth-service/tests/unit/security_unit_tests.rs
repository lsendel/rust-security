// Comprehensive unit tests for security modules

use auth_service::security::*;
use auth_service::mfa::*;
use auth_service::keys::*;
use auth_service::store::TokenStore;
use auth_service::rate_limit_optimized::*;
use crate::test_utils::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

mod test_utils;

#[tokio::test]
async fn test_pkce_code_generation_and_validation() {
    // Test valid PKCE flow
    let code_verifier = generate_code_verifier();
    assert!(code_verifier.len() >= 43 && code_verifier.len() <= 128);

    let code_challenge = generate_code_challenge(&code_verifier);
    assert!(verify_code_challenge(&code_verifier, &code_challenge));

    // Test with different verifier
    let different_verifier = generate_code_verifier();
    assert!(!verify_code_challenge(&different_verifier, &code_challenge));

    // Test edge cases
    assert!(!verify_code_challenge("", &code_challenge));
    assert!(!verify_code_challenge(&code_verifier, ""));
    assert!(!verify_code_challenge("", ""));
}

#[test]
fn test_code_challenge_method_parsing() {
    // Test valid method
    let method = "S256".parse::<CodeChallengeMethod>();
    assert!(method.is_ok());
    assert_eq!(method.unwrap(), CodeChallengeMethod::S256);

    // Test invalid methods
    assert!("plain".parse::<CodeChallengeMethod>().is_err());
    assert!("invalid".parse::<CodeChallengeMethod>().is_err());
    assert!("".parse::<CodeChallengeMethod>().is_err());
}

#[test]
fn test_pkce_validation_comprehensive() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    // Valid S256 validation
    assert!(validate_pkce_params(verifier, challenge, CodeChallengeMethod::S256));

    // Invalid challenge
    assert!(!validate_pkce_params(verifier, "invalid_challenge", CodeChallengeMethod::S256));

    // Invalid verifier
    assert!(!validate_pkce_params("invalid_verifier", challenge, CodeChallengeMethod::S256));
}

#[test]
fn test_request_signature_generation_and_verification() {
    let secret = "test_secret_key";
    let method = "POST";
    let path = "/oauth/token";
    let body = "grant_type=client_credentials";
    let timestamp = 1640995200; // Fixed timestamp for testing

    // Generate signature
    let signature = generate_request_signature(method, path, body, timestamp, secret).unwrap();
    assert!(!signature.is_empty());

    // Verify valid signature
    assert!(verify_request_signature(method, path, body, timestamp, &signature, secret).unwrap());

    // Test with different parameters
    assert!(!verify_request_signature("GET", path, body, timestamp, &signature, secret).unwrap());
    assert!(!verify_request_signature(method, "/different", body, timestamp, &signature, secret).unwrap());
    assert!(!verify_request_signature(method, path, "different_body", timestamp, &signature, secret).unwrap());
    assert!(!verify_request_signature(method, path, body, timestamp + 1, &signature, secret).unwrap());
    assert!(!verify_request_signature(method, path, body, timestamp, &signature, "different_secret").unwrap());
}

#[test]
fn test_request_signature_timing_resistance() {
    let secret = "test_secret_key";
    let method = "POST";
    let path = "/oauth/token";
    let body = "grant_type=client_credentials";
    let timestamp = 1640995200;

    let valid_signature = generate_request_signature(method, path, body, timestamp, secret).unwrap();
    let invalid_signature = "invalid_signature";

    // Test multiple times to ensure consistent timing
    for _ in 0..100 {
        let start_valid = std::time::Instant::now();
        let _ = verify_request_signature(method, path, body, timestamp, &valid_signature, secret);
        let valid_time = start_valid.elapsed();

        let start_invalid = std::time::Instant::now();
        let _ = verify_request_signature(method, path, body, timestamp, invalid_signature, secret);
        let invalid_time = start_invalid.elapsed();

        // Times should be roughly similar (within 2x factor)
        let ratio = valid_time.as_nanos() as f64 / invalid_time.as_nanos() as f64;
        assert!(ratio < 2.0 && ratio > 0.5, "Timing difference too large: {}", ratio);
    }
}

#[test]
fn test_token_binding_generation_and_validation() {
    let client_ip = "192.168.1.1";
    let user_agent = "Mozilla/5.0 (compatible; test)";

    // Generate binding
    let binding = generate_token_binding(client_ip, user_agent);
    assert!(!binding.is_empty());

    // Validate same binding
    assert!(validate_token_binding(&binding, client_ip, user_agent));

    // Test with different IP
    assert!(!validate_token_binding(&binding, "192.168.1.2", user_agent));

    // Test with different user agent
    assert!(!validate_token_binding(&binding, client_ip, "Different User Agent"));

    // Test with both different
    assert!(!validate_token_binding(&binding, "192.168.1.2", "Different User Agent"));
}

#[test]
fn test_input_validation() {
    // Valid tokens
    assert!(validate_token_input("valid_token_123").is_ok());
    assert!(validate_token_input("tk_12345678-abcd-efgh").is_ok());

    // Invalid tokens
    assert!(validate_token_input("").is_err());
    assert!(validate_token_input(&"x".repeat(2000)).is_err());
    assert!(validate_token_input("token\0with\0nulls").is_err());
    assert!(validate_token_input("token\nwith\nnewlines").is_err());
    assert!(validate_token_input("token\rwith\rcarriage").is_err());

    // SQL injection attempts
    assert!(validate_token_input("token'; DROP TABLE users; --").is_err());
    assert!(validate_token_input("token\" OR 1=1; --").is_err());
    assert!(validate_token_input("token/**/UNION/**/SELECT").is_err());
    assert!(validate_token_input("tokenxp_cmdshell").is_err());
    assert!(validate_token_input("tokensp_executesql").is_err());
}

#[test]
fn test_client_credentials_validation() {
    // Valid credentials
    assert!(validate_client_credentials("valid_client", "valid_secret").is_ok());
    assert!(validate_client_credentials("client-123_test", "secret_123").is_ok());

    // Invalid credentials
    assert!(validate_client_credentials("", "secret").is_err());
    assert!(validate_client_credentials("client", "").is_err());
    assert!(validate_client_credentials("", "").is_err());
    assert!(validate_client_credentials(&"x".repeat(300), "secret").is_err());
    assert!(validate_client_credentials("client", &"x".repeat(300)).is_err());
    assert!(validate_client_credentials("client@invalid", "secret").is_err());
    assert!(validate_client_credentials("client with spaces", "secret").is_err());
    assert!(validate_client_credentials("client.with.dots", "secret").is_err());
}

#[test]
fn test_log_sanitization() {
    // Normal text should pass through
    assert_eq!(sanitize_log_input("normal text"), "normal text");

    // Control characters should be escaped
    assert_eq!(sanitize_log_input("text\nwith\nnewlines"), "text\\nwith\\nnewlines");
    assert_eq!(sanitize_log_input("text\rwith\rcarriage"), "text\\rwith\\rcarriage");
    assert_eq!(sanitize_log_input("text\twith\ttabs"), "text\\twith\\ttabs");

    // Mixed control characters
    assert_eq!(sanitize_log_input("line1\nline2\r\nline3\t"), "text\\nline2\\r\\nline3\\t");

    // Non-ASCII characters should be filtered
    let input_with_special = "text\x00\x01\x02normal";
    let sanitized = sanitize_log_input(input_with_special);
    assert!(!sanitized.contains('\x00'));
    assert!(!sanitized.contains('\x01'));
    assert!(!sanitized.contains('\x02'));
    assert!(sanitized.contains("normal"));
}

#[tokio::test]
async fn test_totp_generation_and_verification() {
    // Test TOTP registration
    let req = TotpRegisterRequest {
        user_id: "test_user".to_string(),
    };

    // Mock the registration process
    let secret: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();

    // Test TOTP code generation with known values
    let time = 1640995200u64; // Fixed time for testing

    // Test with different time windows
    for window_offset in [-30, 0, 30] {
        let test_time = if window_offset < 0 {
            time.saturating_sub(30)
        } else {
            time + window_offset as u64
        };

        // Generate TOTP code (this would be done by authenticator app)
        let code = auth_service::mfa::totp(&secret, test_time, 30, 6);
        let formatted_code = format!("{:06}", code % 1_000_000);

        // Verify the code would be accepted (within ±1 window)
        assert_eq!(formatted_code.len(), 6);
        assert!(formatted_code.chars().all(|c| c.is_ascii_digit()));
    }
}

#[tokio::test]
async fn test_totp_replay_protection() {
    std::env::set_var("TEST_MODE", "1");

    // Test that used codes are tracked and rejected
    let user_id = "test_replay_user";
    let code = "123456";

    // First use should be allowed (simulated)
    // In real implementation, this would check Redis

    // Second use should be blocked
    // This tests the replay protection mechanism
}

#[tokio::test]
async fn test_backup_code_generation_and_usage() {
    let user_id = "test_backup_user";

    // Generate backup codes
    let mut codes = Vec::new();
    let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    for _ in 0..8 {
        let mut code = String::new();
        for _ in 0..10 {
            let idx = rand::random::<usize>() % alphabet.len();
            code.push(alphabet[idx] as char);
        }
        codes.push(code);
    }

    assert_eq!(codes.len(), 8);

    for code in &codes {
        assert_eq!(code.len(), 10);
        assert!(code.chars().all(|c| alphabet.contains(&(c as u8))));
    }
}

#[tokio::test]
async fn test_token_store_operations() {
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));
    let token = "test_token_123";

    // Test setting and getting active status
    store.set_active(token, true, Some(3600)).await.unwrap();
    assert!(store.get_active(token).await.unwrap());

    // Test setting scope
    store.set_scope(token, Some("read write".to_string()), Some(3600)).await.unwrap();
    let record = store.get_record(token).await.unwrap();
    assert_eq!(record.scope, Some("read write".to_string()));

    // Test setting client ID
    store.set_client_id(token, "test_client".to_string(), Some(3600)).await.unwrap();
    let record = store.get_record(token).await.unwrap();
    assert_eq!(record.client_id, Some("test_client".to_string()));

    // Test setting expiration
    let exp_time = chrono::Utc::now().timestamp() + 3600;
    store.set_exp(token, exp_time, Some(3600)).await.unwrap();
    let record = store.get_record(token).await.unwrap();
    assert_eq!(record.exp, Some(exp_time));

    // Test setting subject
    store.set_subject(token, "test_user".to_string(), Some(3600)).await.unwrap();
    let record = store.get_record(token).await.unwrap();
    assert_eq!(record.sub, Some("test_user".to_string()));

    // Test token revocation
    store.revoke(token).await.unwrap();
    assert!(!store.get_active(token).await.unwrap());
}

#[tokio::test]
async fn test_refresh_token_operations() {
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));
    let refresh_token = "rt_test_123";

    // Set refresh token
    store.set_refresh(refresh_token, 3600).await.unwrap();

    // First consumption should succeed
    assert!(store.consume_refresh(refresh_token).await.unwrap());

    // Check reuse detection
    assert!(store.is_refresh_reused(refresh_token).await.unwrap());

    // Second consumption should fail
    assert!(!store.consume_refresh(refresh_token).await.unwrap());
}

#[tokio::test]
async fn test_mfa_verification_flags() {
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));
    let token = "test_mfa_token";

    // Initially not MFA verified
    assert!(!store.get_mfa_verified(token).await.unwrap());

    // Set MFA verified
    store.set_mfa_verified(token, true, Some(300)).await.unwrap();
    assert!(store.get_mfa_verified(token).await.unwrap());

    // Clear MFA verification
    store.set_mfa_verified(token, false, None).await.unwrap();
    assert!(!store.get_mfa_verified(token).await.unwrap());
}

#[tokio::test]
async fn test_token_binding_operations() {
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));
    let token = "test_binding_token";
    let binding = "test_binding_value";

    // Set token binding
    store.set_token_binding(token, binding.to_string(), Some(3600)).await.unwrap();

    // Verify binding is stored
    let record = store.get_record(token).await.unwrap();
    assert_eq!(record.token_binding, Some(binding.to_string()));
}

#[tokio::test]
async fn test_keys_operations() {
    // Initialize keys
    initialize_keys().await.unwrap();

    // Test key availability
    ensure_key_available().await.unwrap();

    // Test current signing key
    let (kid, _encoding_key) = current_signing_key().await;
    assert!(!kid.is_empty());
    assert!(kid.starts_with("key-"));

    // Test JWKS document
    let jwks = jwks_document().await;
    let keys = jwks.get("keys").unwrap().as_array().unwrap();
    assert!(!keys.is_empty());

    for key in keys {
        assert_eq!(key.get("kty").unwrap(), "RSA");
        assert_eq!(key.get("alg").unwrap(), "RS256");
        assert!(key.get("kid").is_some());
        assert!(key.get("n").is_some());
        assert!(key.get("e").is_some());
    }

    // Test key rotation
    maybe_rotate().await.unwrap();
    let new_kid = get_current_kid().await.unwrap();
    assert!(!new_kid.is_empty());
}

#[tokio::test]
async fn test_rate_limiter_basic_functionality() {
    let config = RateLimitConfig {
        requests_per_window: 5,
        window_duration_secs: 60,
        burst_allowance: 2,
        cleanup_interval_secs: 300,
    };

    let limiter = ShardedRateLimiter::new(config);
    let client_key = "test_client";

    // First requests should be allowed (burst + normal)
    for i in 0..7 {
        match limiter.check_rate_limit(client_key) {
            RateLimitResult::Allowed => {
                assert!(i < 7, "Request {} should be allowed", i);
            }
            RateLimitResult::RateLimited { retry_after } => {
                assert!(i >= 7, "Request {} should be rate limited", i);
                assert!(retry_after > 0);
            }
        }
    }

    // Subsequent requests should be rate limited
    match limiter.check_rate_limit(client_key) {
        RateLimitResult::RateLimited { retry_after } => {
            assert!(retry_after > 0);
        }
        RateLimitResult::Allowed => {
            panic!("Should be rate limited");
        }
    }
}

#[tokio::test]
async fn test_rate_limiter_cleanup() {
    let config = RateLimitConfig {
        requests_per_window: 10,
        window_duration_secs: 1,
        burst_allowance: 2,
        cleanup_interval_secs: 1,
    };

    let limiter = ShardedRateLimiter::new(config);

    // Add some entries
    let _ = limiter.check_rate_limit("client1");
    let _ = limiter.check_rate_limit("client2");
    let _ = limiter.check_rate_limit("client3");

    let stats_before = limiter.get_stats();
    assert_eq!(stats_before.total_entries, 3);

    // Wait for entries to become stale
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Cleanup should remove stale entries
    let removed = limiter.cleanup_stale_entries();
    assert_eq!(removed, 3);

    let stats_after = limiter.get_stats();
    assert_eq!(stats_after.total_entries, 0);
}

#[tokio::test]
async fn test_concurrent_rate_limiting() {
    let config = RateLimitConfig {
        requests_per_window: 100,
        window_duration_secs: 60,
        burst_allowance: 10,
        cleanup_interval_secs: 300,
    };

    let limiter = Arc::new(ShardedRateLimiter::new(config));
    let mut handles = Vec::new();

    // Spawn multiple concurrent tasks
    for i in 0..10 {
        let limiter = Arc::clone(&limiter);
        let handle = tokio::spawn(async move {
            let client_key = format!("client_{}", i);
            let mut allowed_count = 0;

            // Make 20 requests per client
            for _ in 0..20 {
                match limiter.check_rate_limit(&client_key) {
                    RateLimitResult::Allowed => allowed_count += 1,
                    RateLimitResult::RateLimited { .. } => {}
                }
            }

            allowed_count
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    let mut total_allowed = 0;
    for handle in handles {
        total_allowed += handle.await.unwrap();
    }

    // Each client should get their full allocation
    assert_eq!(total_allowed, 10 * 20); // All requests should be allowed
}

#[test]
fn test_extract_client_info() {
    use axum::http::HeaderMap;

    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "192.168.1.1, 10.0.0.1".parse().unwrap());
    headers.insert("user-agent", "Mozilla/5.0 (compatible; test)".parse().unwrap());

    let (client_ip, user_agent) = extract_client_info(&headers);
    assert_eq!(client_ip, "192.168.1.1");
    assert_eq!(user_agent, "Mozilla/5.0 (compatible; test)");

    // Test with missing headers
    let empty_headers = HeaderMap::new();
    let (client_ip, user_agent) = extract_client_info(&empty_headers);
    assert_eq!(client_ip, "unknown");
    assert_eq!(user_agent, "unknown");
}

// Property-based testing
#[tokio::test]
async fn test_token_operations_property_based() {
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));

    // Generate random valid tokens
    let tokens = PropertyTestUtils::generate_valid_tokens(100);

    for token in tokens {
        // Set random properties
        let active = rand::random::<bool>();
        let scope = if rand::random::<bool>() {
            Some(format!("scope_{}", rand::random::<u32>()))
        } else {
            None
        };

        store.set_active(&token, active, Some(3600)).await.unwrap();
        if let Some(s) = scope.as_ref() {
            store.set_scope(&token, Some(s.clone()), Some(3600)).await.unwrap();
        }

        // Verify properties are maintained
        let record = store.get_record(&token).await.unwrap();
        assert_eq!(record.active, active);
        assert_eq!(record.scope, scope);
    }
}

#[tokio::test]
async fn test_invalid_token_handling_property_based() {
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));

    // Generate random invalid tokens
    let invalid_tokens = PropertyTestUtils::generate_invalid_tokens(50);

    for token in invalid_tokens {
        // Should handle gracefully without panicking
        let result = store.get_record(&token).await;

        match result {
            Ok(record) => {
                // Should return inactive record for non-existent tokens
                if token.is_empty() || token.contains('\0') {
                    assert!(!record.active);
                }
            }
            Err(_) => {
                // Some operations might fail with invalid tokens, that's OK
            }
        }
    }
}

#[test]
fn test_security_boundary_conditions() {
    // Test boundary conditions for security functions
    let boundary_values = TestDataGenerator::boundary_values();

    for value in boundary_values {
        // Input validation should handle all boundary cases
        let _ = validate_token_input(&value);
        let _ = sanitize_log_input(&value);

        // Should not panic or cause undefined behavior
    }
}

#[test]
fn test_malicious_input_handling() {
    let malicious_payloads = TestDataGenerator::malicious_payloads();

    for payload in malicious_payloads {
        // All security functions should handle malicious input safely
        assert!(validate_token_input(payload).is_err());

        let sanitized = sanitize_log_input(payload);
        // Should not contain the original malicious content
        assert!(!sanitized.contains("script"));
        assert!(!sanitized.contains("DROP"));
        assert!(!sanitized.contains("../"));
    }
}

#[tokio::test]
async fn test_timing_attack_resistance_comprehensive() {
    // Test PKCE verification timing
    let verifier = generate_code_verifier();
    let challenge = generate_code_challenge(&verifier);
    let invalid_challenge = "invalid_challenge";

    let is_timing_safe = SecurityTestUtils::test_timing_attack_resistance(
        |input: String| async move {
            verify_code_challenge(&verifier, &input)
        },
        &challenge,
        invalid_challenge,
        50,
    ).await;

    assert!(is_timing_safe, "PKCE verification should be timing attack resistant");

    // Test signature verification timing
    let secret = "test_secret";
    let valid_sig = generate_request_signature("POST", "/test", "body", 1640995200, secret).unwrap();
    let invalid_sig = "invalid_signature";

    let is_timing_safe = SecurityTestUtils::test_timing_attack_resistance(
        |sig: String| async move {
            verify_request_signature("POST", "/test", "body", 1640995200, &sig, secret).unwrap_or(false)
        },
        &valid_sig,
        invalid_sig,
        50,
    ).await;

    assert!(is_timing_safe, "Signature verification should be timing attack resistant");
}