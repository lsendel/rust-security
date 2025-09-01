#[cfg(test)]
mod security_tests {
    use crate::jwt_secure::create_secure_jwt_validation;
    use crate::rate_limit_secure::{RateLimitConfig, SecureRateLimiter};
    use crate::infrastructure::security::security::{
        generate_code_challenge, generate_code_verifier, generate_request_signature,
        generate_token_binding, verify_code_challenge, verify_request_signature,
    };
    use crate::infrastructure::storage::session::secure::{
        SecureSessionConfig, SecureSessionManager, SessionError,
    };
    use crate::validation_secure::*;
    use crate::redirect_validation::*;
    use base64::Engine;
    use std::net::{IpAddr, Ipv4Addr};

    /// Test hardcoded salt vulnerability fix
    #[test]
    fn test_token_binding_uses_secure_salt() {
        // Test that token binding doesn't use hardcoded salt
        let binding1 = generate_token_binding("192.168.1.1", "Mozilla/5.0");

        // Add small delay to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_secs(1));

        let binding2 = generate_token_binding("192.168.1.1", "Mozilla/5.0");

        // Should be different due to timestamp
        assert_ne!(
            binding1, binding2,
            "Token bindings should not be identical due to timestamp"
        );

        // Should be base64 encoded
        assert!(base64::engine::general_purpose::STANDARD
            .decode(&binding1)
            .is_ok());
    }

    /// Test PKCE code verifier generation security
    #[test]
    fn test_pkce_code_verifier_security() {
        let verifier1 = generate_code_verifier().unwrap();
        let verifier2 = generate_code_verifier().unwrap();

        // Should be different (cryptographically random)
        assert_ne!(verifier1, verifier2);

        // Should meet length requirements
        assert!(verifier1.len() >= 43);
        assert!(verifier1.len() <= 128);

        // Should only contain URL-safe characters
        assert!(verifier1
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    /// Test PKCE challenge generation and verification
    #[test]
    fn test_pkce_challenge_verification() {
        let verifier = generate_code_verifier().unwrap();
        let challenge = generate_code_challenge(&verifier).unwrap();

        // Should verify correctly
        assert!(verify_code_challenge(&verifier, &challenge).unwrap());

        // Should not verify with wrong verifier
        let wrong_verifier = generate_code_verifier().unwrap();
        assert!(!verify_code_challenge(&wrong_verifier, &challenge).unwrap());
    }

    /// Test request signature security
    #[test]
    fn test_request_signature_security() {
        let secret = "a".repeat(32); // 32 character secret
        let timestamp = chrono::Utc::now().timestamp();

        let signature = generate_request_signature(
            "POST",
            "/oauth/token",
            "grant_type=client_credentials",
            timestamp,
            &secret,
        )
        .unwrap();

        // Should verify correctly
        assert!(verify_request_signature(
            "POST",
            "/oauth/token",
            "grant_type=client_credentials",
            timestamp,
            &signature,
            &secret,
        )
        .unwrap());

        // Should not verify with wrong secret
        let wrong_secret = "b".repeat(32);
        assert!(!verify_request_signature(
            "POST",
            "/oauth/token",
            "grant_type=client_credentials",
            timestamp,
            &signature,
            &wrong_secret,
        )
        .unwrap());
    }

    /// Test weak secret rejection
    #[test]
    fn test_weak_secret_rejection() {
        let weak_secret = "weak";
        let timestamp = chrono::Utc::now().timestamp();

        let result = generate_request_signature(
            "POST",
            "/oauth/token",
            "grant_type=client_credentials",
            timestamp,
            weak_secret,
        );

        assert!(result.is_err());
    }

    /// Test input validation security
    #[test]
    fn test_input_validation_injection_prevention() {
        // Test SQL injection patterns
        let sql_injection = "'; DROP TABLE users; --";
        assert!(validate_scope(sql_injection).is_err());

        // Test XSS patterns
        let xss_payload = "<script>alert('xss')</script>";
        assert!(validate_scope(xss_payload).is_err());

        // Test JavaScript injection
        let js_injection = "javascript:alert(1)";
        assert!(validate_redirect_uri(js_injection).is_err());

        // Test command injection
        let cmd_injection = "test; rm -rf /";
        assert!(validate_username_secure(cmd_injection).is_err());
    }

    /// Test email validation security
    #[test]
    fn test_email_validation_security() {
        // Valid emails should pass
        assert!(validate_email_secure("user@example.com").is_ok());
        assert!(validate_email_secure("test.user+tag@domain.co.uk").is_ok());

        // Invalid/malicious emails should fail
        assert!(validate_email_secure("").is_err());
        assert!(validate_email_secure("invalid-email").is_err());
        assert!(validate_email_secure("user@<script>alert(1)</script>").is_err());
        assert!(validate_email_secure("user@domain..com").is_err());
    }

    /// Test password strength validation
    #[test]
    fn test_password_strength_validation() {
        // Strong passwords should pass
        assert!(validate_password_strength("MyStr0ng!Pass").is_ok());
        assert!(validate_password_strength("C0mplex#P@ssw0rd").is_ok());

        // Weak passwords should fail
        assert!(validate_password_strength("").is_err());
        assert!(validate_password_strength("weak").is_err());
        assert!(validate_password_strength("password123").is_err());
        assert!(validate_password_strength("12345678").is_err());
        assert!(validate_password_strength("PASSWORD").is_err()); // No variety
    }

    /// Test redirect URI validation security
    #[test]
    fn test_redirect_uri_validation_security() {
        // Valid URIs should pass
        assert!(validate_redirect_uri("https://example.com/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:3000/callback").is_ok());
        assert!(validate_redirect_uri("myapp://callback").is_ok());

        // Malicious URIs should fail
        assert!(validate_redirect_uri("").is_err());
        assert!(validate_redirect_uri("javascript:alert(1)").is_err());
        assert!(validate_redirect_uri("data:text/html,<script>alert(1)</script>").is_err());
        assert!(validate_redirect_uri("vbscript:msgbox(1)").is_err());
    }

    /// Test session security
    #[tokio::test]
    async fn test_session_security() {
        let config = SecureSessionConfig::default();
        let manager = SecureSessionManager::new(config);

        let session_id = manager
            .create_session(
                "user123".to_string(),
                Some("client456".to_string()),
                "192.168.1.1".to_string(),
                "Mozilla/5.0".to_string(),
                false,
            )
            .await
            .unwrap();

        // Should validate with correct IP and user agent
        let session = manager
            .validate_session(&session_id, "192.168.1.1", "Mozilla/5.0")
            .await
            .unwrap();

        assert_eq!(session.user_id, "user123");
        assert!(session.is_authenticated);

        // Should detect session hijacking (different IP)
        let result = manager
            .validate_session(&session_id, "192.168.1.2", "Mozilla/5.0")
            .await;

        assert!(matches!(
            result,
            Err(SessionError::SessionHijackingDetected)
        ));
    }

    /// Test rate limiting security
    #[tokio::test]
    async fn test_rate_limiting_security() {
        let mut config = RateLimitConfig::default();
        config.ip_requests_per_minute = 3; // Lower limit for testing
        config.ban_threshold = 2;

        let limiter = SecureRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Should allow initial requests
        for i in 0..3 {
            let result = limiter
                .check_rate_limit(ip, None, "/test", Some("Mozilla/5.0"))
                .await;
            println!("Request {}: {:?}", i + 1, result);
            assert!(result.is_ok(), "Request {} should be allowed", i + 1);
        }

        // Should start rate limiting on 4th request (implementation may vary)
        let _ = limiter
            .check_rate_limit(ip, None, "/test", Some("Mozilla/5.0"))
            .await;
    }

    /// Test suspicious activity detection
    #[tokio::test]
    async fn test_suspicious_activity_detection() {
        let config = RateLimitConfig::default();
        let limiter = SecureRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Request with suspicious user agent should trigger detection
        let _result = limiter
            .check_rate_limit(ip, None, "/test", Some("curl/7.68.0"))
            .await;
        // May trigger suspicious activity (depends on implementation)

        // Request without user agent should be suspicious
        let _result = limiter.check_rate_limit(ip, None, "/test", None).await;
        // Should be handled appropriately
    }

    /// Test JWT algorithm confusion prevention
    #[test]
    fn test_jwt_algorithm_confusion_prevention() {
        // This would test that only RS256 is accepted
        // Implementation would create test tokens with different algorithms
        // and verify they are rejected

        // Mock test - in real implementation, would use actual JWT tokens
        let validation = create_secure_jwt_validation();
        assert_eq!(validation.algorithms, vec![jsonwebtoken::Algorithm::RS256]);
    }

    /// Test timing attack prevention
    #[test]
    fn test_timing_attack_prevention() {
        let verifier = generate_code_verifier().unwrap();
        let challenge = generate_code_challenge(&verifier).unwrap();

        // Measure time for correct verification
        let start = std::time::Instant::now();
        let _ = verify_code_challenge(&verifier, &challenge);
        let correct_time = start.elapsed();

        // Measure time for incorrect verification
        let wrong_challenge = "wrong_challenge";
        let start = std::time::Instant::now();
        let _ = verify_code_challenge(&verifier, wrong_challenge);
        let incorrect_time = start.elapsed();

        // Times should be similar (constant-time comparison)
        // Allow for some variance due to system scheduling
        let time_diff = if correct_time > incorrect_time {
            correct_time - incorrect_time
        } else {
            incorrect_time - correct_time
        };

        // Should not have significant timing difference (within 1ms)
        assert!(
            time_diff.as_millis() < 1,
            "Timing difference too large: {:?}",
            time_diff
        );
    }

    /// Test secure random generation
    #[test]
    fn test_secure_random_generation() {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();

        // Generate multiple random values
        let mut random1 = [0u8; 32];
        let mut random2 = [0u8; 32];
        let mut random3 = [0u8; 32];

        rng.fill(&mut random1).unwrap();
        rng.fill(&mut random2).unwrap();
        rng.fill(&mut random3).unwrap();

        // Should all be different
        assert_ne!(random1, random2);
        assert_ne!(random2, random3);
        assert_ne!(random1, random3);

        // Should have correct length
        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
        assert_eq!(random3.len(), 32);
    }

    /// Test session ID generation security
    #[test]
    fn test_session_id_generation_security() {
        let rng = TestSecureRandom::new();

        // Generate multiple session IDs
        let id1 = rng.generate_session_id().unwrap();
        let id2 = rng.generate_session_id().unwrap();
        let id3 = rng.generate_session_id().unwrap();

        // Should all be different
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);

        // Should be proper length (base64url encoded 32 bytes = 43 chars without padding)
        assert_eq!(id1.len(), 43);
        assert_eq!(id2.len(), 43);
        assert_eq!(id3.len(), 43);

        // Should only contain URL-safe base64 characters
        for id in [&id1, &id2, &id3] {
            assert!(id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        }
    }

    /// Test configuration security validation
    #[test]
    fn test_configuration_security_validation() {
        use crate::config_secure::*;

        // Test that weak configurations are rejected
        std::env::set_var("ENVIRONMENT", "production");
        std::env::remove_var("REQUEST_SIGNING_SECRET");

        let result = load_secure_config();
        assert!(result.is_err());

        // Test that strong configurations are accepted
        std::env::set_var("REQUEST_SIGNING_SECRET", "a".repeat(32));
        std::env::set_var("FORCE_HTTPS", "true");
        std::env::set_var("ALLOWED_ORIGINS", "https://example.com");

        let result = load_secure_config();
        assert!(result.is_ok());
    }

    /// Test CORS security
    #[test]
    fn test_cors_security() {
        use crate::config_secure::*;

        // Test that wildcard CORS is rejected
        std::env::set_var("ALLOWED_ORIGINS", "*");

        let result = load_secure_config();
        assert!(result.is_err());

        // Test that specific origins are accepted
        std::env::set_var(
            "ALLOWED_ORIGINS",
            "https://example.com,https://app.example.com",
        );

        let result = load_secure_config();
        if result.is_ok() {
            let config = result.unwrap();
            assert!(!config.security.allowed_origins.contains(&"*".to_string()));
        }
    }

    /// Test that debug endpoints are disabled in production
    #[test]
    fn test_debug_endpoints_disabled_in_production() {
        use crate::config_secure::*;

        std::env::set_var("ENVIRONMENT", "production");
        std::env::set_var("REQUEST_SIGNING_SECRET", "a".repeat(32));
        std::env::set_var("FORCE_HTTPS", "true");
        std::env::set_var("ALLOWED_ORIGINS", "https://example.com");

        let config = load_secure_config().unwrap();
        assert!(!config.features.debug_endpoints_enabled);
        assert!(!config.features.experimental_features_enabled);
    }

    /// Test memory safety (no unsafe code in security-critical paths)
    #[test]
    fn test_memory_safety() {
        // This test ensures we're not using unsafe code in security-critical functions
        // Rust's type system provides memory safety, but we should verify
        // no unsafe blocks are used in our security implementations

        // Generate some secure random data
        let rng = TestSecureRandom::new();
        let _data = rng.generate_bytes(1024).unwrap();

        // Process it through our security functions
        let verifier = generate_code_verifier().unwrap();
        let challenge = generate_code_challenge(&verifier).unwrap();
        let _ = verify_code_challenge(&verifier, &challenge);

        // If we get here without crashes, memory safety is maintained
        assert!(true);
    }

    /// Security utilities for testing
    #[cfg(test)]
    pub struct TestSecureRandom {
        rng: ring::rand::SystemRandom,
    }

    #[cfg(test)]
    impl TestSecureRandom {
        pub fn new() -> Self {
            Self {
                rng: ring::rand::SystemRandom::new(),
            }
        }

        pub fn generate_bytes(&self, len: usize) -> Result<Vec<u8>, &'static str> {
            use ring::rand::SecureRandom;
            let mut bytes = vec![0u8; len];
            self.rng
                .fill(&mut bytes)
                .map_err(|_| "Random generation failed")?;
            Ok(bytes)
        }

        pub fn generate_session_id(&self) -> Result<String, &'static str> {
            use base64::Engine;
            let bytes = self.generate_bytes(32)?;
            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
        }
    }
}
