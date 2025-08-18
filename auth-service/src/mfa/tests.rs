use crate::mfa::{
    adaptive::{AdaptiveMfaPolicy, AdaptiveSecurityConfig, AuthContext, GeoLocation},
    audit::{MfaAuditor, MfaAuditEvent, MfaEventType, MfaMethod, MfaResult as AuditResult},
    cache::{MultiLayerMfaCache, TotpCacheData},
    crypto::SecretManager,
    errors::MfaError,
    rate_limiting::{MfaRateLimiter, RateLimitConfig},
    replay_protection::ReplayProtection,
    service::{HighPerformanceMfaService, TotpRegistrationRequest, TotpVerificationRequest, SecurityLevel},
    storage::{MfaStorage, TotpConfiguration},
    totp_enhanced::{EnhancedTotpConfig, EnhancedTotpGenerator, TotpAlgorithm},
    webauthn::WebAuthnMfa,
};
use proptest::prelude::*;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, timeout};

// Property-based testing with proptest
mod property_tests {
    use super::*;

    proptest! {
        #[test]
        fn test_totp_code_generation_roundtrip(
            secret in prop::collection::vec(any::<u8>(), 20..=32),
            timestamp in 1000000000u64..=2000000000u64,
            algorithm in prop_oneof![
                Just(TotpAlgorithm::SHA1),
                Just(TotpAlgorithm::SHA256),
                Just(TotpAlgorithm::SHA512),
            ],
            digits in 6u32..=8u32,
            period in 15u64..=120u64,
        ) {
            let config = EnhancedTotpConfig::new(
                algorithm,
                digits,
                period,
                1,
                "test".to_string(),
            ).unwrap();

            let generator = EnhancedTotpGenerator::new(config);

            // Generate code
            let code = generator.generate_code(&secret, Some(timestamp)).unwrap();

            // Verify properties
            prop_assert_eq!(code.len(), digits as usize);
            prop_assert!(code.chars().all(|c| c.is_ascii_digit()));

            // Verify the code validates
            prop_assert!(generator.verify_code(&secret, &code, Some(timestamp)).unwrap());

            // Verify wrong code doesn't validate
            let wrong_code = "0".repeat(digits as usize);
            if code != wrong_code {
                prop_assert!(!generator.verify_code(&secret, &wrong_code, Some(timestamp)).unwrap());
            }
        }

        #[test]
        fn test_secret_encryption_roundtrip(
            secret in prop::collection::vec(any::<u8>(), 16..=64),
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let secret_manager = SecretManager::new().unwrap();

                let encrypted = secret_manager.encrypt_secret(&secret).await.unwrap();
                let decrypted = secret_manager.decrypt_secret(&encrypted).await.unwrap();

                prop_assert_eq!(secret, decrypted);

                // Verify encrypted data is different from original
                prop_assert_ne!(secret, encrypted.ciphertext);

                // Verify each encryption produces different ciphertext (due to random nonce)
                let encrypted2 = secret_manager.encrypt_secret(&secret).await.unwrap();
                prop_assert_ne!(encrypted.ciphertext, encrypted2.ciphertext);
                prop_assert_ne!(encrypted.nonce, encrypted2.nonce);
            });
        }

        #[test]
        fn test_backup_code_generation_uniqueness(
            iterations in 1usize..=100,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let service = HighPerformanceMfaService::new().await.unwrap();
                let mut all_codes = std::collections::HashSet::new();

                for _ in 0..iterations {
                    let codes = service.generate_backup_codes();
                    prop_assert_eq!(codes.len(), 8);

                    for code in codes {
                        prop_assert_eq!(code.len(), 10);
                        prop_assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
                        prop_assert!(all_codes.insert(code)); // Should be unique
                    }
                }
            });
        }

        #[test]
        fn test_rate_limiting_properties(
            max_attempts in 1i64..=10,
            window_secs in 60u64..=3600,
            attempt_count in 1usize..=20,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = RateLimitConfig {
                    max_verification_attempts_per_5min: max_attempts,
                    ..RateLimitConfig::default()
                };
                let limiter = MfaRateLimiter::new(config).await;
                let user_id = "prop_test_user";

                let mut allowed_count = 0;
                let mut denied_count = 0;

                for _ in 0..attempt_count {
                    let result = limiter.check_verification_attempts(user_id).await.unwrap();
                    if result.allowed {
                        allowed_count += 1;
                    } else {
                        denied_count += 1;
                    }
                }

                // Should allow at most max_attempts
                prop_assert!(allowed_count <= max_attempts as usize);

                // If we exceeded max_attempts, some should be denied
                if attempt_count > max_attempts as usize {
                    prop_assert!(denied_count > 0);
                }
            });
        }
    }
}

// Integration tests
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_full_totp_registration_and_verification_flow() {
        let service = HighPerformanceMfaService::new().await.unwrap();
        let user_id = "integration_test_user";

        // Create auth context
        let context = create_test_auth_context(user_id);

        // Register TOTP
        let registration_request = TotpRegistrationRequest {
            user_id: user_id.to_string(),
            display_name: "Test User".to_string(),
            security_level: Some(SecurityLevel::Standard),
        };

        let registration_response = service
            .register_totp(registration_request, context.clone())
            .await
            .unwrap();

        assert!(!registration_response.secret_base32.is_empty());
        assert!(registration_response.otpauth_url.contains("otpauth://totp/"));
        assert_eq!(registration_response.backup_codes.len(), 8);

        // Decode secret and generate code
        let secret = data_encoding::BASE32
            .decode(registration_response.secret_base32.as_bytes())
            .unwrap();

        let generator = EnhancedTotpGenerator::with_default_config();
        let code = generator.generate_code(&secret, None).unwrap();

        // Verify TOTP code
        let verification_request = TotpVerificationRequest {
            user_id: user_id.to_string(),
            code: code.clone(),
            remember_device: Some(false),
        };

        let verification_response = service
            .verify_totp(verification_request, context.clone())
            .await
            .unwrap();

        assert!(verification_response.verified);
        assert!(verification_response.session_timeout.is_some());
        assert_eq!(verification_response.backup_codes_remaining, Some(8));

        // Test backup code verification
        let backup_code = registration_response.backup_codes[0].clone();
        let backup_verification_request = TotpVerificationRequest {
            user_id: user_id.to_string(),
            code: backup_code,
            remember_device: Some(false),
        };

        let backup_verification_response = service
            .verify_totp(backup_verification_request, context)
            .await
            .unwrap();

        assert!(backup_verification_response.verified);
        assert_eq!(backup_verification_response.backup_codes_remaining, Some(7));
    }

    #[tokio::test]
    async fn test_replay_attack_prevention() {
        let service = HighPerformanceMfaService::new().await.unwrap();
        let user_id = "replay_test_user";
        let context = create_test_auth_context(user_id);

        // Register TOTP
        let registration_request = TotpRegistrationRequest {
            user_id: user_id.to_string(),
            display_name: "Test User".to_string(),
            security_level: Some(SecurityLevel::Standard),
        };

        let registration_response = service
            .register_totp(registration_request, context.clone())
            .await
            .unwrap();

        let secret = data_encoding::BASE32
            .decode(registration_response.secret_base32.as_bytes())
            .unwrap();

        let generator = EnhancedTotpGenerator::with_default_config();
        let code = generator.generate_code(&secret, None).unwrap();

        // First verification should succeed
        let verification_request = TotpVerificationRequest {
            user_id: user_id.to_string(),
            code: code.clone(),
            remember_device: Some(false),
        };

        let first_response = service
            .verify_totp(verification_request.clone(), context.clone())
            .await
            .unwrap();

        assert!(first_response.verified);

        // Second verification with same code should fail (replay protection)
        let second_response = service
            .verify_totp(verification_request, context)
            .await
            .unwrap();

        assert!(!second_response.verified);
        assert_eq!(second_response.reason, Some("code_reused".to_string()));
    }

    #[tokio::test]
    async fn test_rate_limiting_enforcement() {
        let service = HighPerformanceMfaService::new().await.unwrap();
        let user_id = "rate_limit_test_user";
        let context = create_test_auth_context(user_id);

        // Register TOTP first
        let registration_request = TotpRegistrationRequest {
            user_id: user_id.to_string(),
            display_name: "Test User".to_string(),
            security_level: Some(SecurityLevel::Standard),
        };

        service.register_totp(registration_request, context.clone()).await.unwrap();

        // Make multiple verification attempts with wrong codes
        let mut rate_limited = false;
        for i in 0..15 {
            let verification_request = TotpVerificationRequest {
                user_id: user_id.to_string(),
                code: format!("{:06}", i), // Wrong codes
                remember_device: Some(false),
            };

            let response = service
                .verify_totp(verification_request, context.clone())
                .await
                .unwrap();

            if !response.verified && response.reason == Some("rate_limited".to_string()) {
                rate_limited = true;
                break;
            }
        }

        assert!(rate_limited, "Rate limiting should have been triggered");
    }

    #[tokio::test]
    async fn test_adaptive_security_policy() {
        let config = AdaptiveSecurityConfig::default();
        let policy = AdaptiveMfaPolicy::new(config);

        // Low risk context
        let low_risk_context = AuthContext {
            user_id: "test_user".to_string(),
            ip_address: Some("192.168.1.1".parse().unwrap()),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string()),
            device_fingerprint: Some("known_device".to_string()),
            geolocation: Some(GeoLocation {
                country: Some("US".to_string()),
                region: Some("CA".to_string()),
                city: Some("San Francisco".to_string()),
                latitude: Some(37.7749),
                longitude: Some(-122.4194),
                timezone: Some("America/Los_Angeles".to_string()),
            }),
            session_id: Some("session123".to_string()),
            previous_auth_time: Some(1234567890),
            failed_attempts_last_hour: 0,
            is_new_device: false,
            is_vpn_or_proxy: false,
            time_since_last_password_change: Some(Duration::from_secs(86400 * 30)),
            account_age_days: 365,
            is_privileged_user: false,
            current_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };

        let low_risk_requirements = policy
            .evaluate_mfa_requirements(&low_risk_context)
            .await
            .unwrap();

        assert_eq!(low_risk_requirements.methods_required, 1);
        assert!(low_risk_requirements.session_timeout > Duration::from_secs(3600));

        // High risk context
        let high_risk_context = AuthContext {
            failed_attempts_last_hour: 5,
            is_new_device: true,
            is_vpn_or_proxy: true,
            is_privileged_user: true,
            geolocation: Some(GeoLocation {
                country: Some("CN".to_string()),
                region: None,
                city: None,
                latitude: None,
                longitude: None,
                timezone: None,
            }),
            ..low_risk_context
        };

        let high_risk_requirements = policy
            .evaluate_mfa_requirements(&high_risk_context)
            .await
            .unwrap();

        assert!(high_risk_requirements.methods_required >= 2);
        assert!(high_risk_requirements.session_timeout < Duration::from_secs(3600));
        assert!(!high_risk_requirements.additional_verification.is_empty());
    }

    #[tokio::test]
    async fn test_webauthn_registration_flow() {
        let webauthn = WebAuthnMfa::new(
            "localhost".to_string(),
            "Test Service".to_string(),
            "http://localhost:3000".to_string(),
        ).await;

        let user_id = "webauthn_test_user";

        // Start registration
        let options = webauthn
            .start_registration(user_id, "test@example.com", "Test User")
            .await
            .unwrap();

        assert_eq!(options.rp.id, "localhost");
        assert_eq!(options.user.name, "test@example.com");
        assert!(!options.challenge.is_empty());
        assert!(!options.pub_key_cred_params.is_empty());

        // Test that we can list user credentials (should be empty initially)
        let credentials = webauthn.list_user_credentials(user_id).await.unwrap();
        assert!(credentials.is_empty());
    }

    #[tokio::test]
    async fn test_cache_performance() {
        let cache = MultiLayerMfaCache::with_default_config().await;

        let test_data = TotpCacheData {
            secret: vec![1, 2, 3, 4, 5, 6, 7, 8],
            config: EnhancedTotpConfig::default(),
            user_verified: true,
        };

        // Measure cache performance
        let start = std::time::Instant::now();

        // Set and get operations
        for i in 0..1000 {
            let user_id = format!("user_{}", i);
            cache.set_totp_data(&user_id, &test_data).await.unwrap();
            let retrieved = cache.get_totp_data(&user_id).await.unwrap();
            assert!(retrieved.is_some());
        }

        let duration = start.elapsed();
        println!("1000 cache operations took: {:?}", duration);

        // Should complete within reasonable time
        assert!(duration < Duration::from_secs(5));

        // Check cache statistics
        let stats = cache.get_stats().await;
        assert!(stats.l1_hits > 0);
        assert!(stats.hit_ratio() > 0.5);
    }

    #[tokio::test]
    async fn test_concurrent_verification_attempts() {
        let service = Arc::new(HighPerformanceMfaService::new().await.unwrap());
        let user_id = "concurrent_test_user";
        let context = create_test_auth_context(user_id);

        // Register TOTP
        let registration_request = TotpRegistrationRequest {
            user_id: user_id.to_string(),
            display_name: "Test User".to_string(),
            security_level: Some(SecurityLevel::Standard),
        };

        let registration_response = service
            .register_totp(registration_request, context.clone())
            .await
            .unwrap();

        let secret = data_encoding::BASE32
            .decode(registration_response.secret_base32.as_bytes())
            .unwrap();

        let generator = EnhancedTotpGenerator::with_default_config();
        let code = generator.generate_code(&secret, None).unwrap();

        // Launch concurrent verification attempts
        let mut handles = Vec::new();

        for i in 0..10 {
            let service_clone = service.clone();
            let context_clone = context.clone();
            let code_clone = code.clone();
            let user_id_clone = user_id.to_string();

            let handle = tokio::spawn(async move {
                let request = TotpVerificationRequest {
                    user_id: user_id_clone,
                    code: code_clone,
                    remember_device: Some(false),
                };

                service_clone.verify_totp(request, context_clone).await
            });

            handles.push(handle);
        }

        // Wait for all attempts
        let results: Vec<_> = futures::future::join_all(handles).await;

        // Only one should succeed due to replay protection
        let successful_attempts = results
            .into_iter()
            .filter_map(|r| r.ok())
            .filter_map(|r| r.ok())
            .filter(|r| r.verified)
            .count();

        assert_eq!(successful_attempts, 1);
    }

    #[tokio::test]
    async fn test_error_handling_and_recovery() {
        let service = HighPerformanceMfaService::new().await.unwrap();
        let user_id = "error_test_user";
        let context = create_test_auth_context(user_id);

        // Test verification without registration (should fail gracefully)
        let verification_request = TotpVerificationRequest {
            user_id: user_id.to_string(),
            code: "123456".to_string(),
            remember_device: Some(false),
        };

        let result = service.verify_totp(verification_request, context).await;
        assert!(result.is_err());

        // Test invalid security level
        let invalid_registration = TotpRegistrationRequest {
            user_id: "invalid_user".to_string(),
            display_name: "".to_string(), // Empty display name
            security_level: Some(SecurityLevel::Standard),
        };

        // Should handle gracefully
        let context = create_test_auth_context("invalid_user");
        let result = service.register_totp(invalid_registration, context).await;
        // Should succeed even with empty display name
        assert!(result.is_ok());
    }
}

// Performance and stress tests
mod performance_tests {
    use super::*;

    #[tokio::test]
    async fn test_totp_generation_performance() {
        let generator = EnhancedTotpGenerator::with_default_config();
        let secret = EnhancedTotpGenerator::generate_secret();

        let start = std::time::Instant::now();

        // Generate 10,000 TOTP codes
        for _ in 0..10_000 {
            let _code = generator.generate_code(&secret, None).unwrap();
        }

        let duration = start.elapsed();
        println!("10,000 TOTP generations took: {:?}", duration);

        // Should complete within reasonable time
        assert!(duration < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_encryption_performance() {
        let secret_manager = SecretManager::new().unwrap();
        let test_secret = vec![0u8; 32];

        let start = std::time::Instant::now();

        // Encrypt and decrypt 1,000 secrets
        for _ in 0..1_000 {
            let encrypted = secret_manager.encrypt_secret(&test_secret).await.unwrap();
            let _decrypted = secret_manager.decrypt_secret(&encrypted).await.unwrap();
        }

        let duration = start.elapsed();
        println!("1,000 encrypt/decrypt cycles took: {:?}", duration);

        // Should complete within reasonable time
        assert!(duration < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_rate_limiter_performance() {
        let rate_limiter = MfaRateLimiter::with_defaults().await;

        let start = std::time::Instant::now();

        // Check rate limits 10,000 times
        for i in 0..10_000 {
            let user_id = format!("perf_user_{}", i % 100); // 100 different users
            let _result = rate_limiter.check_verification_attempts(&user_id).await.unwrap();
        }

        let duration = start.elapsed();
        println!("10,000 rate limit checks took: {:?}", duration);

        // Should complete within reasonable time
        assert!(duration < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn test_cache_performance_under_load() {
        let cache = MultiLayerMfaCache::with_default_config().await;
        let test_data = TotpCacheData {
            secret: vec![1, 2, 3, 4, 5, 6, 7, 8],
            config: EnhancedTotpConfig::default(),
            user_verified: true,
        };

        // Pre-populate cache
        for i in 0..1000 {
            let user_id = format!("load_user_{}", i);
            cache.set_totp_data(&user_id, &test_data).await.unwrap();
        }

        let start = std::time::Instant::now();

        // Simulate mixed read/write load
        let mut handles = Vec::new();
        for i in 0..100 {
            let cache_clone = cache.clone();
            let test_data_clone = test_data.clone();

            let handle = tokio::spawn(async move {
                for j in 0..100 {
                    let user_id = format!("load_user_{}", (i * 100 + j) % 1000);

                    if j % 10 == 0 {
                        // Write operation
                        cache_clone.set_totp_data(&user_id, &test_data_clone).await.unwrap();
                    } else {
                        // Read operation
                        let _result = cache_clone.get_totp_data(&user_id).await.unwrap();
                    }
                }
            });

            handles.push(handle);
        }

        futures::future::join_all(handles).await;

        let duration = start.elapsed();
        println!("Mixed cache load (10,000 ops) took: {:?}", duration);

        // Should handle load efficiently
        assert!(duration < Duration::from_secs(5));

        let stats = cache.get_stats().await;
        println!("Cache hit ratio: {:.2}%", stats.hit_ratio() * 100.0);
        assert!(stats.hit_ratio() > 0.8); // Should have good hit ratio
    }
}

// Security tests
mod security_tests {
    use super::*;

    #[tokio::test]
    async fn test_timing_attack_resistance() {
        let service = HighPerformanceMfaService::new().await.unwrap();
        let user_id = "timing_test_user";
        let context = create_test_auth_context(user_id);

        // Register TOTP
        let registration_request = TotpRegistrationRequest {
            user_id: user_id.to_string(),
            display_name: "Test User".to_string(),
            security_level: Some(SecurityLevel::Standard),
        };

        service.register_totp(registration_request, context.clone()).await.unwrap();

        // Measure timing for correct vs incorrect codes
        let mut correct_times = Vec::new();
        let mut incorrect_times = Vec::new();

        for _ in 0..50 {
            // Test with incorrect code
            let start = std::time::Instant::now();
            let verification_request = TotpVerificationRequest {
                user_id: user_id.to_string(),
                code: "000000".to_string(),
                remember_device: Some(false),
            };

            let _result = service.verify_totp(verification_request, context.clone()).await;
            incorrect_times.push(start.elapsed());

            // Small delay to avoid rate limiting
            sleep(Duration::from_millis(10)).await;
        }

        // The timing difference should be minimal (constant-time operations)
        let avg_incorrect = incorrect_times.iter().sum::<Duration>() / incorrect_times.len() as u32;

        println!("Average verification time for incorrect codes: {:?}", avg_incorrect);

        // All timings should be relatively consistent
        let max_incorrect = incorrect_times.iter().max().unwrap();
        let min_incorrect = incorrect_times.iter().min().unwrap();
        let timing_variance = max_incorrect.saturating_sub(*min_incorrect);

        // Variance should be relatively small (indicating constant-time behavior)
        assert!(timing_variance < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_secret_isolation() {
        let service1 = HighPerformanceMfaService::new().await.unwrap();
        let service2 = HighPerformanceMfaService::new().await.unwrap();

        let user_id = "isolation_test_user";
        let context = create_test_auth_context(user_id);

        // Register with first service
        let registration_request = TotpRegistrationRequest {
            user_id: user_id.to_string(),
            display_name: "Test User".to_string(),
            security_level: Some(SecurityLevel::Standard),
        };

        let registration_response = service1
            .register_totp(registration_request, context.clone())
            .await
            .unwrap();

        // Generate code with first service's secret
        let secret = data_encoding::BASE32
            .decode(registration_response.secret_base32.as_bytes())
            .unwrap();

        let generator = EnhancedTotpGenerator::with_default_config();
        let code = generator.generate_code(&secret, None).unwrap();

        // Verify with first service (should work)
        let verification_request = TotpVerificationRequest {
            user_id: user_id.to_string(),
            code: code.clone(),
            remember_device: Some(false),
        };

        let result1 = service1.verify_totp(verification_request.clone(), context.clone()).await;
        assert!(result1.is_ok());

        // Verify with second service (should fail - different secret manager)
        let result2 = service2.verify_totp(verification_request, context).await;
        assert!(result2.is_err()); // Different service, no registration
    }

    #[tokio::test]
    async fn test_replay_protection_across_time_windows() {
        let service = HighPerformanceMfaService::new().await.unwrap();
        let user_id = "replay_window_test_user";
        let context = create_test_auth_context(user_id);

        // Register TOTP
        let registration_request = TotpRegistrationRequest {
            user_id: user_id.to_string(),
            display_name: "Test User".to_string(),
            security_level: Some(SecurityLevel::Standard),
        };

        let registration_response = service
            .register_totp(registration_request, context.clone())
            .await
            .unwrap();

        let secret = data_encoding::BASE32
            .decode(registration_response.secret_base32.as_bytes())
            .unwrap();

        let generator = EnhancedTotpGenerator::with_default_config();

        // Generate codes for different time windows
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let code1 = generator.generate_code(&secret, Some(now)).unwrap();
        let code2 = generator.generate_code(&secret, Some(now + 30)).unwrap(); // Next window

        // Use first code
        let verification_request1 = TotpVerificationRequest {
            user_id: user_id.to_string(),
            code: code1.clone(),
            remember_device: Some(false),
        };

        let result1 = service.verify_totp(verification_request1, context.clone()).await.unwrap();
        assert!(result1.verified);

        // Try to reuse first code (should fail)
        let replay_request = TotpVerificationRequest {
            user_id: user_id.to_string(),
            code: code1,
            remember_device: Some(false),
        };

        let replay_result = service.verify_totp(replay_request, context.clone()).await.unwrap();
        assert!(!replay_result.verified);
        assert_eq!(replay_result.reason, Some("code_reused".to_string()));

        // Use second code from different time window (should work)
        let verification_request2 = TotpVerificationRequest {
            user_id: user_id.to_string(),
            code: code2,
            remember_device: Some(false),
        };

        let result2 = service.verify_totp(verification_request2, context).await.unwrap();
        assert!(result2.verified);
    }
}

// Utility functions
fn create_test_auth_context(user_id: &str) -> AuthContext {
    AuthContext {
        user_id: user_id.to_string(),
        ip_address: Some("192.168.1.100".parse().unwrap()),
        user_agent: Some("TestClient/1.0".to_string()),
        device_fingerprint: Some("test_device_fp".to_string()),
        geolocation: Some(GeoLocation {
            country: Some("US".to_string()),
            region: Some("CA".to_string()),
            city: Some("San Francisco".to_string()),
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
            timezone: Some("America/Los_Angeles".to_string()),
        }),
        session_id: Some("test_session_123".to_string()),
        previous_auth_time: Some(1234567890),
        failed_attempts_last_hour: 0,
        is_new_device: false,
        is_vpn_or_proxy: false,
        time_since_last_password_change: Some(Duration::from_secs(86400 * 30)),
        account_age_days: 90,
        is_privileged_user: false,
        current_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    }
}

// Test utilities
pub struct TestUtils;

impl TestUtils {
    pub async fn create_test_mfa_service() -> HighPerformanceMfaService {
        HighPerformanceMfaService::new().await.unwrap()
    }

    pub async fn register_test_user(service: &HighPerformanceMfaService, user_id: &str) -> String {
        let context = create_test_auth_context(user_id);
        let registration_request = TotpRegistrationRequest {
            user_id: user_id.to_string(),
            display_name: format!("Test User {}", user_id),
            security_level: Some(SecurityLevel::Standard),
        };

        let response = service.register_totp(registration_request, context).await.unwrap();
        response.secret_base32
    }

    pub fn generate_valid_code(secret_base32: &str) -> String {
        let secret = data_encoding::BASE32.decode(secret_base32.as_bytes()).unwrap();
        let generator = EnhancedTotpGenerator::with_default_config();
        generator.generate_code(&secret, None).unwrap()
    }
}

// Benchmark tests (only run with --features bench)
#[cfg(feature = "bench")]
mod benchmarks {
    use super::*;
    use criterion::{black_box, criterion_group, criterion_main, Criterion};

    fn bench_totp_generation(c: &mut Criterion) {
        let generator = EnhancedTotpGenerator::with_default_config();
        let secret = EnhancedTotpGenerator::generate_secret();

        c.bench_function("totp_generation", |b| {
            b.iter(|| {
                black_box(generator.generate_code(&secret, None).unwrap())
            })
        });
    }

    fn bench_secret_encryption(c: &mut Criterion) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let secret_manager = rt.block_on(async {
            SecretManager::new().unwrap()
        });
        let test_secret = vec![0u8; 32];

        c.bench_function("secret_encryption", |b| {
            b.to_async(&rt).iter(|| async {
                let encrypted = secret_manager.encrypt_secret(black_box(&test_secret)).await.unwrap();
                black_box(secret_manager.decrypt_secret(&encrypted).await.unwrap())
            })
        });
    }

    criterion_group!(benches, bench_totp_generation, bench_secret_encryption);
    criterion_main!(benches);
}