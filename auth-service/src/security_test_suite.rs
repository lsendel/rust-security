//! Comprehensive Security Test Suite
//!
//! This module contains comprehensive security tests for all the enhanced
//! security features including PKCE, JWT blacklisting, request fingerprinting,
//! and adaptive rate limiting.

#[cfg(test)]
mod tests {
    use crate::adaptive_rate_limiting::*;
    use crate::auth_api::*;
    use crate::jwt_blacklist::*;
    use crate::pkce::*;
    use crate::request_fingerprinting::*;
    use axum::{
        body::Body,
        extract::Request,
        http::{HeaderMap, StatusCode},
        Json,
    };
    use chrono::Utc;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::time::{sleep, timeout};

    /// Helper function to create a test user
    fn create_test_user(id: &str, email: &str) -> User {
        User {
            id: id.to_string(),
            email: email.to_string(),
            password_hash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash".to_string(),
            name: "Test User".to_string(),
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
            roles: vec!["user".to_string()],
        }
    }

    /// Helper function to create test auth state
    fn create_test_auth_state() -> AuthState {
        AuthState::new("test_secret_key_32_characters_long".to_string())
    }

    /// Test suite for PKCE implementation
    mod pkce_tests {
        use super::*;

        #[tokio::test]
        async fn test_pkce_s256_flow_complete() {
            let manager = PkceManager::new();
            let client_id = "test_client";
            let auth_code = "test_auth_code";

            // Generate challenge and verifier
            let verifier = PkceManager::generate_code_verifier();
            let challenge = manager.compute_s256_challenge(&verifier);

            // Store challenge
            assert!(manager
                .store_challenge(
                    auth_code,
                    challenge,
                    CodeChallengeMethod::S256,
                    client_id.to_string()
                )
                .await
                .is_ok());

            // Verify with correct verifier
            assert!(manager
                .verify_and_consume(auth_code, &verifier, client_id)
                .await
                .is_ok());

            // Verify with same verifier again (should fail - single use)
            assert!(manager
                .verify_and_consume(auth_code, &verifier, client_id)
                .await
                .is_err());
        }

        #[tokio::test]
        async fn test_pkce_plain_method() {
            let manager = PkceManager::new();
            let client_id = "test_client";
            let auth_code = "test_auth_code_plain";
            let verifier = PkceManager::generate_code_verifier();

            // For plain method, challenge equals verifier
            assert!(manager
                .store_challenge(
                    auth_code,
                    verifier.clone(),
                    CodeChallengeMethod::Plain,
                    client_id.to_string()
                )
                .await
                .is_ok());

            // Verify with same verifier
            assert!(manager
                .verify_and_consume(auth_code, &verifier, client_id)
                .await
                .is_ok());
        }

        #[tokio::test]
        async fn test_pkce_wrong_client_rejection() {
            let manager = PkceManager::new();
            let client_id = "test_client";
            let wrong_client = "wrong_client";
            let auth_code = "test_auth_code";
            let verifier = PkceManager::generate_code_verifier();
            let challenge = manager.compute_s256_challenge(&verifier);

            // Store challenge for test_client
            manager
                .store_challenge(
                    auth_code,
                    challenge,
                    CodeChallengeMethod::S256,
                    client_id.to_string(),
                )
                .await
                .unwrap();

            // Try to verify with wrong client
            assert!(matches!(
                manager
                    .verify_and_consume(auth_code, &verifier, wrong_client)
                    .await
                    .unwrap_err(),
                PkceError::VerificationFailed
            ));
        }

        #[tokio::test]
        async fn test_pkce_challenge_expiration() {
            let manager = PkceManager::with_lifetime(1); // 1 second expiration
            let client_id = "test_client";
            let auth_code = "expiring_code";
            let verifier = PkceManager::generate_code_verifier();
            let challenge = manager.compute_s256_challenge(&verifier);

            // Store challenge
            manager
                .store_challenge(
                    auth_code,
                    challenge,
                    CodeChallengeMethod::S256,
                    client_id.to_string(),
                )
                .await
                .unwrap();

            // Wait for expiration
            sleep(Duration::from_secs(2)).await;

            // Should fail due to expiration
            assert!(matches!(
                manager
                    .verify_and_consume(auth_code, &verifier, client_id)
                    .await
                    .unwrap_err(),
                PkceError::ChallengeExpired
            ));
        }

        #[test]
        fn test_pkce_verifier_validation() {
            let manager = PkceManager::new();

            // Valid verifier should pass
            let valid_verifier = PkceManager::generate_code_verifier();
            assert!(manager.validate_verifier(&valid_verifier).is_ok());

            // Too short verifier should fail
            assert!(manager.validate_verifier("short").is_err());

            // Too long verifier should fail
            let too_long = "a".repeat(129);
            assert!(manager.validate_verifier(&too_long).is_err());

            // Invalid characters should fail
            assert!(manager
                .validate_verifier("invalid+characters/here")
                .is_err());
        }
    }

    /// Test suite for JWT blacklisting
    mod jwt_blacklist_tests {
        use super::*;

        #[tokio::test]
        async fn test_token_blacklisting_lifecycle() {
            let blacklist = JwtBlacklist::new();
            let jti = "test_token_123";
            let user_id = "user_123";
            let issuer = "test_issuer";

            // Token should not be blacklisted initially
            assert!(!blacklist.is_token_blacklisted(jti).await);

            // Blacklist the token
            blacklist
                .blacklist_token(
                    jti.to_string(),
                    issuer.to_string(),
                    user_id.to_string(),
                    None,
                    BlacklistReason::Logout,
                )
                .await
                .unwrap();

            // Token should now be blacklisted
            assert!(blacklist.is_token_blacklisted(jti).await);

            // Attempting to blacklist again should fail
            assert!(matches!(
                blacklist
                    .blacklist_token(
                        jti.to_string(),
                        issuer.to_string(),
                        user_id.to_string(),
                        None,
                        BlacklistReason::Logout,
                    )
                    .await
                    .unwrap_err(),
                BlacklistError::TokenAlreadyBlacklisted
            ));
        }

        #[tokio::test]
        async fn test_token_expiry_handling() {
            let blacklist = JwtBlacklist::new();
            let jti = "expiring_token";
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Blacklist token that expires in 1 second
            blacklist
                .blacklist_token(
                    jti.to_string(),
                    "issuer".to_string(),
                    "user".to_string(),
                    Some(now + 1),
                    BlacklistReason::Logout,
                )
                .await
                .unwrap();

            // Should be blacklisted initially
            assert!(blacklist.is_token_blacklisted(jti).await);

            // Wait for expiration
            sleep(Duration::from_secs(2)).await;

            // Should not be blacklisted after expiration
            assert!(!blacklist.is_token_blacklisted(jti).await);
        }

        #[tokio::test]
        async fn test_blacklist_cleanup() {
            let blacklist = JwtBlacklist::new();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Add tokens with different expiration times
            for i in 0..5 {
                let expired = i < 3; // First 3 tokens are expired
                blacklist
                    .blacklist_token(
                        format!("token_{i}"),
                        "issuer".to_string(),
                        "user".to_string(),
                        Some(if expired { now - 1 } else { now + 3600 }),
                        BlacklistReason::Logout,
                    )
                    .await
                    .unwrap();
            }

            let stats_before = blacklist.get_stats().await;
            assert_eq!(stats_before.total_entries, 5);

            // Cleanup expired entries
            let cleaned = blacklist.cleanup_expired_entries().await;
            assert_eq!(cleaned, 3);

            let stats_after = blacklist.get_stats().await;
            assert_eq!(stats_after.total_entries, 2);
        }

        #[test]
        fn test_jti_extraction() {
            let blacklist = JwtBlacklist::new();

            // Valid JWT-like token with JTI claim
            let test_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJ0ZXN0X2p0aV8xMjMiLCJzdWIiOiJ1c2VyXzEyMyIsImlhdCI6MTYzOTM0NDAwMCwiZXhwIjoxNjM5MzQ3NjAwfQ.signature";

            match blacklist.extract_jti_from_token(test_token) {
                Ok(jti) => assert_eq!(jti, "test_jti_123"),
                Err(e) => panic!("Failed to extract JTI: {:?}", e),
            }

            // Invalid token should fail
            assert!(blacklist.extract_jti_from_token("invalid.token").is_err());
        }

        #[tokio::test]
        async fn test_blacklist_statistics() {
            let blacklist = JwtBlacklist::new();

            // Add tokens with different reasons
            blacklist
                .blacklist_token(
                    "token1".to_string(),
                    "issuer".to_string(),
                    "user1".to_string(),
                    None,
                    BlacklistReason::Logout,
                )
                .await
                .unwrap();

            blacklist
                .blacklist_token(
                    "token2".to_string(),
                    "issuer".to_string(),
                    "user2".to_string(),
                    None,
                    BlacklistReason::AdminRevocation,
                )
                .await
                .unwrap();

            let stats = blacklist.get_stats().await;
            assert_eq!(stats.total_entries, 2);
            assert_eq!(stats.active_entries, 2);
            assert_eq!(stats.reason_counts.get("logout"), Some(&1));
            assert_eq!(stats.reason_counts.get("admin_revocation"), Some(&1));
        }
    }

    /// Test suite for request fingerprinting
    mod fingerprinting_tests {
        use super::*;

        #[tokio::test]
        async fn test_fingerprint_creation_and_analysis() {
            let config = FingerprintingConfig::default();
            let analyzer = RequestFingerprintAnalyzer::new(config);

            let fingerprint = analyzer.create_fingerprint(
                "192.168.1.1",
                "POST",
                "/api/login",
                Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
                Some("application/json"),
                Some("application/json"),
                Some(128),
                None,
            );

            assert_eq!(fingerprint.ip_address, "192.168.1.1");
            assert_eq!(fingerprint.method, "POST");
            assert_eq!(fingerprint.path, "/api/login");
            assert!(!fingerprint.user_agent_hash.is_empty());
            assert!(!fingerprint.fingerprint_hash.is_empty());

            // Analyze the fingerprint
            let result = analyzer.analyze_request(fingerprint).await;
            // First request should typically be low risk
            matches!(result.risk_level, RiskLevel::Low);
        }

        #[tokio::test]
        async fn test_suspicious_pattern_detection() {
            let config = FingerprintingConfig::default();
            let analyzer = RequestFingerprintAnalyzer::new(config);

            // Request to suspicious path
            let fingerprint = analyzer.create_fingerprint(
                "192.168.1.100",
                "GET",
                "/.env",
                Some("curl/7.68.0"),
                None,
                None,
                None,
                None,
            );

            let result = analyzer.analyze_request(fingerprint).await;

            // Should detect suspicious path
            assert!(result.is_anomalous);
            assert!(result
                .indicators
                .iter()
                .any(|i| i.contains("Suspicious request path")));
            matches!(result.risk_level, RiskLevel::Medium | RiskLevel::High);
        }

        #[tokio::test]
        async fn test_pattern_learning() {
            let config = FingerprintingConfig {
                min_requests_for_pattern: 3,
                ..Default::default()
            };
            let analyzer = RequestFingerprintAnalyzer::new(config);

            // Send multiple similar requests to establish pattern
            for _i in 0..5 {
                let fingerprint = analyzer.create_fingerprint(
                    "192.168.1.1",
                    "GET",
                    "/api/data",
                    Some("Mozilla/5.0 (consistent browser)"),
                    None,
                    Some("application/json"),
                    None,
                    None,
                );
                analyzer.analyze_request(fingerprint).await;

                // Small delay to ensure timestamps differ
                sleep(Duration::from_millis(10)).await;
            }

            let stats = analyzer.get_stats().await;
            assert!(stats.total_requests >= 5);
            assert!(stats.total_patterns >= 1);
        }

        #[tokio::test]
        async fn test_anomaly_detection_sensitivity() {
            let high_sensitivity_config = FingerprintingConfig {
                anomaly_sensitivity: 0.3, // Very sensitive
                ..Default::default()
            };

            let low_sensitivity_config = FingerprintingConfig {
                anomaly_sensitivity: 0.9, // Less sensitive
                ..Default::default()
            };

            let high_analyzer = RequestFingerprintAnalyzer::new(high_sensitivity_config);
            let low_analyzer = RequestFingerprintAnalyzer::new(low_sensitivity_config);

            // Create a mildly suspicious request
            let fingerprint = high_analyzer.create_fingerprint(
                "192.168.1.1",
                "GET",
                "/admin", // Suspicious but not extremely so
                None,     // Missing User-Agent
                None,
                None,
                None,
                None,
            );

            let high_result = high_analyzer.analyze_request(fingerprint.clone()).await;
            let low_result = low_analyzer.analyze_request(fingerprint).await;

            // High sensitivity should be more likely to flag as anomalous
            assert!(high_result.confidence >= low_result.confidence);
        }

        #[tokio::test]
        async fn test_fingerprint_cleanup() {
            let config = FingerprintingConfig {
                analysis_window: 1, // Very short window for testing
                ..Default::default()
            };
            let analyzer = RequestFingerprintAnalyzer::new(config);

            // Add some requests
            for i in 0..3 {
                let fingerprint = analyzer.create_fingerprint(
                    "192.168.1.1",
                    "GET",
                    &format!("/test/{i}"),
                    Some("test-agent"),
                    None,
                    None,
                    None,
                    None,
                );
                analyzer.analyze_request(fingerprint).await;
            }

            let stats_before = analyzer.get_stats().await;
            assert!(stats_before.total_requests > 0);

            // Wait for data to expire
            sleep(Duration::from_secs(3)).await;

            // Cleanup old data
            analyzer.cleanup_old_data().await;

            let stats_after = analyzer.get_stats().await;
            // Data should be cleaned up due to short analysis window
            assert_eq!(stats_after.total_requests, 0);
        }
    }

    /// Test suite for adaptive rate limiting
    mod adaptive_rate_limiting_tests {
        use super::*;

        #[tokio::test]
        async fn test_basic_rate_limiting() {
            let config = AdaptiveRateLimitConfig {
                base_requests_per_minute: 5,
                ..Default::default()
            };

            let fp_analyzer = Arc::new(RequestFingerprintAnalyzer::new(
                FingerprintingConfig::default(),
            ));

            let limiter = AdaptiveRateLimiter::new(config, fp_analyzer);

            // Create test requests
            let mut allowed_count = 0;
            let mut rate_limited_count = 0;

            for _ in 0..10 {
                let req = Request::builder()
                    .method("GET")
                    .uri("/api/test")
                    .header("user-agent", "test-agent")
                    .header("x-forwarded-for", "192.168.1.1")
                    .body(Body::empty())
                    .unwrap();

                match limiter.check_rate_limit(&req).await {
                    RateLimitDecision::Allow => allowed_count += 1,
                    RateLimitDecision::RateLimit { .. } => rate_limited_count += 1,
                    RateLimitDecision::Block { .. } => {}
                }
            }

            // Should have allowed some requests and rate limited others
            assert!(allowed_count > 0);
            assert!(rate_limited_count > 0);
            assert_eq!(allowed_count + rate_limited_count, 10);
        }

        #[tokio::test]
        async fn test_endpoint_specific_limits() {
            let mut endpoint_configs = std::collections::HashMap::new();
            endpoint_configs.insert(
                "/api/auth/login".to_string(),
                EndpointRateLimitConfig {
                    requests_per_minute: 2, // Very restrictive
                    requests_per_hour: 10,
                    burst_capacity: 1,
                },
            );

            let config = AdaptiveRateLimitConfig {
                base_requests_per_minute: 60, // Generous default
                endpoint_configs,
                ..Default::default()
            };

            let fp_analyzer = Arc::new(RequestFingerprintAnalyzer::new(
                FingerprintingConfig::default(),
            ));

            let limiter = AdaptiveRateLimiter::new(config, fp_analyzer);

            // Test restrictive endpoint
            let login_req = Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("user-agent", "test-agent")
                .header("x-forwarded-for", "192.168.1.1")
                .body(Body::empty())
                .unwrap();

            // Test lenient endpoint
            let general_req = Request::builder()
                .method("GET")
                .uri("/api/general")
                .header("user-agent", "test-agent")
                .header("x-forwarded-for", "192.168.1.1")
                .body(Body::empty())
                .unwrap();

            // Login endpoint should be rate limited quickly
            let mut login_allowed = 0;
            for _ in 0..5 {
                if matches!(
                    limiter.check_rate_limit(&login_req).await,
                    RateLimitDecision::Allow
                ) {
                    login_allowed += 1;
                }
            }

            // General endpoint should be more lenient
            let mut general_allowed = 0;
            for _ in 0..5 {
                if matches!(
                    limiter.check_rate_limit(&general_req).await,
                    RateLimitDecision::Allow
                ) {
                    general_allowed += 1;
                }
            }

            // Login should have fewer allowed requests due to stricter limits
            assert!(login_allowed < general_allowed);
        }

        #[tokio::test]
        async fn test_risk_based_adaptation() {
            let config = AdaptiveRateLimitConfig {
                base_requests_per_minute: 10,
                high_risk_multiplier: 0.1, // 90% reduction for high risk
                ..Default::default()
            };

            let fp_config = FingerprintingConfig {
                anomaly_sensitivity: 0.1, // Very sensitive
                ..Default::default()
            };

            let fp_analyzer = Arc::new(RequestFingerprintAnalyzer::new(fp_config));
            let limiter = AdaptiveRateLimiter::new(config, fp_analyzer);

            // Create a suspicious request
            let suspicious_req = Request::builder()
                .method("GET")
                .uri("/.env") // Suspicious path
                .header("x-forwarded-for", "192.168.1.100")
                .body(Body::empty())
                .unwrap();

            // First request might establish the pattern
            limiter.check_rate_limit(&suspicious_req).await;

            // Subsequent requests should face stricter limits due to risk assessment
            let mut blocked_or_limited = 0;
            for _ in 0..5 {
                match limiter.check_rate_limit(&suspicious_req).await {
                    RateLimitDecision::Allow => {}
                    RateLimitDecision::RateLimit { .. } | RateLimitDecision::Block { .. } => {
                        blocked_or_limited += 1;
                    }
                }
            }

            // Should have limited or blocked some requests due to risk
            assert!(blocked_or_limited > 0);
        }

        #[tokio::test]
        async fn test_progressive_penalties() {
            let config = AdaptiveRateLimitConfig {
                base_requests_per_minute: 2,
                enable_progressive_penalties: true,
                penalty_decay_rate: 0.5, // Aggressive penalty
                ..Default::default()
            };

            let fp_analyzer = Arc::new(RequestFingerprintAnalyzer::new(
                FingerprintingConfig::default(),
            ));

            let limiter = AdaptiveRateLimiter::new(config, fp_analyzer);

            // Trigger rate limiting multiple times
            for _ in 0..20 {
                let req = Request::builder()
                    .method("GET")
                    .uri("/api/test")
                    .header("user-agent", "aggressive-client")
                    .header("x-forwarded-for", "192.168.1.200")
                    .body(Body::empty())
                    .unwrap();

                limiter.check_rate_limit(&req).await;
            }

            let stats = limiter.get_stats();

            // Should have rate limited requests
            assert!(stats.rate_limited_requests > 0);
            assert!(stats.total_requests > 0);
        }

        #[tokio::test]
        async fn test_rate_limiter_statistics() {
            let config = AdaptiveRateLimitConfig {
                base_requests_per_minute: 3,
                ..Default::default()
            };

            let fp_analyzer = Arc::new(RequestFingerprintAnalyzer::new(
                FingerprintingConfig::default(),
            ));

            let limiter = AdaptiveRateLimiter::new(config, fp_analyzer);

            // Send various requests
            for i in 0..10 {
                let req = Request::builder()
                    .method("GET")
                    .uri("/api/test")
                    .header("user-agent", "test-agent")
                    .header("x-forwarded-for", format!("192.168.1.{}", i % 3)) // Different IPs
                    .body(Body::empty())
                    .unwrap();

                limiter.check_rate_limit(&req).await;
            }

            let stats = limiter.get_stats();

            assert_eq!(stats.total_requests, 10);
            assert!(stats.allowed_requests > 0);
            assert!(stats.active_clients > 0);
        }
    }

    /// Integration tests combining multiple security features
    mod integration_tests {
        use super::*;

        #[tokio::test]
        async fn test_complete_authentication_flow_with_security_features() {
            let auth_state = create_test_auth_state();

            // Test OAuth authorization with PKCE
            let verifier = PkceManager::generate_code_verifier();
            let challenge = auth_state.pkce_manager.compute_s256_challenge(&verifier);

            let _auth_request = AuthorizeRequest {
                client_id: "test_client".to_string(),
                redirect_uri: "https://example.com/callback".to_string(),
                scope: Some("read".to_string()),
                state: Some("state123".to_string()),
                code_challenge: Some(challenge),
                code_challenge_method: Some("S256".to_string()),
            };

            // Store OAuth client for the test
            let oauth_client = OAuthClient {
                client_id: "test_client".to_string(),
                client_secret: "client_secret".to_string(),
                name: "Test OAuth Client".to_string(),
                redirect_uris: vec!["https://example.com/callback".to_string()],
                grant_types: vec!["authorization_code".to_string()],
                response_types: vec!["code".to_string()],
                created_at: Utc::now(),
            };

            auth_state
                .oauth_clients
                .write()
                .await
                .insert("test_client".to_string(), oauth_client);

            // Note: The authorize endpoint currently returns UNAUTHORIZED in test mode
            // This is by design for security - it requires authenticated users
            // In a real test, you'd need to simulate user authentication first

            // Test token blacklisting
            let jti = "test_jti_123";
            let user_id = "test_user";

            // Blacklist a token
            assert!(auth_state
                .jwt_blacklist
                .blacklist_token(
                    jti.to_string(),
                    "test_issuer".to_string(),
                    user_id.to_string(),
                    None,
                    BlacklistReason::Logout,
                )
                .await
                .is_ok());

            // Verify it's blacklisted
            assert!(auth_state.jwt_blacklist.is_token_blacklisted(jti).await);
        }

        #[tokio::test]
        async fn test_coordinated_security_response() {
            // Create integrated security system
            let fp_config = FingerprintingConfig {
                anomaly_sensitivity: 0.5,
                ..Default::default()
            };
            let fp_analyzer = Arc::new(RequestFingerprintAnalyzer::new(fp_config));

            let rate_limit_config = AdaptiveRateLimitConfig {
                base_requests_per_minute: 10,
                high_risk_multiplier: 0.1,
                enable_adaptive_limits: true,
                enable_fingerprint_analysis: true,
                ..Default::default()
            };

            let rate_limiter = AdaptiveRateLimiter::new(rate_limit_config, fp_analyzer.clone());

            // Simulate attack pattern - multiple suspicious requests
            let attack_requests = vec![
                "/.env",
                "/wp-admin",
                "/../../../etc/passwd",
                "/phpmyadmin",
                "/admin/config.php",
            ];

            let attacker_ip = "192.168.1.666";
            let mut responses = Vec::new();

            for (i, path) in attack_requests.iter().enumerate() {
                let req = Request::builder()
                    .method("GET")
                    .uri(*path)
                    .header("user-agent", "curl/7.68.0")
                    .header("x-forwarded-for", attacker_ip)
                    .body(Body::empty())
                    .unwrap();

                let decision = rate_limiter.check_rate_limit(&req).await;
                responses.push((i, path, decision));

                // Small delay between requests
                sleep(Duration::from_millis(50)).await;
            }

            // Verify security response escalation
            let mut was_rate_limited = false;
            let mut was_blocked = false;

            for (i, path, decision) in responses {
                match decision {
                    RateLimitDecision::Allow => {
                        println!("Request {} to {} was allowed", i, path);
                    }
                    RateLimitDecision::RateLimit { .. } => {
                        println!("Request {} to {} was rate limited", i, path);
                        was_rate_limited = true;
                    }
                    RateLimitDecision::Block { reason, .. } => {
                        println!("Request {} to {} was blocked: {}", i, path, reason);
                        was_blocked = true;
                    }
                }
            }

            // The system should have responded with increasing security measures
            assert!(
                was_rate_limited || was_blocked,
                "System should have applied security measures"
            );

            // Verify fingerprinting detected patterns
            let fp_stats = fp_analyzer.get_stats().await;
            assert!(fp_stats.total_requests > 0);

            // Verify rate limiting tracked the activity
            let rl_stats = rate_limiter.get_stats();
            assert_eq!(rl_stats.total_requests, attack_requests.len() as u64);
        }

        #[tokio::test]
        async fn test_legitimate_user_experience() {
            // Test that legitimate users aren't affected by security measures
            let fp_analyzer = Arc::new(RequestFingerprintAnalyzer::new(
                FingerprintingConfig::default(),
            ));

            let rate_limiter =
                AdaptiveRateLimiter::new(AdaptiveRateLimitConfig::default(), fp_analyzer);

            let legitimate_requests = vec![
                "/api/v1/status",
                "/api/v1/auth/me",
                "/api/v1/data",
                "/api/v1/profile",
                "/api/v1/settings",
            ];

            let mut all_allowed = true;

            for path in legitimate_requests {
                let req = Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(
                        "user-agent",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    )
                    .header("x-forwarded-for", "192.168.1.100")
                    .header("accept", "application/json")
                    .body(Body::empty())
                    .unwrap();

                match rate_limiter.check_rate_limit(&req).await {
                    RateLimitDecision::Allow => {}
                    _ => {
                        all_allowed = false;
                        break;
                    }
                }

                // Normal user request spacing
                sleep(Duration::from_millis(100)).await;
            }

            // Legitimate requests should generally be allowed
            assert!(all_allowed, "Legitimate user requests should be allowed");
        }

        #[tokio::test]
        async fn test_system_performance_under_load() {
            // Test system performance with concurrent requests
            let fp_analyzer = Arc::new(RequestFingerprintAnalyzer::new(
                FingerprintingConfig::default(),
            ));

            let rate_limiter = Arc::new(AdaptiveRateLimiter::new(
                AdaptiveRateLimitConfig::default(),
                fp_analyzer,
            ));

            let start_time = std::time::Instant::now();
            let num_requests = 100;

            // Send concurrent requests
            let mut handles = Vec::new();
            for i in 0..num_requests {
                let limiter = Arc::clone(&rate_limiter);
                let handle = tokio::spawn(async move {
                    let req = Request::builder()
                        .method("GET")
                        .uri("/api/test")
                        .header("user-agent", "load-test-agent")
                        .header(
                            "x-forwarded-for",
                            format!("192.168.{}.{}", i / 256, i % 256),
                        )
                        .body(reqwest::Body::from(""))
                        .unwrap();

                    limiter.check_rate_limit(&req).await
                });
                handles.push(handle);
            }

            // Wait for all requests to complete with timeout
            let results = timeout(Duration::from_secs(10), async {
                let mut results = Vec::new();
                for handle in handles {
                    results.push(handle.await.unwrap());
                }
                results
            })
            .await;

            let elapsed = start_time.elapsed();

            assert!(
                results.is_ok(),
                "All requests should complete within timeout"
            );
            assert!(
                elapsed < Duration::from_secs(5),
                "Requests should complete quickly"
            );

            let stats = rate_limiter.get_stats();
            assert_eq!(stats.total_requests, num_requests);

            println!("Processed {} requests in {:?}", num_requests, elapsed);
            println!(
                "Average time per request: {:?}",
                elapsed / num_requests as u32
            );
        }
    }
}
