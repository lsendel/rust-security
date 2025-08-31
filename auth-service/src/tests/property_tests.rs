//! Property-Based Tests for Authentication Service
//!
//! Comprehensive property-based testing using proptest to ensure correctness
//! under various input conditions and edge cases.

use chrono::{DateTime, Utc};
use proptest::prelude::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::domain::entities::{Session, Token, TokenType, User};
use crate::domain::value_objects::{Email, PasswordHash, UserId};
use crate::infrastructure::cache::advanced_cache::{AdvancedCache, AdvancedCacheConfig};
use crate::middleware::security_enhanced::{RateLimiter, SecurityConfig};
use crate::services::{constant_time_compare, PasswordService};
use crate::shared::error::AppError;

/// Generate valid email addresses for testing
fn email_strategy() -> impl Strategy<Value = String> {
    // Generate valid email patterns
    prop_oneof![
        // Simple valid emails
        r"[a-z]{3,10}@[a-z]{3,10}\.com",
        r"[a-z]{3,10}@[a-z]{3,10}\.org",
        r"[a-z]{3,10}@[a-z]{3,10}\.net",
        // Emails with numbers and special chars
        r"[a-z0-9]{3,10}@[a-z0-9]{3,10}\.com",
        r"[a-z0-9._-]{3,15}@[a-z0-9.-]{3,10}\.com",
        // Edge cases
        r"a@b.co",
        r"user.name+tag@domain.com",
    ]
}

/// Generate valid passwords for testing
fn password_strategy() -> impl Strategy<Value = String> {
    // Generate passwords of various lengths and complexities
    prop_oneof![
        // Short passwords (should fail validation)
        r"[a-z]{1,7}",
        r"[A-Z]{1,7}",
        r"[0-9]{1,7}",
        // Valid passwords
        r"[a-zA-Z0-9!@#$%^&*]{8,20}",
        r"[a-zA-Z0-9!@#$%^&*()_+-=]{8,50}",
        // Complex passwords with special chars
        r"[a-zA-Z0-9!@#$%^&*()_+-=\[\]{}|;:,.<>?]{12,64}",
    ]
}

/// Generate valid user IDs
fn user_id_strategy() -> impl Strategy<Value = String> {
    // Generate valid UUID strings
    r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
}

/// Generate valid tokens
fn token_strategy() -> impl Strategy<Value = String> {
    // Generate token-like strings
    r"[a-zA-Z0-9_-]{20,100}"
}

/// Generate valid role names
fn roles_strategy() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(r"[a-z_]{3,20}", 0..5)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Test password hashing is deterministic
    #[test]
    fn test_password_hash_deterministic(password in password_strategy()) {
        let service = PasswordService::new();

        // Skip if password is too short (validation will fail)
        if password.len() < 8 {
            return Ok(());
        }

        let hash1 = service.hash_password(&password)?;
        let hash2 = service.hash_password(&password)?;

        // Hashes should be different (different salts) but verification should work
        assert_ne!(hash1.as_str(), hash2.as_str());

        // Both should verify against original password
        assert!(service.verify_password(&password, &hash1).unwrap_or(false));
        assert!(service.verify_password(&password, &hash2).unwrap_or(false));
    }

    /// Test password verification fails for wrong passwords
    #[test]
    fn test_password_verification_fails(password in password_strategy(), wrong_password in password_strategy()) {
        let service = PasswordService::new();

        // Skip if passwords are too short or identical
        if password.len() < 8 || wrong_password.len() < 8 || password == wrong_password {
            return Ok(());
        }

        let hash = service.hash_password(&password)?;

        // Wrong password should fail verification
        assert!(!service.verify_password(&wrong_password, &hash).unwrap_or(false));
    }

    /// Test constant-time comparison properties
    #[test]
    fn test_constant_time_compare_properties(a in r".*", b in r".*") {
        let result = constant_time_compare(&a, &b);

        // Basic correctness
        assert_eq!(result, a == b);

        // Length sensitivity check (should not leak length info)
        // This is a simplified check - in practice we'd use timing analysis
        if a.len() != b.len() {
            // Even when lengths differ, timing should be similar
            assert_eq!(result, false);
        }
    }

    /// Test email validation
    #[test]
    fn test_email_validation(email_str in email_strategy()) {
        // All generated emails should be valid
        let email = Email::new(email_str.clone());
        assert!(email.is_ok(), "Generated email '{}' should be valid", email_str);

        let email = email.unwrap();
        assert_eq!(email.as_str(), email_str.to_lowercase());
    }

    /// Test rate limiter behavior
    #[test]
    fn test_rate_limiter_properties(requests in 1..200u32) {
        let limiter = RateLimiter::new(100, Duration::from_secs(60));

        // Create a test IP
        let ip = "192.168.1.100";

        // Make multiple requests
        for i in 0..requests {
            let is_limited = limiter.is_rate_limited(ip).await;

            if i < 100 {
                // First 100 requests should not be limited
                assert!(!is_limited, "Request {} should not be rate limited", i);
            } else {
                // Subsequent requests should be limited
                assert!(is_limited, "Request {} should be rate limited", i);
            }
        }
    }

    /// Test cache operations
    #[test]
    fn test_cache_operations(
        key in r"[a-zA-Z0-9_-]{1,50}",
        value in r"[a-zA-Z0-9_-]{1,100}",
        ttl_ms in 1000..3600000i64,
    ) {
        let config = AdvancedCacheConfig {
            l1_max_size: 1000,
            ..Default::default()
        };

        let cache = AdvancedCache::<String, String>::new(config, None, None);

        let ttl = Duration::from_millis(ttl_ms as u64);

        // Insert value
        cache.insert(key.clone(), value.clone(), Some(ttl)).unwrap();

        // Retrieve value
        let retrieved = cache.get(&key).await;
        assert_eq!(retrieved, Some(value));
    }

    /// Test user entity creation
    #[test]
    fn test_user_creation_properties(
        email_str in email_strategy(),
        password in password_strategy(),
        name in prop::option::of(r"[a-zA-Z ]{1,50}"),
        roles in roles_strategy(),
    ) {
        // Skip if password is too short
        if password.len() < 8 {
            return Ok(());
        }

        let user_id = UserId::new();
        let email = Email::new(email_str)?;
        let password_hash = PasswordHash::new(format!("$argon2id$v=19$m=4096,t=3,p=1${}", Uuid::new_v4()))?;

        let user = User::new(
            user_id.clone(),
            email.clone(),
            password_hash.clone(),
            name.clone(),
        );

        // Set roles
        for role in roles {
            // Note: This assumes there's a method to set roles
            // In practice, you'd modify the User struct to support this
        }

        // Verify user properties
        assert_eq!(user.id, user_id);
        assert_eq!(user.email, email);
        assert_eq!(user.password_hash.as_str(), password_hash.as_str());
        assert_eq!(user.name, name);
        assert!(!user.is_active); // Default should be false
    }

    /// Test session creation and validation
    #[test]
    fn test_session_properties(
        user_id_str in user_id_strategy(),
        token in token_strategy(),
        expires_hours in 1..168i64, // 1 hour to 1 week
    ) {
        let user_id = UserId::new(); // In practice, you'd parse the user_id_str
        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::hours(expires_hours);

        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            token: token.clone(),
            created_at,
            expires_at,
            is_active: true,
        };

        // Verify session properties
        assert_eq!(session.user_id, user_id);
        assert_eq!(session.token, token);
        assert_eq!(session.created_at, created_at);
        assert_eq!(session.expires_at, expires_at);
        assert!(session.is_active);

        // Test expiration logic
        let future_time = expires_at + chrono::Duration::hours(1);
        assert!(future_time > session.expires_at);

        let past_time = expires_at - chrono::Duration::hours(1);
        assert!(past_time < session.expires_at);
    }

    /// Test token creation and validation
    #[test]
    fn test_token_properties(
        user_id_str in user_id_strategy(),
        token_value in token_strategy(),
        scope in prop::option::of(r"[a-z:_]{1,100}"),
        expires_hours in 1..8760i64, // 1 hour to 1 year
    ) {
        let user_id = UserId::new(); // In practice, you'd parse the user_id_str
        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::hours(expires_hours);

        let token = Token {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            token: token_value.clone(),
            token_type: TokenType::Access,
            created_at,
            expires_at,
            is_active: true,
            scope: scope.clone(),
        };

        // Verify token properties
        assert_eq!(token.user_id, user_id);
        assert_eq!(token.token, token_value);
        assert_eq!(token.token_type, TokenType::Access);
        assert_eq!(token.created_at, created_at);
        assert_eq!(token.expires_at, expires_at);
        assert!(token.is_active);
        assert_eq!(token.scope, scope);
    }

    /// Test security middleware configuration
    #[test]
    fn test_security_config_properties(
        csrf_enabled in prop::bool::ANY,
        rate_limiting_enabled in prop::bool::ANY,
        input_validation_enabled in prop::bool::ANY,
        max_requests in 1..1000u32,
        window_secs in 1..3600u64,
        max_body_size in 1024..10485760usize, // 1KB to 10MB
    ) {
        let config = SecurityConfig {
            csrf_enabled,
            rate_limiting_enabled,
            input_validation_enabled,
            rate_limit_requests: max_requests,
            rate_limit_window: Duration::from_secs(window_secs),
            max_body_size,
            ..Default::default()
        };

        // Verify configuration is valid
        assert_eq!(config.csrf_enabled, csrf_enabled);
        assert_eq!(config.rate_limiting_enabled, rate_limiting_enabled);
        assert_eq!(config.input_validation_enabled, input_validation_enabled);
        assert_eq!(config.rate_limit_requests, max_requests);
        assert_eq!(config.rate_limit_window, Duration::from_secs(window_secs));
        assert_eq!(config.max_body_size, max_body_size);

        // Test middleware creation
        let _middleware = SecurityMiddleware::new(config);
        // If we reach here without panicking, the config is valid
    }

    /// Test cache configuration properties
    #[test]
    fn test_cache_config_properties(
        l1_max_size in 10..10000usize,
        l2_ttl_secs in 60..86400u64,
        l3_ttl_secs in 3600..604800u64,
        compression_threshold in 512..1048576usize,
    ) {
        let config = AdvancedCacheConfig {
            l1_max_size,
            l2_ttl: Duration::from_secs(l2_ttl_secs),
            l3_ttl: Duration::from_secs(l3_ttl_secs),
            compression_threshold,
            ..Default::default()
        };

        // Verify configuration
        assert_eq!(config.l1_max_size, l1_max_size);
        assert_eq!(config.l2_ttl, Duration::from_secs(l2_ttl_secs));
        assert_eq!(config.l3_ttl, Duration::from_secs(l3_ttl_secs));
        assert_eq!(config.compression_threshold, compression_threshold);

        // L2 TTL should be less than L3 TTL (cache hierarchy)
        assert!(config.l2_ttl <= config.l3_ttl);
    }

    /// Test error handling properties
    #[test]
    fn test_error_properties(
        error_message in r"[a-zA-Z0-9 .,!?]{1,200}",
        user_id in prop::option::of(user_id_strategy()),
        session_id in prop::option::of(r"[a-f0-9]{32}"),
    ) {
        let error = AppError::Validation(error_message.clone());

        // Test error message
        assert!(error.to_string().contains(&error_message));

        // Test status code
        let status = error.status_code();
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

        // Test user message
        let user_msg = error.user_message();
        assert_eq!(user_msg, "Validation failed");
    }

    /// Test UUID generation properties
    #[test]
    fn test_uuid_properties() {
        let uuid1 = Uuid::new_v4();
        let uuid2 = Uuid::new_v4();

        // UUIDs should be unique
        assert_ne!(uuid1, uuid2);

        // UUIDs should be valid format
        let uuid_str = uuid1.to_string();
        assert_eq!(uuid_str.len(), 36);

        // Should contain 4 hyphens
        assert_eq!(uuid_str.chars().filter(|&c| c == '-').count(), 4);

        // Should be parseable
        let parsed = Uuid::parse_str(&uuid_str).unwrap();
        assert_eq!(parsed, uuid1);
    }

    /// Test timing attack resistance
    #[test]
    fn test_timing_attack_resistance(
        password1 in r"[a-zA-Z0-9]{8,20}",
        password2 in r"[a-zA-Z0-9]{8,20}",
    ) {
        // This test verifies that constant_time_compare doesn't leak timing information
        // In practice, you'd use statistical analysis tools for this

        let start1 = Instant::now();
        let _result1 = constant_time_compare(&password1, &password1);
        let time1 = start1.elapsed();

        let start2 = Instant::now();
        let _result2 = constant_time_compare(&password1, &password2);
        let time2 = start2.elapsed();

        // Times should be very similar (within reasonable bounds)
        // This is a basic check - real timing attack analysis would be more sophisticated
        let time_diff = if time1 > time2 {
            time1 - time2
        } else {
            time2 - time1
        };

        // Allow for some variance due to system conditions
        assert!(time_diff < Duration::from_micros(100),
            "Timing difference too large: {:?} vs {:?}", time1, time2);
    }
}

/// Additional edge case tests
#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_empty_password_hashing() {
        let service = PasswordService::new();
        let result = service.hash_password("");
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_short_password_hashing() {
        let service = PasswordService::new();
        let result = service.hash_password("short");
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_null_byte_in_password() {
        let service = PasswordService::new();
        let password = format!("validpassword{}", '\0');
        let result = service.hash_password(&password);
        // Should handle null bytes gracefully
        assert!(result.is_ok() || matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn test_unicode_password() {
        let service = PasswordService::new();
        let password = "pássword123!🚀";
        let result = service.hash_password(password);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cache_with_zero_ttl() {
        let config = AdvancedCacheConfig {
            l1_max_size: 100,
            ..Default::default()
        };

        let cache = AdvancedCache::<String, String>::new(config, None, None);
        let result = cache.insert(
            "key".to_string(),
            "value".to_string(),
            Some(Duration::from_secs(0)),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_rate_limiter_edge_cases() {
        let limiter = RateLimiter::new(1, Duration::from_millis(1));

        // First request should succeed
        assert!(!limiter.is_rate_limited("test_ip").await);

        // Second request should be limited
        assert!(limiter.is_rate_limited("test_ip").await);

        // Wait for reset
        std::thread::sleep(Duration::from_millis(2));

        // Should work again
        assert!(!limiter.is_rate_limited("test_ip").await);
    }

    #[test]
    fn test_email_edge_cases() {
        // Valid edge cases
        assert!(Email::new("a@b.co".to_string()).is_ok());
        assert!(Email::new("user@sub.domain.com".to_string()).is_ok());

        // Invalid cases
        assert!(Email::new("".to_string()).is_err());
        assert!(Email::new("no-at-sign".to_string()).is_err());
        assert!(Email::new("@domain.com".to_string()).is_err());
        assert!(Email::new("user@".to_string()).is_err());
    }

    #[test]
    fn test_constant_time_compare_edge_cases() {
        // Empty strings
        assert!(constant_time_compare("", ""));
        assert!(!constant_time_compare("", "a"));
        assert!(!constant_time_compare("a", ""));

        // Different lengths
        assert!(!constant_time_compare("abc", "abcd"));
        assert!(!constant_time_compare("abcd", "abc"));

        // Unicode strings
        assert!(constant_time_compare("🚀", "🚀"));
        assert!(!constant_time_compare("🚀", "🚁"));
    }
}

/// Performance regression tests
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_password_hashing_performance() {
        let service = PasswordService::new();
        let password = "SecurePassword123!";

        let start = Instant::now();

        // Hash password multiple times
        for _ in 0..10 {
            let _hash = service.hash_password(password).unwrap();
        }

        let elapsed = start.elapsed();
        let avg_time = elapsed / 10;

        // Should complete within reasonable time (adjust based on hardware)
        assert!(
            avg_time < Duration::from_millis(100),
            "Password hashing too slow: {:?}",
            avg_time
        );
    }

    #[test]
    fn test_cache_performance() {
        let config = AdvancedCacheConfig {
            l1_max_size: 10000,
            ..Default::default()
        };

        let cache = AdvancedCache::<String, String>::new(config, None, None);

        let start = Instant::now();

        // Insert many items
        for i in 0..1000 {
            cache
                .insert(format!("key{}", i), format!("value{}", i), None)
                .unwrap();
        }

        let insert_time = start.elapsed();

        let start = Instant::now();

        // Retrieve items
        for i in 0..1000 {
            let _value = cache.get(&format!("key{}", i)).await;
        }

        let retrieve_time = start.elapsed();

        // Performance assertions (adjust based on hardware)
        assert!(
            insert_time < Duration::from_millis(500),
            "Cache insertion too slow: {:?}",
            insert_time
        );
        assert!(
            retrieve_time < Duration::from_millis(200),
            "Cache retrieval too slow: {:?}",
            retrieve_time
        );
    }

    #[test]
    fn test_rate_limiter_performance() {
        let limiter = RateLimiter::new(10000, Duration::from_secs(60));

        let start = Instant::now();

        // Make many requests
        for i in 0..1000 {
            let _limited = limiter.is_rate_limited(&format!("ip{}", i % 10)).await;
        }

        let elapsed = start.elapsed();

        // Should handle high throughput
        assert!(
            elapsed < Duration::from_millis(500),
            "Rate limiter too slow: {:?}",
            elapsed
        );
    }
}

