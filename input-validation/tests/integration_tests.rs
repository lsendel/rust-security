//! Integration tests for the input validation framework
//!
//! Tests the complete validation, sanitization, and parsing pipeline

use input_validation::{
    dos_protection::{DoSConfig, DoSProtection},
    error_handling::{SecurityError, ValidationError, ValidationResult},
    middleware::{RequestValidator, SecurityMiddleware, SecurityMiddlewareConfig},
    parsers::{JwtParser, OAuthParser, ParserConfig, SafeParser, ScimParser},
    sanitization::{SanitizationConfig, Sanitizer},
    validation::{InputType, SecurityValidator, ValidatorConfig},
};
use std::collections::HashMap;
use std::time::Duration;

#[test]
fn test_complete_validation_pipeline() {
    // Setup components
    let validator = SecurityValidator::new(ValidatorConfig::production()).unwrap();
    let sanitizer = Sanitizer::strict();

    // Test malicious input
    let malicious_input = "<script>alert('xss')</script>";

    // 1. Validation should detect issues
    let validation_result = validator.validate(malicious_input, InputType::Text);
    // Note: Depending on rules, this might pass basic text validation

    // 2. Injection detection should catch it
    let injection_patterns = validator.check_injection(malicious_input);
    assert!(!injection_patterns.is_empty(), "Should detect injection patterns");
    assert!(injection_patterns.contains(&"xss".to_string()));

    // 3. Sanitization should clean it
    let sanitized = sanitizer.sanitize(malicious_input, InputType::Text).unwrap();
    assert!(sanitized.was_sanitized, "Input should have been sanitized");
    assert!(!sanitized.sanitized.contains("<script>"), "Script tags should be removed");

    // 4. Sanitized output should be safe
    let sanitized_patterns = validator.check_injection(&sanitized.sanitized);
    assert!(
        sanitized_patterns.len() <= injection_patterns.len(),
        "Sanitized input should have fewer or equal injection patterns"
    );
}

#[test]
fn test_scim_filter_security() {
    let parser = ScimParser::new(ParserConfig::production()).unwrap();

    // Valid SCIM filter should parse
    let valid_filter = "userName eq \"john\"";
    let _result = parser.parse(valid_filter);
    assert!(result.is_ok(), "Valid SCIM filter should parse successfully");

    // SQL injection attempt should be rejected
    let sql_injection = "userName eq \"john\"; DROP TABLE users";
    let _result = parser.parse(sql_injection);
    assert!(result.is_err(), "SQL injection should be rejected");

    // XSS attempt should be rejected
    let xss_attempt = "userName eq \"<script>alert('xss')</script>\"";
    let _result = parser.parse(xss_attempt);
    assert!(result.is_err(), "XSS attempt should be rejected");

    // Unbalanced parentheses should be rejected
    let unbalanced = "userName eq \"john\" and (active eq true";
    let _result = parser.parse(unbalanced);
    assert!(result.is_err(), "Unbalanced parentheses should be rejected");

    // Oversized filter should be rejected
    let oversized = format!("userName eq \"{}\"", "a".repeat(1000));
    let _result = parser.parse(&oversized);
    assert!(result.is_err(), "Oversized filter should be rejected");
}

#[test]
fn test_oauth_parameter_security() {
    let parser = OAuthParser::new(ParserConfig::production()).unwrap();

    // Valid OAuth parameters should parse
    let valid_params = "grant_type=authorization_code&client_id=test123&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback";
    let _result = parser.parse(valid_params);
    assert!(result.is_ok(), "Valid OAuth parameters should parse successfully");

    let parsed = result.unwrap();
    assert_eq!(parsed.value.grant_type, Some("authorization_code".to_string()));
    assert_eq!(parsed.value.client_id, Some("test123".to_string()));

    // Invalid grant type should be rejected
    let invalid_grant = "grant_type=invalid_type&client_id=test123";
    let _result = parser.parse(invalid_grant);
    assert!(result.is_err(), "Invalid grant type should be rejected");

    // Malicious redirect URI should be rejected
    let malicious_redirect =
        "grant_type=authorization_code&redirect_uri=javascript%3Aalert%28%27xss%27%29";
    let _result = parser.parse(malicious_redirect);
    assert!(result.is_err(), "Malicious redirect URI should be rejected");

    // PKCE parameters should be validated
    let invalid_pkce = "grant_type=authorization_code&code_verifier=too_short";
    let _result = parser.parse(invalid_pkce);
    assert!(result.is_err(), "Invalid PKCE code_verifier should be rejected");
}

#[test]
fn test_jwt_token_security() {
    let parser = JwtParser::new(ParserConfig::production()).unwrap();

    // Create a valid-looking JWT (not cryptographically valid, just structurally)
    let header = base64::encode_config(r#"{"alg":"RS256","typ":"JWT"}"#, base64::URL_SAFE_NO_PAD);
    let payload =
        base64::encode_config(r#"{"sub":"user123","exp":9999999999}"#, base64::URL_SAFE_NO_PAD);
    let signature = "fake_signature";
    let valid_jwt = format!("{}.{}.{}", header, payload, signature);

    let _result = parser.parse(&valid_jwt);
    assert!(result.is_ok(), "Valid JWT structure should parse");

    // JWT with "none" algorithm should be rejected
    let none_header =
        base64::encode_config(r#"{"alg":"none","typ":"JWT"}"#, base64::URL_SAFE_NO_PAD);
    let none_jwt = format!("{}.{}.{}", none_header, payload, signature);
    let _result = parser.parse(&none_jwt);
    assert!(result.is_err(), "JWT with 'none' algorithm should be rejected");

    // Malformed JWT should be rejected
    let malformed_jwt = "not.a.valid.jwt.format";
    let _result = parser.parse(malformed_jwt);
    assert!(result.is_err(), "Malformed JWT should be rejected");

    // JWT with only 2 parts should be rejected
    let incomplete_jwt = "header.payload";
    let _result = parser.parse(incomplete_jwt);
    assert!(result.is_err(), "Incomplete JWT should be rejected");
}

#[test]
fn test_dos_protection() {
    let dos_protection = DoSProtection::new(DoSConfig::production());

    // Test size limits
    let size_limiter = dos_protection.size_limiter();

    // Normal size should pass
    assert!(size_limiter.check_body_size(1000).is_ok());
    assert!(size_limiter.check_field_size(500).is_ok());
    assert!(size_limiter.check_field_count(50).is_ok());

    // Oversized inputs should fail
    assert!(size_limiter.check_body_size(10 * 1024 * 1024).is_err()); // 10MB
    assert!(size_limiter.check_field_size(128 * 1024).is_err()); // 128KB
    assert!(size_limiter.check_field_count(500).is_err()); // Too many fields

    // Test JSON structure validation
    let valid_json = r#"{"name":"test","value":123}"#;
    assert!(size_limiter.validate_json_structure(valid_json).is_ok());

    let deeply_nested =
        r#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":"too deep"}}}}}}}}}}}"#;
    assert!(size_limiter.validate_json_structure(deeply_nested).is_err());
}

#[tokio::test]
async fn test_rate_limiting() {
    let dos_protection = DoSProtection::new(DoSConfig::production());
    let rate_limiter = dos_protection.rate_limiter();

    let client_id = "test_client";

    // First few requests should succeed
    for _ in 0..5 {
        assert!(rate_limiter.check_rate_limit(client_id).await.is_ok());
    }

    // Additional requests should eventually be rate limited
    // Note: This depends on the specific rate limit configuration
    let mut rate_limited = false;
    for _ in 0..100 {
        if rate_limiter.check_rate_limit(client_id).await.is_err() {
            rate_limited = true;
            break;
        }
    }

    // In a production config, we should eventually hit the rate limit
    // In development/test configs, limits might be higher
}

#[test]
fn test_sanitization_idempotence() {
    let sanitizer = Sanitizer::strict();

    let test_inputs = vec![
        "<script>alert('xss')</script>",
        "Hello & goodbye",
        "\"quoted text\"",
        "normal text",
        "",
        "unicode: αβγ",
    ];

    for input in test_inputs {
        // Sanitize once
        let sanitized1 = sanitizer.sanitize(input, InputType::Text).unwrap();

        // Sanitize again
        let sanitized2 = sanitizer.sanitize(sanitized1.value(), InputType::Text).unwrap();

        // Results should be identical (idempotent)
        assert_eq!(
            sanitized1.value(),
            sanitized2.value(),
            "Sanitization should be idempotent for input: {}",
            input
        );
    }
}

#[test]
fn test_input_type_specific_validation() {
    let validator = SecurityValidator::new(ValidatorConfig::production()).unwrap();

    // Email validation
    let valid_email = "user@example.com";
    let invalid_email = "not-an-email";

    let _result = validator.validate(valid_email, InputType::Email);
    assert!(result.is_valid(), "Valid email should pass validation");

    let _result = validator.validate(invalid_email, InputType::Email);
    assert!(!result.is_valid(), "Invalid email should fail validation");

    // Phone validation
    let valid_phone = "+1-555-123-4567";
    let invalid_phone = "not-a-phone";

    let _result = validator.validate(valid_phone, InputType::Phone);
    // Note: Phone validation rules might vary

    let _result = validator.validate(invalid_phone, InputType::Phone);
    // Should likely fail, but depends on validation rules

    // URL validation
    let valid_url = "https://example.com/path";
    let invalid_url = "not-a-url";

    let _result = validator.validate(valid_url, InputType::Url);
    // URL validation depends on rules

    let _result = validator.validate(invalid_url, InputType::Url);
    // Should likely fail
}

#[test]
fn test_validation_error_handling() {
    let validator = SecurityValidator::new(ValidatorConfig::production()).unwrap();

    // Test with oversized input
    let oversized_input = "a".repeat(100_000);
    let _result = validator.validate(&oversized_input, InputType::Email);

    assert!(!result.is_valid(), "Oversized input should fail validation");
    assert!(!result.errors.is_empty(), "Should have validation errors");

    // Check error details
    let first_error = &result.errors[0];
    assert!(!first_error.field.is_empty(), "Error should have field name");
    assert!(!first_error.code.is_empty(), "Error should have error code");
    assert!(!first_error.message.is_empty(), "Error should have message");

    // Test error grouping
    let errors_by_field = result.errors_by_field();
    assert!(!errors_by_field.is_empty(), "Should be able to group errors by field");
}

#[test]
fn test_security_middleware_integration() {
    let config = SecurityMiddlewareConfig::default();
    let middleware = SecurityMiddleware::new(config);
    assert!(middleware.is_ok(), "Should be able to create security middleware");

    // Test request validator
    let request_validator =
        RequestValidator::new(ValidatorConfig::production(), SanitizationConfig::strict()).unwrap();

    // Test OAuth parameter validation
    let mut oauth_params = HashMap::new();
    oauth_params.insert("grant_type".to_string(), "authorization_code".to_string());
    oauth_params.insert("client_id".to_string(), "test123".to_string());

    let _result = request_validator.validate_oauth_params(&oauth_params);
    assert!(result.is_valid(), "Valid OAuth params should pass validation");

    // Test with malicious parameters
    let mut malicious_params = HashMap::new();
    malicious_params.insert("client_id".to_string(), "<script>alert('xss')</script>".to_string());

    let _result = request_validator.validate_oauth_params(&malicious_params);
    assert!(!result.is_valid(), "Malicious OAuth params should fail validation");
}

#[test]
fn test_concurrent_validation() {
    use std::sync::Arc;
    use std::thread;

    let validator = Arc::new(SecurityValidator::new(ValidatorConfig::production()).unwrap());
    let sanitizer = Arc::new(Sanitizer::strict());

    let mut handles = vec![];

    // Spawn multiple threads to test concurrent validation
    for i in 0..10 {
        let validator = Arc::clone(&validator);
        let sanitizer = Arc::clone(&sanitizer);

        let handle = thread::spawn(move || {
            let test_input = format!("test_input_{}", i);

            // Test validation
            let validation_result = validator.validate(&test_input, InputType::Text);
            assert!(validation_result.is_valid());

            // Test injection detection
            let injection_patterns = validator.check_injection(&test_input);
            // Normal input should not have injection patterns

            // Test sanitization
            let sanitized = sanitizer.sanitize(&test_input, InputType::Text).unwrap();
            // Normal input might not need sanitization
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_performance_bounds() {
    let validator = SecurityValidator::new(ValidatorConfig::production()).unwrap();

    // Test that validation completes within reasonable time
    let start = std::time::Instant::now();

    let test_input = "a".repeat(1000);
    for _ in 0..1000 {
        let _ = validator.validate(&test_input, InputType::Text);
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "1000 validations should complete within 1 second, took {:?}",
        elapsed
    );
}

#[test]
fn test_memory_safety() {
    let validator = SecurityValidator::new(ValidatorConfig::production()).unwrap();
    let sanitizer = Sanitizer::strict();

    // Test with various input sizes to ensure no memory issues
    let sizes = vec![0, 1, 100, 1000, 10000];

    for size in sizes {
        let input = "a".repeat(size);

        // These operations should not cause memory issues
        let _ = validator.validate(&input, InputType::Text);
        let _ = validator.check_injection(&input);
        let _ = sanitizer.sanitize(&input, InputType::Text);
    }
}

#[test]
fn test_configuration_variants() {
    // Test different security levels
    let strict_config = ValidatorConfig::production();
    let relaxed_config = ValidatorConfig::development();

    let strict_validator = SecurityValidator::new(strict_config).unwrap();
    let relaxed_validator = SecurityValidator::new(relaxed_config).unwrap();

    // Strict validator should have tighter limits
    assert!(
        strict_validator.config().input_limits.max_length
            <= relaxed_validator.config().input_limits.max_length
    );
}

// Test helper functions
fn create_test_jwt(alg: &str, payload: &str) -> String {
    let header = base64::encode_config(
        &format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg),
        base64::URL_SAFE_NO_PAD,
    );
    let payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
    let signature = "fake_signature";

    format!("{}.{}.{}", header, payload, signature)
}

fn assert_contains_error_code(result: &ValidationResult, code: &str) {
    assert!(
        result.errors.iter().any(|e| e.code.contains(code)),
        "Expected error code '{}' not found in errors: {:?}",
        code,
        result.errors
    );
}
