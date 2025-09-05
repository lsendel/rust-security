//! # Input Validation and Fuzzing Framework
//!
//! This crate provides comprehensive input validation, sanitization, and fuzzing capabilities
//! for the Rust Security Platform. It includes:
//!
//! - Security-first input validation with configurable limits
//! - DoS protection mechanisms with rate limiting and input size restrictions
//! - Injection attack prevention (SQL, XSS, Command, Path Traversal)
//! - Comprehensive fuzz testing for all critical parsers
//! - Property-based testing for validation invariants
//! - Performance optimization for validation operations
//! - Structured error handling without information leakage

pub mod dos_protection;
pub mod error_handling;
pub mod fuzzing;
pub mod middleware;
pub mod parsers;
pub mod property_testing;
pub mod sanitization;
pub mod validation;

// Re-export core types
pub use dos_protection::{
    DoSConfig, DoSProtection, InputSizeLimiter, ProtectionMetrics, RateLimiter, ResourceGuard,
};
pub use error_handling::{SecurityError, ValidationError, ValidationResult};
pub use middleware::{
    RequestValidator, SecurityHeaders, SecurityMiddleware, ValidatedExtractor, ValidationMiddleware,
};
pub use parsers::{
    JwtParser, OAuthParser, ParsedResult, ParserConfig, ParserError, SafeParser, ScimParser,
};
pub use sanitization::{SanitizationConfig, SanitizedInput, Sanitizer};
pub use validation::{
    InputLimits, InputType, SecurityValidator, ValidatedInput, ValidationRule, ValidatorConfig,
};

#[cfg(feature = "fuzzing")]
pub use fuzzing::{FuzzConfig, FuzzResult, FuzzTarget, FuzzTestSuite};

#[cfg(feature = "property-testing")]
pub use property_testing::{
    PropertyConfig, PropertyTestResult, PropertyTestSuite, TestStrategy, ValidationProperty,
};

/// Current version of the input validation framework
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default security configuration for production environments
pub fn default_security_config() -> ValidatorConfig {
    ValidatorConfig::production()
}

/// Default development configuration with relaxed limits for testing
pub fn default_dev_config() -> ValidatorConfig {
    ValidatorConfig::development()
}

/// Initialize the input validation framework with default configuration
pub fn init() -> anyhow::Result<()> {
    tracing::info!("Initializing input validation framework v{}", VERSION);

    // Initialize metrics if enabled
    #[cfg(feature = "metrics")]
    {
        prometheus::register(prometheus::Counter::new(
            "input_validation_total",
            "Total number of input validations performed",
        )?)?;
        prometheus::register(prometheus::Histogram::new(
            "input_validation_duration_seconds",
            "Duration of input validation operations",
        )?)?;
    }

    Ok(())
}

/// Initialize with custom configuration
pub fn init_with_config(config: ValidatorConfig) -> anyhow::Result<SecurityValidator> {
    tracing::info!("Initializing input validation framework with custom config");
    SecurityValidator::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_default_configs() {
        let prod_config = default_security_config();
        let dev_config = default_dev_config();

        // Production should be more restrictive
        assert!(prod_config.input_limits.max_length < dev_config.input_limits.max_length);
    }
}
