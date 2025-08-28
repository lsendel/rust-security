use common::config::{PlatformConfiguration, RateLimitConfig, SecurityConfig};

#[test]
fn platform_config_validate_defaults_ok() {
    let cfg = PlatformConfiguration::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn platform_config_validate_invalid_env() {
    let mut cfg = PlatformConfiguration::default();
    cfg.environment = "weird".into();
    assert!(cfg.validate().is_err());
}

#[test]
fn rate_limit_validate_bounds() {
    let mut cfg = PlatformConfiguration::default();
    cfg.security = SecurityConfig {
        enable_security_headers: true,
        rate_limit: RateLimitConfig {
            enabled: true,
            requests_per_minute: 0,
        },
    };
    assert!(cfg.validate().is_err());

    cfg.security.rate_limit.requests_per_minute = 1_000_001;
    assert!(cfg.validate().is_err());

    cfg.security.rate_limit.requests_per_minute = 1000;
    assert!(cfg.validate().is_ok());
}
