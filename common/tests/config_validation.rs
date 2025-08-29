use common::config::{PlatformConfiguration, RateLimitConfig, SecurityConfig};

// Suppress unused dependency warnings for test dependencies
use anyhow as _;
use async_trait as _;
use base64 as _;
use chrono as _;
use constant_time_eq as _;
use deadpool_redis as _;
use hex as _;
use num_cpus as _;
use once_cell as _;
use rand as _;
use redis as _;
use regex as _;
use ring as _;
use serde as _;
use serde_json as _;
use thiserror as _;
use tokio as _;
use tracing as _;
use url as _;
use uuid as _;

#[test]
fn platform_config_validate_defaults_ok() {
    let cfg = PlatformConfiguration::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn platform_config_validate_invalid_env() {
    let cfg = PlatformConfiguration {
        environment: "weird".into(),
        ..Default::default()
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn rate_limit_validate_bounds() {
    let cfg = PlatformConfiguration {
        security: SecurityConfig {
            enable_security_headers: true,
            rate_limit: RateLimitConfig {
                enabled: true,
                requests_per_minute: 0,
            },
        },
        ..Default::default()
    };
    assert!(cfg.validate().is_err());

    let cfg = PlatformConfiguration {
        security: SecurityConfig {
            rate_limit: RateLimitConfig {
                requests_per_minute: 1_000_001,
                ..cfg.security.rate_limit
            },
            ..cfg.security
        },
        ..cfg
    };
    assert!(cfg.validate().is_err());

    let cfg = PlatformConfiguration {
        security: SecurityConfig {
            rate_limit: RateLimitConfig {
                requests_per_minute: 1000,
                ..cfg.security.rate_limit
            },
            ..cfg.security
        },
        ..cfg
    };
    assert!(cfg.validate().is_ok());
}
