//! Configuration Module
//!
//! This module handles configuration management including loading,
//! validation, and runtime configuration updates.

pub mod loader;
pub mod runtime;
pub mod validator;

// Re-export main types
pub use loader::{
    ConfigLoader, DatabaseConfig, FeaturesConfig, JwtConfig, MonitoringConfig, OAuthConfig,
    RateLimitingConfig, RedisConfig, SecurityConfig, ServerConfig, ServiceConfig, SessionConfig,
};
pub use runtime::{ConfigWatcher, LoggingConfigWatcher, RuntimeConfig};
pub use validator::ConfigValidator;
