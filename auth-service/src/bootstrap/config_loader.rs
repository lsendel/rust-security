//! Configuration Loader
//!
//! This module handles loading and validating application configuration
//! from various sources (environment variables, config files, etc.).

use crate::config::Config;

/// Configuration loader for the auth service
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration from environment and config files
    ///
    /// This method loads configuration in the following order:
    /// 1. Base configuration file (config/base.toml)
    /// 2. Environment-specific configuration file (config/{env}.toml)
    /// 3. Local overrides (config/local.toml)
    /// 4. Environment variables (AUTH_* prefix)
    ///
    /// # Errors
    ///
    /// Returns an error if configuration loading or validation fails.
    pub fn load() -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
        let config = Config::load()?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration for development environment
    ///
    /// This method loads configuration optimized for development
    /// with relaxed security settings and debugging enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration loading fails.
    pub fn load_for_development() -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
        std::env::set_var("APP_ENV", "development");
        Self::load()
    }

    /// Load configuration for production environment
    ///
    /// This method loads configuration optimized for production
    /// with strict security settings and performance optimizations.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration loading fails.
    pub fn load_for_production() -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
        std::env::set_var("APP_ENV", "production");
        Self::load()
    }
}
