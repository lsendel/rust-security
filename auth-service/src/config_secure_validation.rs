//! Secure Configuration Validation Module
//!
//! This module provides secure validation and loading of environment variables
//! to prevent configuration injection and ensure secure defaults.

use std::fmt;

/// Application environment types
#[derive(Debug, Clone, PartialEq)]
pub enum AppEnvironment {
    Development,
    Production,
    Test,
}

impl AppEnvironment {
    pub fn is_production(&self) -> bool {
        matches!(self, AppEnvironment::Production)
    }
}

impl fmt::Display for AppEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppEnvironment::Development => write!(f, "development"),
            AppEnvironment::Production => write!(f, "production"),
            AppEnvironment::Test => write!(f, "test"),
        }
    }
}

/// Configuration validation errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Required environment variable '{0}' is missing")]
    Missing(&'static str),

    #[error("Environment variable '{var}' has invalid value: {reason}")]
    Invalid { var: &'static str, reason: String },

    #[error("Security validation failed: {0}")]
    Security(String),
}

/// Secure application configuration
#[derive(Debug, Clone)]
pub struct SecureConfig {
    pub jwt_secret: String,
    pub app_env: AppEnvironment,
    pub enable_mfa: bool,
    pub token_binding_salt: Option<String>,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub allowed_origins: Vec<String>,
    pub policy_fail_open: bool,
}

impl SecureConfig {
    /// Load configuration from environment variables with security validation
    pub fn from_env() -> Result<Self, ConfigError> {
        // JWT Secret - Critical for security
        let jwt_secret =
            std::env::var("JWT_SECRET").map_err(|_| ConfigError::Missing("JWT_SECRET"))?;

        if jwt_secret.len() < 32 {
            return Err(ConfigError::Invalid {
                var: "JWT_SECRET",
                reason: "must be at least 32 characters".to_string(),
            });
        }

        // Check for common weak secrets
        let weak_secrets = [
            "secret",
            "password",
            "default",
            "fallback-secret-key",
            "dev-secret",
        ];
        if weak_secrets.iter().any(|&weak| jwt_secret.contains(weak)) {
            return Err(ConfigError::Security(
                "JWT_SECRET appears to contain weak or default values".to_string(),
            ));
        }

        // Application Environment
        let app_env = match std::env::var("APP_ENV").as_deref() {
            Ok("production") => AppEnvironment::Production,
            Ok("development") => AppEnvironment::Development,
            Ok("test") => AppEnvironment::Test,
            Ok(other) => {
                return Err(ConfigError::Invalid {
                    var: "APP_ENV",
                    reason: format!("unknown environment '{}'", other),
                })
            }
            Err(_) => AppEnvironment::Development, // Safe default
        };

        // MFA Configuration - Secure default is enabled
        let enable_mfa = match std::env::var("ENABLE_MFA").as_deref() {
            Ok("true") => true,
            Ok("false") => {
                if app_env.is_production() {
                    tracing::warn!(
                        target: "security_config",
                        "MFA is disabled in production environment"
                    );
                }
                false
            }
            Ok(other) => {
                return Err(ConfigError::Invalid {
                    var: "ENABLE_MFA",
                    reason: format!("must be 'true' or 'false', got '{}'", other),
                })
            }
            Err(_) => true, // Secure default: enable MFA
        };

        // Token Binding Salt - Optional but validated if present
        let token_binding_salt = match std::env::var("TOKEN_BINDING_SALT") {
            Ok(salt) if salt.len() >= 32 => Some(salt),
            Ok(_) => {
                return Err(ConfigError::Invalid {
                    var: "TOKEN_BINDING_SALT",
                    reason: "must be at least 32 characters if provided".to_string(),
                })
            }
            Err(_) => None,
        };

        // Database URL - Validated for security
        let database_url = std::env::var("DATABASE_URL").ok();
        if let Some(ref url) = database_url {
            if url.contains("password=")
                && !url.starts_with("postgresql://")
                && !url.starts_with("postgres://")
            {
                tracing::warn!(
                    target: "security_config",
                    "Database URL may contain plaintext password"
                );
            }
        }

        // Redis URL - Validated for security
        let redis_url = std::env::var("REDIS_URL").ok();
        if let Some(ref url) = redis_url {
            if url.contains("@") && !url.starts_with("redis://") && !url.starts_with("rediss://") {
                return Err(ConfigError::Security(
                    "Redis URL format appears invalid or insecure".to_string(),
                ));
            }
        }

        // Allowed Origins - Parsed and validated
        let allowed_origins = match std::env::var("ALLOWED_ORIGINS") {
            Ok(origins) => {
                let parsed: Vec<String> = origins
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                // Validate each origin
                for origin in &parsed {
                    if origin == "*" && app_env.is_production() {
                        return Err(ConfigError::Security(
                            "Wildcard CORS origin '*' not allowed in production".to_string(),
                        ));
                    }

                    // Basic URL validation
                    if !origin.starts_with("http://")
                        && !origin.starts_with("https://")
                        && origin != "*"
                    {
                        return Err(ConfigError::Invalid {
                            var: "ALLOWED_ORIGINS",
                            reason: format!("invalid origin format: {}", origin),
                        });
                    }
                }

                parsed
            }
            Err(_) => vec![], // Default to no origins (most secure)
        };

        // Policy Fail Open - Secure default is false (closed)
        let policy_fail_open = match std::env::var("POLICY_FAIL_OPEN").as_deref() {
            Ok("1") | Ok("true") => {
                if app_env.is_production() {
                    tracing::warn!(
                        target: "security_config",
                        "POLICY_FAIL_OPEN is enabled in production - security policies will allow access if policy service is unavailable"
                    );
                }
                true
            }
            Ok("0") | Ok("false") => false,
            Ok(other) => {
                return Err(ConfigError::Invalid {
                    var: "POLICY_FAIL_OPEN",
                    reason: format!("must be '0', '1', 'true', or 'false', got '{}'", other),
                })
            }
            Err(_) => false, // Secure default: fail closed
        };

        Ok(SecureConfig {
            jwt_secret,
            app_env,
            enable_mfa,
            token_binding_salt,
            database_url,
            redis_url,
            allowed_origins,
            policy_fail_open,
        })
    }

    /// Validate configuration for production readiness
    pub fn validate_production_ready(&self) -> Result<(), ConfigError> {
        if !self.app_env.is_production() {
            return Ok(());
        }

        // Production-specific security requirements
        if self.jwt_secret.len() < 64 {
            return Err(ConfigError::Security(
                "JWT_SECRET should be at least 64 characters in production".to_string(),
            ));
        }

        if !self.enable_mfa {
            return Err(ConfigError::Security(
                "MFA must be enabled in production".to_string(),
            ));
        }

        if self.token_binding_salt.is_none() {
            return Err(ConfigError::Security(
                "TOKEN_BINDING_SALT must be set in production".to_string(),
            ));
        }

        if self.policy_fail_open {
            return Err(ConfigError::Security(
                "POLICY_FAIL_OPEN should not be enabled in production".to_string(),
            ));
        }

        Ok(())
    }

    /// Log security-relevant configuration (without sensitive values)
    pub fn log_security_status(&self) {
        tracing::info!(
            target: "security_config",
            environment = %self.app_env,
            mfa_enabled = self.enable_mfa,
            token_binding_configured = self.token_binding_salt.is_some(),
            cors_origins_count = self.allowed_origins.len(),
            policy_fail_open = self.policy_fail_open,
            "Security configuration loaded"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_jwt_secret_detection() {
        std::env::set_var("JWT_SECRET", "fallback-secret-key-extended-to-32-chars");

        let result = SecureConfig::from_env();
        assert!(matches!(result, Err(ConfigError::Security(_))));
    }

    #[test]
    fn test_production_wildcard_cors_rejection() {
        std::env::set_var(
            "JWT_SECRET",
            "very-secure-secret-key-at-least-32-characters-long",
        );
        std::env::set_var("APP_ENV", "production");
        std::env::set_var("ALLOWED_ORIGINS", "*");

        let result = SecureConfig::from_env();
        assert!(matches!(result, Err(ConfigError::Security(_))));
    }

    #[test]
    fn test_secure_configuration_valid() {
        std::env::set_var(
            "JWT_SECRET",
            "very-secure-jwt-key-at-least-32-characters-long-abcdef",
        );
        std::env::set_var("APP_ENV", "development");
        std::env::set_var("ENABLE_MFA", "true");

        let result = SecureConfig::from_env();
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.app_env, AppEnvironment::Development);
        assert!(config.enable_mfa);
    }
}
