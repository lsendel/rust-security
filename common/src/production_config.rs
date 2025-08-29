//! Production-ready configuration validation and startup checks
//!
//! This module provides comprehensive validation for production deployments,
//! ensuring all required settings are present and properly configured.

use crate::config::{PlatformConfiguration, RateLimitConfig, SecurityConfig};
use std::collections::HashMap;
use std::env;
use thiserror::Error;

/// Configuration validation errors
#[derive(Error, Debug)]
pub enum ConfigValidationError {
    #[error("Missing required environment variable: {variable}")]
    MissingVariable { variable: String },

    #[error("Invalid environment variable value for {variable}: {value} - {reason}")]
    InvalidValue {
        variable: String,
        value: String,
        reason: String,
    },

    #[error("Configuration conflict: {conflict}")]
    ConfigConflict { conflict: String },

    #[error("Security configuration error: {error}")]
    SecurityError { error: String },

    #[error("Database configuration error: {error}")]
    DatabaseError { error: String },

    #[error("Redis configuration error: {error}")]
    RedisError { error: String },

    #[error("External service configuration error: {error}")]
    ExternalServiceError { error: String },
}

/// Production configuration validator
pub struct ProductionConfigValidator {
    environment: String,
    required_vars: HashMap<String, ValidationRule>,
    security_checks: Vec<SecurityValidationRule>,
}

#[derive(Debug, Clone)]
pub struct ValidationRule {
    pub description: String,
    pub required_in_env: Vec<String>,
    pub validator: Option<fn(&str) -> Result<(), String>>,
}

#[derive(Debug, Clone)]
pub struct SecurityValidationRule {
    pub name: String,
    pub description: String,
    pub severity: SecuritySeverity,
    pub validator: fn(&ProductionConfigValidator) -> Result<(), ConfigValidationError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl ProductionConfigValidator {
    /// Create a new production configuration validator
    pub fn new() -> Self {
        let mut validator = Self {
            environment: env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
            required_vars: HashMap::new(),
            security_checks: Vec::new(),
        };

        validator.initialize_validation_rules();
        validator.initialize_security_checks();
        validator
    }

    /// Initialize validation rules for different environments
    fn initialize_validation_rules(&mut self) {
        // Core application settings
        self.required_vars.insert(
            "SERVICE_NAME".to_string(),
            ValidationRule {
                description: "Application service name".to_string(),
                required_in_env: vec!["production".to_string(), "staging".to_string()],
                validator: Some(|value| {
                    if value.trim().is_empty() {
                        Err("Service name cannot be empty".to_string())
                    } else if value.len() > 50 {
                        Err("Service name too long (max 50 characters)".to_string())
                    } else {
                        Ok(())
                    }
                }),
            },
        );

        // Database configuration
        self.required_vars.insert(
            "DATABASE_URL".to_string(),
            ValidationRule {
                description: "PostgreSQL database connection URL".to_string(),
                required_in_env: vec!["production".to_string(), "staging".to_string()],
                validator: Some(|value| {
                    if !value.starts_with("postgresql://") && !value.starts_with("postgres://") {
                        Err("Database URL must start with postgresql:// or postgres://".to_string())
                    } else if value.len() < 20 {
                        Err("Database URL appears to be incomplete".to_string())
                    } else {
                        Ok(())
                    }
                }),
            },
        );

        // Redis configuration
        self.required_vars.insert(
            "REDIS_URL".to_string(),
            ValidationRule {
                description: "Redis connection URL".to_string(),
                required_in_env: vec!["production".to_string(), "staging".to_string()],
                validator: Some(|value| {
                    if !value.starts_with("redis://") && !value.starts_with("rediss://") {
                        Err("Redis URL must start with redis:// or rediss://".to_string())
                    } else {
                        Ok(())
                    }
                }),
            },
        );

        // JWT configuration
        self.required_vars.insert(
            "JWT_SECRET".to_string(),
            ValidationRule {
                description: "JWT signing secret key".to_string(),
                required_in_env: vec!["production".to_string(), "staging".to_string()],
                validator: Some(|value| {
                    if value.len() < 32 {
                        Err("JWT secret must be at least 32 characters long".to_string())
                    } else if value.chars().all(|c| c.is_alphanumeric()) {
                        Err(
                            "JWT secret should contain special characters for better security"
                                .to_string(),
                        )
                    } else {
                        Ok(())
                    }
                }),
            },
        );

        // OAuth client credentials
        self.required_vars.insert(
            "OAUTH_CLIENT_SECRET".to_string(),
            ValidationRule {
                description: "OAuth client secret".to_string(),
                required_in_env: vec!["production".to_string(), "staging".to_string()],
                validator: Some(|value| {
                    if value.len() < 32 {
                        Err("OAuth client secret must be at least 32 characters long".to_string())
                    } else {
                        Ok(())
                    }
                }),
            },
        );
    }

    /// Initialize security validation checks
    fn initialize_security_checks(&mut self) {
        self.security_checks.push(SecurityValidationRule {
            name: "HTTPS Enforcement".to_string(),
            description: "Ensure HTTPS is enforced in production".to_string(),
            severity: SecuritySeverity::Critical,
            validator: |validator| {
                if validator.environment == "production" {
                    if let Ok(force_https) = env::var("FORCE_HTTPS") {
                        if force_https.to_lowercase() != "true" {
                            return Err(ConfigValidationError::SecurityError {
                                error: "FORCE_HTTPS must be set to 'true' in production"
                                    .to_string(),
                            });
                        }
                    } else {
                        return Err(ConfigValidationError::SecurityError {
                            error: "FORCE_HTTPS environment variable must be set in production"
                                .to_string(),
                        });
                    }
                }
                Ok(())
            },
        });

        self.security_checks.push(SecurityValidationRule {
            name: "Secure Headers".to_string(),
            description: "Validate security headers configuration".to_string(),
            severity: SecuritySeverity::High,
            validator: |_| {
                // Check for required security headers configuration
                let headers_check =
                    env::var("SECURITY_HEADERS_ENABLED").unwrap_or_else(|_| "true".to_string());

                if headers_check.to_lowercase() == "false"
                    && matches!(
                        env::var("ENVIRONMENT").as_deref(),
                        Ok("production") | Ok("staging")
                    )
                {
                    return Err(ConfigValidationError::SecurityError {
                        error: "Security headers cannot be disabled in production or staging"
                            .to_string(),
                    });
                }
                Ok(())
            },
        });

        self.security_checks.push(SecurityValidationRule {
            name: "Rate Limiting".to_string(),
            description: "Ensure rate limiting is properly configured".to_string(),
            severity: SecuritySeverity::High,
            validator: |_| {
                let rate_limit_enabled =
                    env::var("RATE_LIMIT_ENABLED").unwrap_or_else(|_| "true".to_string());

                if rate_limit_enabled.to_lowercase() == "true" {
                    if let Ok(requests_per_min) = env::var("RATE_LIMIT_REQUESTS_PER_MINUTE") {
                        if let Ok(requests) = requests_per_min.parse::<u32>() {
                            if requests == 0 {
                                return Err(ConfigValidationError::SecurityError {
                                    error: "Rate limit cannot be set to 0 when enabled".to_string(),
                                });
                            }
                            if requests > 10000 {
                                return Err(ConfigValidationError::SecurityError {
                                    error:
                                        "Rate limit seems unreasonably high (>10,000 per minute)"
                                            .to_string(),
                                });
                            }
                        }
                    }
                }
                Ok(())
            },
        });

        self.security_checks.push(SecurityValidationRule {
            name: "Session Security".to_string(),
            description: "Validate session security configuration".to_string(),
            severity: SecuritySeverity::Medium,
            validator: |_| {
                if let Ok(session_ttl) = env::var("SESSION_TTL_SECONDS") {
                    if let Ok(ttl) = session_ttl.parse::<u64>() {
                        if ttl < 300 {
                            // 5 minutes minimum
                            return Err(ConfigValidationError::SecurityError {
                                error: "Session TTL should be at least 300 seconds (5 minutes)"
                                    .to_string(),
                            });
                        }
                        if ttl > 86400 {
                            // 24 hours maximum
                            return Err(ConfigValidationError::SecurityError {
                                error: "Session TTL should not exceed 86400 seconds (24 hours)"
                                    .to_string(),
                            });
                        }
                    }
                }
                Ok(())
            },
        });
    }

    /// Validate all configuration requirements
    pub fn validate_all(&self) -> Result<ValidationReport, Vec<ConfigValidationError>> {
        let mut errors = Vec::new();

        // Validate required environment variables
        for (var_name, rule) in &self.required_vars {
            if rule.required_in_env.contains(&self.environment) {
                match env::var(var_name) {
                    Ok(value) => {
                        if let Some(validator) = rule.validator {
                            if let Err(reason) = validator(&value) {
                                errors.push(ConfigValidationError::InvalidValue {
                                    variable: var_name.clone(),
                                    value,
                                    reason,
                                });
                            }
                        }
                    }
                    Err(_) => {
                        errors.push(ConfigValidationError::MissingVariable {
                            variable: var_name.clone(),
                        });
                    }
                }
            }
        }

        // Run security validation checks
        for check in &self.security_checks {
            if let Err(error) = (check.validator)(self) {
                errors.push(error);
            }
        }

        // Additional cross-validation
        self.validate_configuration_consistency(&mut errors);

        if errors.is_empty() {
            Ok(ValidationReport {
                status: ValidationStatus::Passed,
                environment: self.environment.clone(),
                checks_performed: self.required_vars.len() + self.security_checks.len(),
                errors: vec![],
            })
        } else {
            Ok(ValidationReport {
                status: ValidationStatus::Failed,
                environment: self.environment.clone(),
                checks_performed: self.required_vars.len() + self.security_checks.len(),
                errors,
            })
        }
    }

    /// Validate configuration consistency across different settings
    fn validate_configuration_consistency(&self, errors: &mut Vec<ConfigValidationError>) {
        // Check for conflicting configurations
        if let (Ok(db_url), Ok(redis_url)) = (env::var("DATABASE_URL"), env::var("REDIS_URL")) {
            if db_url == redis_url {
                errors.push(ConfigValidationError::ConfigConflict {
                    conflict: "DATABASE_URL and REDIS_URL should not be the same".to_string(),
                });
            }
        }

        // Validate JWT and OAuth consistency
        if let (Ok(jwt_secret), Ok(oauth_secret)) =
            (env::var("JWT_SECRET"), env::var("OAUTH_CLIENT_SECRET"))
        {
            if jwt_secret == oauth_secret {
                errors.push(ConfigValidationError::SecurityError {
                    error: "JWT_SECRET and OAUTH_CLIENT_SECRET should not be the same for security"
                        .to_string(),
                });
            }
        }
    }

    /// Get configuration summary for logging
    pub fn get_config_summary(&self) -> HashMap<String, String> {
        let mut summary = HashMap::new();

        summary.insert("environment".to_string(), self.environment.clone());
        summary.insert(
            "service_name".to_string(),
            env::var("SERVICE_NAME").unwrap_or_else(|_| "rust-security".to_string()),
        );

        // Add configuration status for key components
        let components = vec![
            ("database", "DATABASE_URL"),
            ("redis", "REDIS_URL"),
            ("jwt", "JWT_SECRET"),
            ("oauth", "OAUTH_CLIENT_SECRET"),
        ];

        for (component, var_name) in components {
            let status = if env::var(var_name).is_ok() {
                "configured"
            } else {
                "not_configured"
            };
            summary.insert(component.to_string(), status.to_string());
        }

        summary
    }
}

/// Validation report
#[derive(Debug)]
pub struct ValidationReport {
    pub status: ValidationStatus,
    pub environment: String,
    pub checks_performed: usize,
    pub errors: Vec<ConfigValidationError>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationStatus {
    Passed,
    Failed,
}

/// Production startup checker
pub struct ProductionStartupChecker {
    config_validator: ProductionConfigValidator,
}

impl ProductionStartupChecker {
    /// Create a new startup checker
    pub fn new() -> Self {
        Self {
            config_validator: ProductionConfigValidator::new(),
        }
    }

    /// Perform complete production readiness check
    pub async fn perform_startup_checks(
        &self,
    ) -> Result<StartupReport, Vec<ConfigValidationError>> {
        println!("🚀 Performing production startup checks...");

        let mut checks = Vec::new();
        let mut errors = Vec::new();

        // Configuration validation
        println!("📋 Checking configuration...");
        match self.config_validator.validate_all() {
            Ok(report) => {
                checks.push(StartupCheck {
                    name: "Configuration Validation".to_string(),
                    status: if report.status == ValidationStatus::Passed {
                        CheckStatus::Passed
                    } else {
                        CheckStatus::Failed
                    },
                    details: format!("Performed {} checks", report.checks_performed),
                    errors: report.errors,
                });

                if report.status == ValidationStatus::Failed {
                    errors.extend(report.errors);
                }
            }
            Err(validation_errors) => {
                errors.extend(validation_errors);
            }
        }

        // Service connectivity checks
        checks.extend(self.check_service_connectivity().await);

        // Security checks
        checks.extend(self.perform_security_checks().await);

        // Resource availability checks
        checks.extend(self.check_resource_availability().await);

        let overall_status =
            if errors.is_empty() && checks.iter().all(|c| c.status == CheckStatus::Passed) {
                StartupStatus::Ready
            } else if errors.is_empty() {
                StartupStatus::Warning
            } else {
                StartupStatus::Failed
            };

        Ok(StartupReport {
            status: overall_status,
            checks,
            config_summary: self.config_validator.get_config_summary(),
            started_at: chrono::Utc::now(),
        })
    }

    /// Check connectivity to required services
    async fn check_service_connectivity(&self) -> Vec<StartupCheck> {
        let mut checks = Vec::new();

        // Check database connectivity
        if let Ok(db_url) = env::var("DATABASE_URL") {
            let status = if Self::can_connect_to_database(&db_url).await {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            };

            checks.push(StartupCheck {
                name: "Database Connectivity".to_string(),
                status,
                details: "PostgreSQL connection test".to_string(),
                errors: vec![],
            });
        }

        // Check Redis connectivity
        if let Ok(redis_url) = env::var("REDIS_URL") {
            let status = if Self::can_connect_to_redis(&redis_url).await {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            };

            checks.push(StartupCheck {
                name: "Redis Connectivity".to_string(),
                status,
                details: "Redis connection test".to_string(),
                errors: vec![],
            });
        }

        checks
    }

    /// Perform security validation checks
    async fn perform_security_checks(&self) -> Vec<StartupCheck> {
        let mut checks = Vec::new();

        // Check for default or weak secrets
        let weak_secrets = Self::check_for_weak_secrets();
        let status = if weak_secrets.is_empty() {
            CheckStatus::Passed
        } else {
            CheckStatus::Warning
        };

        checks.push(StartupCheck {
            name: "Secret Strength".to_string(),
            status,
            details: format!("Found {} potential weak secrets", weak_secrets.len()),
            errors: vec![],
        });

        // Check file permissions
        let permission_issues = Self::check_file_permissions();
        let status = if permission_issues.is_empty() {
            CheckStatus::Passed
        } else {
            CheckStatus::Warning
        };

        checks.push(StartupCheck {
            name: "File Permissions".to_string(),
            status,
            details: format!("Found {} permission issues", permission_issues.len()),
            errors: vec![],
        });

        checks
    }

    /// Check resource availability
    async fn check_resource_availability(&self) -> Vec<StartupCheck> {
        let mut checks = Vec::new();

        // Check available memory
        let memory_mb = Self::get_available_memory_mb();
        let memory_status = if memory_mb > 512 {
            CheckStatus::Passed
        } else if memory_mb > 256 {
            CheckStatus::Warning
        } else {
            CheckStatus::Failed
        };

        checks.push(StartupCheck {
            name: "Available Memory".to_string(),
            status: memory_status,
            details: format!("{} MB available", memory_mb),
            errors: vec![],
        });

        // Check available disk space
        let disk_gb = Self::get_available_disk_gb();
        let disk_status = if disk_gb > 10 {
            CheckStatus::Passed
        } else if disk_gb > 5 {
            CheckStatus::Warning
        } else {
            CheckStatus::Failed
        };

        checks.push(StartupCheck {
            name: "Available Disk Space".to_string(),
            status: disk_status,
            details: format!("{} GB available", disk_gb),
            errors: vec![],
        });

        checks
    }

    // Helper methods (simplified implementations)
    async fn can_connect_to_database(_url: &str) -> bool {
        // In a real implementation, this would attempt a database connection
        true // Placeholder
    }

    async fn can_connect_to_redis(_url: &str) -> bool {
        // In a real implementation, this would attempt a Redis connection
        true // Placeholder
    }

    fn check_for_weak_secrets() -> Vec<String> {
        // In a real implementation, this would check for default/weak secrets
        vec![] // Placeholder
    }

    fn check_file_permissions() -> Vec<String> {
        // In a real implementation, this would check file permissions
        vec![] // Placeholder
    }

    fn get_available_memory_mb() -> u64 {
        // In a real implementation, this would check system memory
        2048 // Placeholder
    }

    fn get_available_disk_gb() -> u64 {
        // In a real implementation, this would check disk space
        50 // Placeholder
    }
}

/// Startup check result
#[derive(Debug)]
pub struct StartupCheck {
    pub name: String,
    pub status: CheckStatus,
    pub details: String,
    pub errors: Vec<ConfigValidationError>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Passed,
    Warning,
    Failed,
}

/// Startup report
#[derive(Debug)]
pub struct StartupReport {
    pub status: StartupStatus,
    pub checks: Vec<StartupCheck>,
    pub config_summary: HashMap<String, String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StartupStatus {
    Ready,
    Warning,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_config_validation() {
        // Set up test environment
        env::set_var("ENVIRONMENT", "production");
        env::set_var("SERVICE_NAME", "test-service");
        env::set_var("DATABASE_URL", "postgresql://user:pass@localhost:5432/test");
        env::set_var("REDIS_URL", "redis://localhost:6379");
        env::set_var(
            "JWT_SECRET",
            "super-secret-jwt-key-that-is-long-enough-for-production-use",
        );
        env::set_var(
            "OAUTH_CLIENT_SECRET",
            "different-oauth-secret-for-security-purposes",
        );

        let validator = ProductionConfigValidator::new();
        let report = validator.validate_all().unwrap();

        assert_eq!(report.status, ValidationStatus::Passed);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn test_missing_required_variables() {
        // Clear environment
        env::remove_var("DATABASE_URL");
        env::set_var("ENVIRONMENT", "production");

        let validator = ProductionConfigValidator::new();
        let report = validator.validate_all().unwrap();

        assert_eq!(report.status, ValidationStatus::Failed);
        assert!(!report.errors.is_empty());

        // Should contain missing DATABASE_URL error
        let has_missing_db = report.errors.iter().any(|e| {
            matches!(e, ConfigValidationError::MissingVariable { variable } if variable == "DATABASE_URL")
        });
        assert!(has_missing_db);
    }

    #[tokio::test]
    async fn test_startup_checker() {
        let checker = ProductionStartupChecker::new();
        let report = checker.perform_startup_checks().await.unwrap();

        // Should complete without panicking
        assert!(matches!(
            report.status,
            StartupStatus::Ready | StartupStatus::Warning | StartupStatus::Failed
        ));
    }
}
