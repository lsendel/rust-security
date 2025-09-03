//! Secure SOAR Configuration Loader
//!
//! This module provides secure configuration loading for SOAR with:
//! - Environment variable validation for secrets
//! - Prevention of hardcoded credentials
//! - Automatic secret redaction in logs
//! - Configuration validation and sanitization

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use thiserror::Error;
use tracing::{error, info, warn};

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Configuration file not found: {0}")]
    FileNotFound(String),

    #[error("Failed to read configuration file: {0}")]
    ReadError(String),

    #[error("Failed to parse TOML configuration: {0}")]
    ParseError(String),

    #[error("Secret found in configuration file: {field}")]
    HardcodedSecret { field: String },

    #[error("Required environment variable not set: {0}")]
    MissingEnvVar(String),

    #[error("Configuration validation failed: {0}")]
    ValidationError(String),
}

/// List of configuration fields that must be loaded from environment variables
const SECRET_FIELDS: &[(&str, &str)] = &[
    ("notifications.email.password", "SMTP_PASSWORD"),
    ("notifications.slack.webhook_url", "SLACK_WEBHOOK_URL"),
    ("notifications.pagerduty.integration_key", "PAGERDUTY_INTEGRATION_KEY"),
    ("notifications.sms.api_key", "SMS_API_KEY"),
    ("integrations.siem.api_key", "SIEM_API_KEY"),
    ("integrations.siem.password", "SIEM_PASSWORD"),
    ("integrations.firewall.api_key", "FIREWALL_API_KEY"),
    ("integrations.identity_provider.api_key", "IDP_API_KEY"),
    ("integrations.identity_provider.tenant_id", "AZURE_TENANT_ID"),
    ("integrations.ticketing.api_key", "TICKETING_API_KEY"),
    ("evidence_management.encryption_key", "EVIDENCE_ENCRYPTION_KEY"),
    ("database.connection_string", "DATABASE_URL"),
];

/// Patterns that indicate potential secrets in configuration
const SECRET_PATTERNS: &[&str] = &[
    "password",
    "secret",
    "api_key",
    "token",
    "credential",
    "auth",
    "private_key",
    "webhook",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureSoarConfig {
    pub soar: SoarSettings,
    pub notifications: NotificationSettings,
    pub integrations: IntegrationSettings,
    pub evidence_management: EvidenceSettings,

    #[serde(skip)]
    secrets: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarSettings {
    pub enabled: bool,
    pub max_concurrent_workflows: usize,
    pub max_workflow_duration_minutes: u64,
    pub workflow_timeout_minutes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    pub email: EmailSettings,
    pub slack: SlackSettings,
    pub pagerduty: PagerDutySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailSettings {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    #[serde(skip)]
    pub password: String,
    pub from_address: String,
    pub use_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackSettings {
    #[serde(skip)]
    pub webhook_url: String,
    pub channel: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutySettings {
    #[serde(skip)]
    pub integration_key: String,
    pub api_url: String,
    pub service_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationSettings {
    pub siem: SiemSettings,
    pub firewall: FirewallSettings,
    pub identity_provider: IdpSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemSettings {
    pub api_url: String,
    #[serde(skip)]
    pub api_key: String,
    pub index_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallSettings {
    pub api_url: String,
    #[serde(skip)]
    pub api_key: String,
    pub default_block_duration_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpSettings {
    pub api_url: String,
    #[serde(skip)]
    pub api_key: String,
    #[serde(skip)]
    pub tenant_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSettings {
    pub enabled: bool,
    pub storage_path: String,
    pub encryption_enabled: bool,
    pub encryption_algorithm: String,
}

impl SecureSoarConfig {
    /// Load configuration from file with secure secret handling
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(ConfigError::FileNotFound(path.display().to_string()));
        }

        // Read the configuration file
        let content = fs::read_to_string(path)
            .map_err(|e| ConfigError::ReadError(e.to_string()))?;

        // Check for hardcoded secrets in the configuration
        Self::validate_no_hardcoded_secrets(&content)?;

        // Parse the TOML configuration
        let mut config: toml::Value = toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;

        // Load secrets from environment variables
        let secrets = Self::load_secrets_from_env()?;

        // Inject secrets into configuration
        Self::inject_secrets(&mut config, &secrets)?;

        // Parse into strongly typed configuration
        let mut soar_config: SecureSoarConfig = config.try_into()
            .map_err(|e| ConfigError::ParseError(format!("Failed to parse config: {}", e)))?;

        // Store secrets separately
        soar_config.secrets = secrets;

        // Validate the configuration
        soar_config.validate()?;

        info!("SOAR configuration loaded successfully (secrets loaded from environment)");

        Ok(soar_config)
    }

    /// Validate that no secrets are hardcoded in the configuration file
    fn validate_no_hardcoded_secrets(content: &str) -> Result<(), ConfigError> {
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Skip comments and empty lines
            if line.trim().starts_with('#') || line.trim().is_empty() {
                continue;
            }

            // Check for secret patterns with non-empty values
            for pattern in SECRET_PATTERNS {
                if line.to_lowercase().contains(pattern) {
                    // Check if the line has a non-empty value (not "", not a comment)
                    if let Some(eq_pos) = line.find('=') {
                        let value_part = line[eq_pos + 1..].trim();

                        // Check if value is not empty and not a placeholder
                        if !value_part.is_empty()
                            && value_part != "\"\""
                            && !value_part.starts_with('#')
                            && !value_part.contains("Set via environment") {

                            return Err(ConfigError::HardcodedSecret {
                                field: format!("Line {}: {}", line_num + 1, line.trim()),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Load secrets from environment variables
    fn load_secrets_from_env() -> Result<HashMap<String, String>, ConfigError> {
        let mut secrets = HashMap::new();

        for (field, env_var) in SECRET_FIELDS {
            match env::var(env_var) {
                Ok(value) if !value.is_empty() => {
                    secrets.insert(field.to_string(), value);
                    info!("Loaded secret from environment variable: {}", env_var);
                }
                Ok(_) => {
                    warn!("Environment variable {} is set but empty", env_var);
                }
                Err(_) => {
                    // Some secrets are optional, don't fail immediately
                    warn!("Environment variable {} not set", env_var);
                }
            }
        }

        Ok(secrets)
    }

    /// Inject secrets from environment into configuration
    fn inject_secrets(config: &mut toml::Value, secrets: &HashMap<String, String>) -> Result<(), ConfigError> {
        if let toml::Value::Table(table) = config {
            for (path, value) in secrets {
                Self::set_nested_value(table, path, value.clone())?;
            }
        }

        Ok(())
    }

    /// Set a nested value in the configuration table
    fn set_nested_value(
        table: &mut toml::map::Map<String, toml::Value>,
        path: &str,
        value: String,
    ) -> Result<(), ConfigError> {
        let parts: Vec<&str> = path.split('.').collect();

        if parts.is_empty() {
            return Ok(());
        }

        let mut current = table;

        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                // Last part - set the value
                current.insert(part.to_string(), toml::Value::String(value));
            } else {
                // Navigate deeper into the structure
                current = current
                    .entry(part.to_string())
                    .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
                    .as_table_mut()
                    .ok_or_else(|| ConfigError::ValidationError(
                        format!("Invalid configuration structure at {}", part)
                    ))?;
            }
        }

        Ok(())
    }

    /// Validate the loaded configuration
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate SOAR settings
        if self.soar.max_concurrent_workflows == 0 {
            return Err(ConfigError::ValidationError(
                "max_concurrent_workflows must be greater than 0".to_string()
            ));
        }

        if self.soar.workflow_timeout_minutes == 0 {
            return Err(ConfigError::ValidationError(
                "workflow_timeout_minutes must be greater than 0".to_string()
            ));
        }

        // Validate notification settings
        if self.notifications.email.smtp_port == 0 {
            return Err(ConfigError::ValidationError(
                "SMTP port must be greater than 0".to_string()
            ));
        }

        // Validate evidence management
        if self.evidence_management.encryption_enabled {
            if self.evidence_management.encryption_algorithm.is_empty() {
                return Err(ConfigError::ValidationError(
                    "Encryption algorithm must be specified when encryption is enabled".to_string()
                ));
            }
        }

        Ok(())
    }

    /// Get a secret value by key
    pub fn get_secret(&self, key: &str) -> Option<&str> {
        self.secrets.get(key).map(|s| s.as_str())
    }

    /// Redact secrets for logging
    pub fn redacted_config(&self) -> String {
        let mut config = serde_json::to_value(self).unwrap_or_default();

        // Redact all secret fields
        if let serde_json::Value::Object(ref mut map) = config {
            Self::redact_secrets_recursive(map);
        }

        serde_json::to_string_pretty(&config).unwrap_or_else(|_| "{}".to_string())
    }

    /// Recursively redact secret values in JSON
    fn redact_secrets_recursive(map: &mut serde_json::Map<String, serde_json::Value>) {
        for (key, value) in map.iter_mut() {
            // Check if the key indicates a secret
            let is_secret = SECRET_PATTERNS.iter().any(|pattern| {
                key.to_lowercase().contains(pattern)
            });

            if is_secret {
                *value = serde_json::Value::String("***REDACTED***".to_string());
            } else if let serde_json::Value::Object(ref mut nested_map) = value {
                Self::redact_secrets_recursive(nested_map);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_no_hardcoded_secrets_validation() {
        let config_with_secret = r#"
[notifications.email]
password = "${EMAIL_PASSWORD}"
"#;

        let result = SecureSoarConfig::validate_no_hardcoded_secrets(config_with_secret);
        assert!(operation_result.is_err());

        let config_without_secret = r#"
[notifications.email]
password = ""  # Set via environment variable SMTP_PASSWORD
"#;

        let result = SecureSoarConfig::validate_no_hardcoded_secrets(config_without_secret);
        assert!(operation_result.is_ok());
    }

    #[test]
    fn test_secret_redaction() {
        let config = SecureSoarConfig {
            soar: SoarSettings {
                enabled: true,
                max_concurrent_workflows: 10,
                max_workflow_duration_minutes: 60,
                workflow_timeout_minutes: 30,
            },
            notifications: NotificationSettings {
                email: EmailSettings {
                    smtp_host: "smtp.test.com".to_string(),
                    smtp_port: 587,
                    username: "test@test.com".to_string(),
                    password: "secret_password".to_string(),
                    from_address: "noreply@test.com".to_string(),
                    use_tls: true,
                },
                slack: SlackSettings {
                    webhook_url: "https://hooks.slack.com/secret".to_string(),
                    channel: "#test".to_string(),
                    username: "bot".to_string(),
                },
                pagerduty: PagerDutySettings {
                    integration_key: "secret_key".to_string(),
                    api_url: "https://api.pagerduty.com".to_string(),
                    service_id: "service123".to_string(),
                },
            },
            integrations: IntegrationSettings {
                siem: SiemSettings {
                    api_url: "https://siem.test.com".to_string(),
                    api_key: "secret_api_key".to_string(),
                    index_name: "logs".to_string(),
                },
                firewall: FirewallSettings {
                    api_url: "https://fw.test.com".to_string(),
                    api_key: "fw_secret".to_string(),
                    default_block_duration_hours: 1,
                },
                identity_provider: IdpSettings {
                    api_url: "https://idp.test.com".to_string(),
                    api_key: "idp_secret".to_string(),
                    tenant_id: "tenant123".to_string(),
                },
            },
            evidence_management: EvidenceSettings {
                enabled: true,
                storage_path: "/var/lib/soar".to_string(),
                encryption_enabled: true,
                encryption_algorithm: "aes256".to_string(),
            },
            secrets: HashMap::new(),
        };

        let redacted = config.redacted_config();

        // Verify secrets are redacted
        assert!(!redacted.contains("secret_password"));
        assert!(!redacted.contains("secret_key"));
        assert!(!redacted.contains("secret_api_key"));
        assert!(redacted.contains("***REDACTED***"));
    }
}