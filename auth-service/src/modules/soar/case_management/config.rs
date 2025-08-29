//! Case Management Configuration
//!
//! This module contains configuration structures for case management.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::errors::{SoarError, SoarResult};

/// Case management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseManagementConfig {
    /// Maximum number of active cases
    pub max_active_cases: usize,
    /// Case retention period in days
    pub retention_days: u32,
    /// Auto-escalation settings
    pub auto_escalation: AutoEscalationConfig,
    /// SLA settings
    pub sla_settings: SlaSettings,
    /// Notification settings
    pub notifications: NotificationSettings,
    /// Database configuration
    pub database: DatabaseConfig,
    /// Workflow configuration
    pub workflows: WorkflowConfig,
}

/// Auto-escalation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoEscalationConfig {
    /// Enable auto-escalation
    pub enabled: bool,
    /// Escalation thresholds by priority
    pub thresholds: HashMap<String, EscalationThreshold>,
}

/// Escalation threshold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationThreshold {
    /// Time threshold in minutes
    pub time_minutes: u32,
    /// Escalation target (email, user, etc.)
    pub target: String,
    /// Escalation message
    pub message: String,
}

/// SLA settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaSettings {
    /// Response time SLA in minutes
    pub response_sla_minutes: u32,
    /// Resolution time SLA in hours
    pub resolution_sla_hours: u32,
    /// Warning threshold (percentage of SLA)
    pub warning_threshold_percent: u8,
}

/// Notification settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    /// Email notifications enabled
    pub email_enabled: bool,
    /// Slack notifications enabled
    pub slack_enabled: bool,
    /// Webhook notifications enabled
    pub webhook_enabled: bool,
    /// Escalation contacts
    pub escalation_contacts: Vec<String>,
    /// Notification templates
    pub templates: NotificationTemplates,
}

/// Notification templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationTemplates {
    /// Case created template
    pub case_created: String,
    /// Case escalated template
    pub case_escalated: String,
    /// SLA violation template
    pub sla_violation: String,
    /// Case resolved template
    pub case_resolved: String,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL
    pub url: String,
    /// Maximum connections
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout_seconds: u64,
    /// Query timeout in seconds
    pub query_timeout_seconds: u64,
}

/// Workflow configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowConfig {
    /// Enable workflows
    pub enabled: bool,
    /// Default workflow
    pub default_workflow: String,
    /// Workflow timeouts
    pub timeouts: WorkflowTimeouts,
    /// Workflow retry settings
    pub retries: WorkflowRetries,
}

/// Workflow timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTimeouts {
    /// Maximum execution time in minutes
    pub max_execution_minutes: u32,
    /// Step timeout in seconds
    pub step_timeout_seconds: u32,
    /// Overall workflow timeout in hours
    pub workflow_timeout_hours: u32,
}

/// Workflow retry settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRetries {
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Retry delay in seconds
    pub retry_delay_seconds: u32,
    /// Exponential backoff enabled
    pub exponential_backoff: bool,
}

impl Default for CaseManagementConfig {
    fn default() -> Self {
        Self {
            max_active_cases: 1000,
            retention_days: 365,
            auto_escalation: AutoEscalationConfig {
                enabled: true,
                thresholds: HashMap::new(),
            },
            sla_settings: SlaSettings {
                response_sla_minutes: 30,
                resolution_sla_hours: 24,
                warning_threshold_percent: 80,
            },
            notifications: NotificationSettings {
                email_enabled: true,
                slack_enabled: false,
                webhook_enabled: false,
                escalation_contacts: Vec::new(),
                templates: NotificationTemplates {
                    case_created: "New security case created: {title}".to_string(),
                    case_escalated: "Security case escalated: {title}".to_string(),
                    sla_violation: "SLA violation detected for case: {title}".to_string(),
                    case_resolved: "Security case resolved: {title}".to_string(),
                },
            },
            database: DatabaseConfig {
                url: "postgresql://localhost/security".to_string(),
                max_connections: 10,
                connection_timeout_seconds: 30,
                query_timeout_seconds: 60,
            },
            workflows: WorkflowConfig {
                enabled: true,
                default_workflow: "default_case_workflow".to_string(),
                timeouts: WorkflowTimeouts {
                    max_execution_minutes: 30,
                    step_timeout_seconds: 300,
                    workflow_timeout_hours: 24,
                },
                retries: WorkflowRetries {
                    max_attempts: 3,
                    retry_delay_seconds: 60,
                    exponential_backoff: true,
                },
            },
        }
    }
}

impl CaseManagementConfig {
    /// Load configuration from file
    pub fn from_file(path: &str) -> SoarResult<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| SoarError::InvalidInput {
            field: "config_file".to_string(),
            reason: format!("Failed to read config file: {}", e),
        })?;

        toml::from_str(&content).map_err(|e| SoarError::InvalidInput {
            field: "config_content".to_string(),
            reason: format!("Failed to parse config: {}", e),
        })
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.max_active_cases == 0 {
            errors.push("max_active_cases must be greater than 0".to_string());
        }

        if self.retention_days == 0 {
            errors.push("retention_days must be greater than 0".to_string());
        }

        if self.sla_settings.response_sla_minutes == 0 {
            errors.push("response_sla_minutes must be greater than 0".to_string());
        }

        if self.sla_settings.resolution_sla_hours == 0 {
            errors.push("resolution_sla_hours must be greater than 0".to_string());
        }

        if self.database.max_connections == 0 {
            errors.push("max_connections must be greater than 0".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CaseManagementConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_config() {
        let config = CaseManagementConfig {
            max_active_cases: 0,
            ..Default::default()
        };
        let errors = config.validate().unwrap_err();
        assert!(errors.len() > 0);
        assert!(errors.contains(&"max_active_cases must be greater than 0".to_string()));
    }
}
