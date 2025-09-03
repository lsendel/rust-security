//! Configuration reload functionality for zero-downtime configuration updates.
//!
//! This module provides the ability to reload configuration without restarting the service,
//! enabling operational flexibility and reducing downtime during configuration changes.

use crate::config::Config;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::fs;
use tokio::signal;
use tokio::sync::{broadcast, RwLock};
use tracing::{error, info, warn};

/// Configuration reload events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigReloadEvent {
    /// Configuration reload requested
    ReloadRequested,
    /// Configuration reload successful
    ReloadSuccess { version: u64, changes: Vec<String> },
    /// Configuration reload failed
    ReloadFailed { error: String, fallback_used: bool },
    /// Configuration validation failed
    ValidationFailed { errors: Vec<String> },
}

/// Configuration change detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
    pub requires_restart: bool,
}

/// Configuration reload manager
#[derive(Debug)]
pub struct ConfigReloadManager {
    /// Current configuration
    config: Arc<RwLock<Config>>,
    /// Configuration file path
    config_path: Option<String>,
    /// Reload event broadcaster
    event_sender: broadcast::Sender<ConfigReloadEvent>,
    /// Configuration version (incremented on each reload)
    version: Arc<RwLock<u64>>,
    /// Backup configuration for fallback
    backup_config: Arc<RwLock<Option<Config>>>,
}

impl ConfigReloadManager {
    /// Create a new configuration reload manager
    #[must_use]
    pub fn new(
        initial_config: Config,
        config_path: Option<String>,
    ) -> (Self, broadcast::Receiver<ConfigReloadEvent>) {
        let (event_sender, event_receiver) = broadcast::channel(100);

        let manager = Self {
            config: Arc::new(RwLock::new(initial_config.clone())),
            config_path,
            event_sender,
            version: Arc::new(RwLock::new(1)),
            backup_config: Arc::new(RwLock::new(Some(initial_config))),
        };

        (manager, event_receiver)
    }

    /// Get the current configuration
    pub async fn get_config(&self) -> Config {
        self.config.read().await.clone()
    }

    /// Get the current configuration version
    pub async fn get_version(&self) -> u64 {
        *self.version.read().await
    }

    /// Start the configuration reload handler
    pub async fn start_reload_handler(self: Arc<Self>) -> Result<()> {
        info!("Starting configuration reload handler");

        // Clone Arc for the signal handler
        let manager = Arc::clone(&self);

        tokio::spawn(async move {
            loop {
                // Wait for SIGHUP signal on Unix systems
                #[cfg(unix)]
                {
                    if signal::unix::signal(signal::unix::SignalKind::hangup())
                        .expect("Failed to register SIGHUP handler")
                        .recv()
                        .await
                        .is_none()
                    {
                        error!("Error receiving SIGHUP signal: signal stream ended");
                        continue;
                    }
                }

                // On Windows or for testing, we could use other mechanisms
                #[cfg(not(unix))]
                {
                    // For now, just sleep and check periodically
                    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                    continue;
                }

                info!("Configuration reload signal received");

                // Send reload event
                if let Err(e) = manager
                    .event_sender
                    .send(ConfigReloadEvent::ReloadRequested)
                {
                    warn!("Failed to send reload event: {}", e);
                }

                // Perform the reload
                if let Err(e) = manager.reload_configuration().await {
                    error!("Configuration reload failed: {}", e);

                    let _ = manager.event_sender.send(ConfigReloadEvent::ReloadFailed {
                        error: e.to_string(),
                        fallback_used: false,
                    });
                }
            }
        });

        Ok(())
    }

    /// Manually trigger configuration reload
    pub async fn trigger_reload(&self) -> Result<()> {
        info!("Manual configuration reload triggered");

        if let Err(e) = self.event_sender.send(ConfigReloadEvent::ReloadRequested) {
            warn!("Failed to send reload event: {}", e);
        }

        self.reload_configuration().await
    }

    /// Reload configuration from file or environment
    async fn reload_configuration(&self) -> Result<()> {
        // Load new configuration
        let new_config = if let Some(config_path) = &self.config_path {
            self.load_config_from_file(config_path).await?
        } else {
            crate::config::Config::load()?
        };

        // Validate the new configuration
        if let Err(validation_errors) = self.validate_config(&new_config).await {
            let _ = self.event_sender.send(ConfigReloadEvent::ValidationFailed {
                errors: validation_errors,
            });
            return Err(anyhow::anyhow!("Configuration validation failed"));
        }

        // Detect changes
        let current_config = self.config.read().await.clone();
        let changes = self.detect_changes(&current_config, &new_config).await;

        // Check if any changes require restart
        let requires_restart = changes.iter().any(|change| change.requires_restart);
        if requires_restart {
            warn!("Configuration changes detected that require restart");
            for change in &changes {
                if change.requires_restart {
                    warn!("Restart required for: {}", change.field);
                }
            }
        }

        // Backup current configuration
        {
            let mut backup = self.backup_config.write().await;
            *backup = Some(current_config);
        }

        // Apply new configuration
        {
            let mut config = self.config.write().await;
            *config = new_config;
        }

        // Increment version
        {
            let mut version = self.version.write().await;
            *version += 1;
        }

        // Send success event
        let version = self.get_version().await;
        let change_descriptions: Vec<String> = changes
            .iter()
            .map(|c| format!("{}: {} -> {}", c.field, c.old_value, c.new_value))
            .collect();

        let _ = self.event_sender.send(ConfigReloadEvent::ReloadSuccess {
            version,
            changes: change_descriptions,
        });

        info!(
            "Configuration reloaded successfully (version: {}, changes: {})",
            version,
            changes.len()
        );

        Ok(())
    }

    /// Load configuration from file
    async fn load_config_from_file(&self, path: &str) -> Result<Config> {
        let config_content = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read configuration file: {path}"))?;

        let config: Config = if path.ends_with(".toml") {
            toml::from_str(&config_content).with_context(|| "Failed to parse TOML configuration")?
        } else if path.ends_with(".json") {
            serde_json::from_str(&config_content)
                .with_context(|| "Failed to parse JSON configuration")?
        } else if path.ends_with(".yaml") || path.ends_with(".yml") {
            serde_yaml::from_str(&config_content)
                .with_context(|| "Failed to parse YAML configuration")?
        } else {
            return Err(anyhow::anyhow!("Unsupported configuration file format"));
        };

        Ok(config)
    }

    /// Validate configuration
    pub async fn validate_config(&self, config: &crate::config::Config) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate using validator crate
        if let Err(e) = config.validate() {
            errors.push(e.to_string());
        }

        // Custom validation logic
        if config.server.bind_addr.ip().is_unspecified() {
            errors.push("bind_addr cannot be unspecified".to_string());
        }

        // Validate Redis URL if provided
        if config.redis.url.is_empty() {
            errors.push("redis_url cannot be empty if provided".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Detect changes between configurations
    async fn detect_changes(
        &self,
        old_config: &crate::config::Config,
        new_config: &crate::config::Config,
    ) -> Vec<ConfigChange> {
        let mut changes = Vec::new();

        // Compare bind address
        if old_config.server.bind_addr != new_config.server.bind_addr {
            changes.push(ConfigChange {
                field: "server.bind_addr".to_string(),
                old_value: old_config.server.bind_addr.to_string(),
                new_value: new_config.server.bind_addr.to_string(),
                requires_restart: true, // Server bind address change requires restart
            });
        }

        // Compare Redis URL
        if old_config.redis.url != new_config.redis.url {
            changes.push(ConfigChange {
                field: "redis.url".to_string(),
                old_value: old_config.redis.url.clone(),
                new_value: new_config.redis.url.clone(),
                requires_restart: false, // Can reconnect to Redis
            });
        }

        // Compare rate limiting settings
        if old_config.rate_limiting.global_limit != new_config.rate_limiting.global_limit {
            changes.push(ConfigChange {
                field: "rate_limiting.global_limit".to_string(),
                old_value: old_config.rate_limiting.global_limit.to_string(),
                new_value: new_config.rate_limiting.global_limit.to_string(),
                requires_restart: false, // Rate limiting can be updated dynamically
            });
        }

        // Compare security settings
        if old_config.security.bcrypt_cost != new_config.security.bcrypt_cost {
            changes.push(ConfigChange {
                field: "security.bcrypt_cost".to_string(),
                old_value: old_config.security.bcrypt_cost.to_string(),
                new_value: new_config.security.bcrypt_cost.to_string(),
                requires_restart: false, // TTL changes can be applied to new tokens
            });
        }

        // Compare feature flags
        if old_config.features != new_config.features {
            changes.push(ConfigChange {
                field: "features".to_string(),
                old_value: format!("{:?}", old_config.features),
                new_value: format!("{:?}", new_config.features),
                requires_restart: false, // Feature flags can be toggled dynamically
            });
        }

        changes
    }

    /// Rollback to backup configuration
    pub async fn rollback(&self) -> Result<()> {
        let backup = self.backup_config.read().await.clone();

        match backup {
            Some(backup_config) => {
                {
                    let mut config = self.config.write().await;
                    *config = backup_config;
                }

                {
                    let mut version = self.version.write().await;
                    *version += 1;
                }

                info!("Configuration rolled back successfully");
                Ok(())
            }
            None => Err(anyhow::anyhow!("No backup configuration available")),
        }
    }
}

/// Configuration reload API for HTTP endpoints
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigReloadRequest {
    pub force: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigReloadResponse {
    pub success: bool,
    pub version: u64,
    pub changes: Vec<String>,
    pub errors: Option<Vec<String>>,
    pub requires_restart: bool,
}

/// Configuration status for monitoring
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigStatus {
    pub version: u64,
    pub last_reload: Option<chrono::DateTime<chrono::Utc>>,
    pub source: String, // "file" or "environment"
    pub validation_status: String,
    pub requires_restart: bool,
}

/// Configuration reload metrics
#[derive(Debug, Clone, Default)]
pub struct ConfigReloadMetrics {
    pub reload_attempts: u64,
    pub successful_reloads: u64,
    pub failed_reloads: u64,
    pub validation_failures: u64,
    pub last_reload_duration: Option<std::time::Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn create_test_config() -> crate::config::Config {
        crate::config::Config::default()
    }

    #[tokio::test]
    async fn test_config_reload_manager_creation() {
        let config = create_test_config();
        let (manager, _receiver) = ConfigReloadManager::new(config.clone(), None);

        let current_config = manager.get_config().await;
        assert_eq!(current_config.server.bind_addr, config.server.bind_addr);
        assert_eq!(manager.get_version().await, 1);
    }

    #[tokio::test]
    async fn test_change_detection() {
        let old_config = create_test_config();
        let mut new_config = old_config.clone();
        new_config.rate_limiting.global_limit = 120;
        new_config.server.bind_addr = "0.0.0.0:8080".parse().unwrap();

        let (manager, _receiver) = ConfigReloadManager::new(old_config.clone(), None);
        let changes = manager.detect_changes(&old_config, &new_config).await;

        assert_eq!(changes.len(), 2);
        assert!(changes
            .iter()
            .any(|c| c.field == "rate_limiting.global_limit"));
        assert!(changes.iter().any(|c| c.field == "server.bind_addr"));
        assert!(changes.iter().any(|c| c.requires_restart));
    }

    #[tokio::test]
    async fn test_config_validation() {
        let mut config = create_test_config();
        config.server.bind_addr = "0.0.0.0:0".parse().unwrap(); // Invalid empty bind address

        let (manager, _receiver) = ConfigReloadManager::new(create_test_config(), None);
        let result = manager.validate_config(&config).await;

        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("bind_addr")));
    }
}
