//! Runtime Configuration Management
//!
//! Manages configuration updates at runtime with thread-safe access.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::watch::{self, Receiver, Sender};
use tracing::{info, warn};
use serde::{Deserialize, Serialize};

use crate::shared::error::AppError;
use super::loader::{ServiceConfig, ConfigLoader};

/// Runtime configuration manager with change notifications
pub struct RuntimeConfig {
    config_loader: ConfigLoader,
    config_tx: Sender<ServiceConfig>,
    config_rx: Receiver<ServiceConfig>,
    watchers: Arc<RwLock<HashMap<String, Box<dyn ConfigWatcher>>>>,
}

/// Configuration change watcher trait
#[async_trait::async_trait]
pub trait ConfigWatcher: Send + Sync {
    /// Called when configuration changes
    async fn on_config_change(&self, old_config: &ServiceConfig, new_config: &ServiceConfig);
}

/// Configuration change event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChangeEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub changes: Vec<ConfigChange>,
    pub source: ConfigChangeSource,
}

/// Individual configuration change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    pub section: String,
    pub key: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Source of configuration change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigChangeSource {
    FileReload,
    EnvironmentUpdate,
    HotReload,
    ManualUpdate,
}

impl RuntimeConfig {
    /// Create new runtime configuration manager
    pub fn new(config_path: impl Into<String>) -> Self {
        let config_loader = ConfigLoader::new(config_path);
        let initial_config = ServiceConfig::default();
        let (config_tx, config_rx) = watch::channel(initial_config);

        Self {
            config_loader,
            config_tx,
            config_rx,
            watchers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize configuration
    pub async fn init(&self) -> Result<(), AppError> {
        // Load initial configuration
        self.config_loader.load().await?;

        // Get initial config and broadcast
        let initial_config = self.config_loader.get_config().await;
        let _ = self.config_tx.send(initial_config);

        info!("Runtime configuration initialized");
        Ok(())
    }

    /// Get current configuration
    pub async fn get_config(&self) -> ServiceConfig {
        self.config_loader.get_config().await
    }

    /// Reload configuration from file
    pub async fn reload(&self) -> Result<(), AppError> {
        let old_config = self.config_loader.get_config().await;

        // Reload configuration
        self.config_loader.reload().await?;

        let new_config = self.config_loader.get_config().await;

        // Notify watchers of changes
        self.notify_watchers(&old_config, &new_config).await;

        // Broadcast new configuration
        let _ = self.config_tx.send(new_config);

        info!("Configuration reloaded successfully");
        Ok(())
    }

    /// Subscribe to configuration changes
    pub fn subscribe(&self) -> Receiver<ServiceConfig> {
        self.config_rx.clone()
    }

    /// Register a configuration watcher
    pub async fn register_watcher(&self, name: String, watcher: Box<dyn ConfigWatcher>) {
        let mut watchers = self.watchers.write().await;
        watchers.insert(name, watcher);
    }

    /// Unregister a configuration watcher
    pub async fn unregister_watcher(&self, name: &str) {
        let mut watchers = self.watchers.write().await;
        watchers.remove(name);
    }

    /// Update configuration value at runtime
    pub async fn update_config_value(
        &self,
        section: &str,
        key: &str,
        value: &str
    ) -> Result<(), AppError> {
        // Note: In a real implementation, this would update the underlying config file
        // and then reload. For now, we'll just log the request.
        warn!("Runtime config updates not yet implemented. Section: {}, Key: {}, Value: {}", section, key, value);
        Ok(())
    }

    /// Get configuration value by path
    pub async fn get_config_value(&self, path: &str) -> Option<String> {
        // Simple path-based value retrieval
        let config = self.get_config().await;
        let parts: Vec<&str> = path.split('.').collect();

        match parts.as_slice() {
            ["server", "port"] => Some(config.server.port.to_string()),
            ["server", "host"] => Some(config.server.host.clone()),
            ["database", "url"] => Some(config.database.url.clone()),
            ["redis", "url"] => Some(config.redis.url.clone()),
            ["security", "bcrypt_cost"] => config.security.bcrypt_cost.map(|v| v.to_string()),
            ["jwt", "algorithm"] => Some(config.jwt.algorithm.clone()),
            ["rate_limiting", "global_limit"] => Some(config.rate_limiting.global_limit.to_string()),
            ["monitoring", "tracing_level"] => Some(config.monitoring.tracing_level.clone()),
            _ => None,
        }
    }

    /// Validate configuration changes before applying
    pub async fn validate_config_changes(&self, changes: &[ConfigChange]) -> Result<(), AppError> {
        // Get current config as baseline
        let current_config = self.get_config().await;

        // Apply changes to a copy and validate
        let mut test_config = current_config.clone();

        for change in changes {
            // Apply change to test config
            if let Err(e) = self.apply_config_change(&mut test_config, change) {
                return Err(AppError::Validation(format!("Invalid configuration change: {}", e)));
            }
        }

        // Validate the modified configuration
        super::validator::ConfigValidator::validate_config(&test_config)
    }

    /// Export current configuration to TOML format
    pub async fn export_config(&self) -> Result<String, AppError> {
        let config = self.get_config().await;
        toml::to_string_pretty(&config)
            .map_err(|e| AppError::Internal(format!("Failed to export config: {}", e)))
    }

    /// Import configuration from TOML string
    pub async fn import_config(&self, toml_content: &str) -> Result<(), AppError> {
        let new_config: ServiceConfig = toml::from_str(toml_content)
            .map_err(|e| AppError::Config(format!("Failed to parse config: {}", e)))?;

        // Validate the new configuration
        super::validator::ConfigValidator::validate_config(&new_config)?;

        // Update the loader's config (in a real implementation)
        warn!("Config import not fully implemented - would update config loader");

        Ok(())
    }

    /// Get configuration change history (placeholder)
    pub async fn get_config_history(&self) -> Vec<ConfigChangeEvent> {
        // In a real implementation, this would track configuration changes over time
        vec![]
    }

    /// Check if configuration is valid
    pub async fn is_config_valid(&self) -> bool {
        let config = self.get_config().await;
        super::validator::ConfigValidator::validate_config(&config).is_ok()
    }

    /// Get configuration statistics
    pub async fn get_config_stats(&self) -> HashMap<String, serde_json::Value> {
        let config = self.get_config().await;
        let mut stats = HashMap::new();

        stats.insert("server_port".to_string(), config.server.port.into());
        stats.insert("database_url".to_string(), config.database.url.clone().into());
        stats.insert("redis_url".to_string(), config.redis.url.clone().into());
        stats.insert("features_enabled".to_string(), config.features.oauth_enabled.into());
        stats.insert("monitoring_enabled".to_string(), config.monitoring.metrics_enabled.into());

        stats
    }

    // Private methods

    async fn notify_watchers(&self, old_config: &ServiceConfig, new_config: &ServiceConfig) {
        let watchers = self.watchers.read().await;
        for (name, watcher) in watchers.iter() {
            if let Err(e) = watcher.on_config_change(old_config, new_config).await {
                warn!("Configuration watcher '{}' failed: {:?}", name, e);
            }
        }
    }

    fn apply_config_change(&self, config: &mut ServiceConfig, change: &ConfigChange) -> Result<(), String> {
        // Simple implementation for applying config changes
        // In a real implementation, this would use reflection or a more sophisticated approach
        match change.section.as_str() {
            "server" => match change.key.as_str() {
                "port" => {
                    if let Some(value) = &change.new_value {
                        config.server.port = value.parse().map_err(|_| "Invalid port")?;
                    }
                }
                "host" => {
                    if let Some(value) = &change.new_value {
                        config.server.host = value.clone();
                    }
                }
                _ => return Err(format!("Unknown server config key: {}", change.key)),
            },
            "database" => match change.key.as_str() {
                "url" => {
                    if let Some(value) = &change.new_value {
                        config.database.url = value.clone();
                    }
                }
                _ => return Err(format!("Unknown database config key: {}", change.key)),
            },
            _ => return Err(format!("Unknown config section: {}", change.section)),
        }

        Ok(())
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::new("config/base.toml")
    }
}

/// Example configuration watcher implementation
pub struct LoggingConfigWatcher;

#[async_trait::async_trait]
impl ConfigWatcher for LoggingConfigWatcher {
    async fn on_config_change(&self, old_config: &ServiceConfig, new_config: &ServiceConfig) {
        if old_config.server.port != new_config.server.port {
            info!("Server port changed from {} to {}", old_config.server.port, new_config.server.port);
        }

        if old_config.database.url != new_config.database.url {
            info!("Database URL changed from {} to {}", old_config.database.url, new_config.database.url);
        }

        if old_config.redis.url != new_config.redis.url {
            info!("Redis URL changed from {} to {}", old_config.redis.url, new_config.redis.url);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_runtime_config_init() {
        let config = RuntimeConfig::new("config/base.toml");
        // Test would require actual config files
        assert!(config.config_loader.get_config().await.server.port > 0);
    }

    #[tokio::test]
    async fn test_config_value_retrieval() {
        let config = RuntimeConfig::new("config/base.toml");

        // Test with default config
        let port = config.get_config_value("server.port").await;
        assert!(port.is_some());
    }

    #[tokio::test]
    async fn test_config_validation() {
        let config = RuntimeConfig::new("config/base.toml");

        // Should be valid with default config
        assert!(config.is_config_valid().await);
    }
}
