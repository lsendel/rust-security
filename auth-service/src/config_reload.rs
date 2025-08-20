//! Configuration reload functionality for zero-downtime configuration updates.
//!
//! This module provides the ability to reload configuration without restarting the service,
//! enabling operational flexibility and reducing downtime during configuration changes.

use crate::config::{AppConfig, StoreBackend};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::signal;
use tokio::sync::{broadcast, RwLock};
use tracing::{error, info, warn};
use validator::Validate;

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
    config: Arc<RwLock<AppConfig>>,
    /// Configuration file path
    config_path: Option<String>,
    /// Reload event broadcaster
    event_sender: broadcast::Sender<ConfigReloadEvent>,
    /// Configuration version (incremented on each reload)
    version: Arc<RwLock<u64>>,
    /// Backup configuration for fallback
    backup_config: Arc<RwLock<Option<AppConfig>>>,
}

impl ConfigReloadManager {
    /// Create a new configuration reload manager
    pub fn new(
        initial_config: AppConfig,
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
    pub async fn get_config(&self) -> AppConfig {
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
                    if let Err(e) = signal::unix::signal(signal::unix::SignalKind::hangup())
                        .expect("Failed to register SIGHUP handler")
                        .recv()
                        .await
                    {
                        error!("Error receiving SIGHUP signal: {}", e);
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
                if let Err(e) = manager.event_sender.send(ConfigReloadEvent::ReloadRequested) {
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
            AppConfig::from_env()?
        };

        // Validate the new configuration
        if let Err(validation_errors) = self.validate_config(&new_config).await {
            let _ = self
                .event_sender
                .send(ConfigReloadEvent::ValidationFailed { errors: validation_errors });
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

        let _ = self
            .event_sender
            .send(ConfigReloadEvent::ReloadSuccess { version, changes: change_descriptions });

        info!(
            "Configuration reloaded successfully (version: {}, changes: {})",
            version,
            changes.len()
        );

        Ok(())
    }

    /// Load configuration from file
    async fn load_config_from_file(&self, path: &str) -> Result<AppConfig> {
        let config_content = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read configuration file: {}", path))?;

        let config: AppConfig = if path.ends_with(".toml") {
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
    async fn validate_config(&self, config: &AppConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate using validator crate
        if let Err(validation_errors) = config.validate() {
            for (field, field_errors) in validation_errors.field_errors() {
                for error in field_errors {
                    errors.push(format!("Field '{}': {}", field, error.code));
                }
            }
        }

        // Custom validation logic
        if config.bind_addr.is_empty() {
            errors.push("bind_addr cannot be empty".to_string());
        }

        if config.client_credentials.is_empty() {
            errors.push("At least one client credential must be configured".to_string());
        }

        // Validate Redis URL if provided
        if let Some(redis_url) = &config.redis_url {
            if redis_url.is_empty() {
                errors.push("redis_url cannot be empty if provided".to_string());
            }
        }

        // Validate store configuration
        match &config.store.backend {
            StoreBackend::Hybrid => {
                if config.redis_url.is_none() {
                    errors.push("Redis URL required for hybrid store backend".to_string());
                }
            }
            StoreBackend::Sql => {
                if config.store.database_url.is_none() {
                    errors.push("Database URL required for SQL store backend".to_string());
                }
            }
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
        old_config: &AppConfig,
        new_config: &AppConfig,
    ) -> Vec<ConfigChange> {
        let mut changes = Vec::new();

        // Compare bind address
        if old_config.bind_addr != new_config.bind_addr {
            changes.push(ConfigChange {
                field: "bind_addr".to_string(),
                old_value: old_config.bind_addr.clone(),
                new_value: new_config.bind_addr.clone(),
                requires_restart: true, // Server bind address change requires restart
            });
        }

        // Compare Redis URL
        if old_config.redis_url != new_config.redis_url {
            changes.push(ConfigChange {
                field: "redis_url".to_string(),
                old_value: old_config.redis_url.as_deref().unwrap_or("None").to_string(),
                new_value: new_config.redis_url.as_deref().unwrap_or("None").to_string(),
                requires_restart: false, // Can reconnect to Redis
            });
        }

        // Compare rate limiting settings
        if old_config.rate_limiting.oauth_requests_per_minute
            != new_config.rate_limiting.oauth_requests_per_minute
        {
            changes.push(ConfigChange {
                field: "rate_limiting.oauth_requests_per_minute".to_string(),
                old_value: old_config.rate_limiting.oauth_requests_per_minute.to_string(),
                new_value: new_config.rate_limiting.oauth_requests_per_minute.to_string(),
                requires_restart: false, // Rate limiting can be updated dynamically
            });
        }

        // Compare security settings
        if old_config.security.jwt_access_token_ttl_seconds
            != new_config.security.jwt_access_token_ttl_seconds
        {
            changes.push(ConfigChange {
                field: "security.jwt_access_token_ttl_seconds".to_string(),
                old_value: old_config.security.jwt_access_token_ttl_seconds.to_string(),
                new_value: new_config.security.jwt_access_token_ttl_seconds.to_string(),
                requires_restart: false, // TTL changes can be applied to new tokens
            });
        }

        // Compare store backend
        if std::mem::discriminant(&old_config.store.backend)
            != std::mem::discriminant(&new_config.store.backend)
        {
            changes.push(ConfigChange {
                field: "store.backend".to_string(),
                old_value: format!("{:?}", old_config.store.backend),
                new_value: format!("{:?}", new_config.store.backend),
                requires_restart: true, // Store backend change requires restart
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
#[derive(Debug, Clone)]
pub struct ConfigReloadMetrics {
    pub reload_attempts: u64,
    pub successful_reloads: u64,
    pub failed_reloads: u64,
    pub validation_failures: u64,
    pub last_reload_duration: Option<std::time::Duration>,
}

impl Default for ConfigReloadMetrics {
    fn default() -> Self {
        Self {
            reload_attempts: 0,
            successful_reloads: 0,
            failed_reloads: 0,
            validation_failures: 0,
            last_reload_duration: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        FeatureFlags, MonitoringConfig, OAuthConfig, RateLimitConfig, ScimConfig, SecurityConfig,
        StoreConfig,
    };
    use std::collections::HashMap;

    fn create_test_config() -> AppConfig {
        AppConfig {
            bind_addr: "127.0.0.1:8080".to_string(),
            redis_url: Some("redis://localhost:6379".to_string()),
            oidc_providers: crate::config::OidcProviders {
                google: None,
                microsoft: None,
                github: None,
            },
            security: SecurityConfig {
                jwt_access_token_ttl_seconds: 3600,
                jwt_refresh_token_ttl_seconds: 86400,
                rsa_key_size: 2048,
                enforce_pkce: true,
                require_state: true,
                max_token_binding_age_seconds: 300,
                token_binding_required: false,
                allowed_cors_origins: vec!["http://localhost:3000".to_string()],
                request_signature_required: false,
                request_signature_max_age_seconds: 300,
            },
            rate_limiting: RateLimitConfig {
                oauth_requests_per_minute: 60,
                burst_size: 10,
                per_ip_limit: Some(100),
                per_client_limit: Some(1000),
                cleanup_interval_seconds: 60,
            },
            monitoring: MonitoringConfig {
                metrics_enabled: true,
                tracing_enabled: true,
                health_check_interval_seconds: 30,
                jaeger_endpoint: None,
            },
            features: FeatureFlags {
                mfa_enabled: true,
                scim_enabled: true,
                oidc_enabled: true,
                advanced_logging: true,
                performance_monitoring: true,
                threat_hunting: false,
                soar_integration: false,
            },
            oauth: OAuthConfig {
                authorization_code_ttl_seconds: 600,
                device_code_ttl_seconds: 600,
                pkce_required: true,
                refresh_token_rotation: true,
            },
            scim: ScimConfig {
                base_url: "http://localhost:8080/scim/v2".to_string(),
                max_results: 100,
                case_exact: false,
            },
            store: StoreConfig {
                backend: StoreBackend::Hybrid,
                connection_pool_size: 10,
                connection_timeout_seconds: 30,
                max_idle_connections: 5,
                database_url: None,
            },
            client_credentials: HashMap::from([
                ("client1".to_string(), "secret1".to_string()),
                ("client2".to_string(), "secret2".to_string()),
            ]),
            allowed_scopes: vec!["read".to_string(), "write".to_string()],
            jwt_secret: "test-secret".to_string(),
            token_expiry_seconds: 3600,
            rate_limit_oauth_requests_per_minute: 60,
        }
    }

    #[tokio::test]
    async fn test_config_reload_manager_creation() {
        let config = create_test_config();
        let (manager, _receiver) = ConfigReloadManager::new(config.clone(), None);

        let current_config = manager.get_config().await;
        assert_eq!(current_config.bind_addr, config.bind_addr);
        assert_eq!(manager.get_version().await, 1);
    }

    #[tokio::test]
    async fn test_change_detection() {
        let old_config = create_test_config();
        let mut new_config = old_config.clone();
        new_config.rate_limiting.oauth_requests_per_minute = 120;
        new_config.bind_addr = "0.0.0.0:8080".to_string();

        let (manager, _receiver) = ConfigReloadManager::new(old_config.clone(), None);
        let changes = manager.detect_changes(&old_config, &new_config).await;

        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| c.field == "rate_limiting.oauth_requests_per_minute"));
        assert!(changes.iter().any(|c| c.field == "bind_addr"));
        assert!(changes.iter().any(|c| c.requires_restart));
    }

    #[tokio::test]
    async fn test_config_validation() {
        let mut config = create_test_config();
        config.bind_addr = "".to_string(); // Invalid empty bind address
        config.client_credentials.clear(); // Invalid empty credentials

        let (manager, _receiver) = ConfigReloadManager::new(create_test_config(), None);
        let result = manager.validate_config(&config).await;

        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("bind_addr")));
        assert!(errors.iter().any(|e| e.contains("client credential")));
    }
}
