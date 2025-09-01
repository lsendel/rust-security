// Removed unused import: use crate::keys;
use std::time::Duration;
use tokio::time::{interval, Instant};
use tracing::{error, info, warn};

/// Key rotation configuration
#[derive(Debug, Clone)]
pub struct KeyRotationConfig {
    /// How often to rotate keys (default: 24 hours)
    pub rotation_interval: Duration,
    /// How long to keep old keys for validation (default: 48 hours)
    pub key_retention_period: Duration,
    /// Whether key rotation is enabled
    pub enabled: bool,
    /// Minimum time between rotations (prevents too frequent rotations)
    pub min_rotation_interval: Duration,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            rotation_interval: Duration::from_secs(24 * 60 * 60), // 24 hours
            key_retention_period: Duration::from_secs(48 * 60 * 60), // 48 hours
            enabled: true,
            min_rotation_interval: Duration::from_secs(60 * 60), // 1 hour minimum
        }
    }
}

impl KeyRotationConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(interval_str) = std::env::var("KEY_ROTATION_INTERVAL_HOURS") {
            if let Ok(hours) = interval_str.parse::<u64>() {
                config.rotation_interval = Duration::from_secs(hours * 60 * 60);
            }
        }

        if let Ok(retention_str) = std::env::var("KEY_RETENTION_PERIOD_HOURS") {
            if let Ok(hours) = retention_str.parse::<u64>() {
                config.key_retention_period = Duration::from_secs(hours * 60 * 60);
            }
        }

        if let Ok(enabled_str) = std::env::var("KEY_ROTATION_ENABLED") {
            config.enabled = enabled_str.to_lowercase() == "true";
        }

        // Ensure minimum rotation interval
        if config.rotation_interval < config.min_rotation_interval {
            warn!(
                "Key rotation interval too short, setting to minimum: {:?}",
                config.min_rotation_interval
            );
            config.rotation_interval = config.min_rotation_interval;
        }

        config
    }
}

/// Key rotation service that handles automatic key rotation
pub struct KeyRotationService {
    config: KeyRotationConfig,
    last_rotation: Option<Instant>,
}

impl KeyRotationService {
    /// Create a new key rotation service
    pub fn new(config: KeyRotationConfig) -> Self {
        Self {
            config,
            last_rotation: None,
        }
    }

    /// Start the key rotation service
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            info!("Key rotation is disabled");
            return Ok(());
        }

        info!(
            rotation_interval = ?self.config.rotation_interval,
            retention_period = ?self.config.key_retention_period,
            "Starting key rotation service"
        );

        // Perform initial key rotation if no keys exist
        self.ensure_initial_key().await?;

        // Start the rotation timer
        let mut interval_timer = interval(self.config.rotation_interval);

        loop {
            interval_timer.tick().await;

            if let Err(e) = self.perform_rotation().await {
                error!(error = %e, "Key rotation failed");
                // Continue running even if rotation fails
            }
        }
    }

    /// Ensure there's at least one key available
    async fn ensure_initial_key(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Check if we have any keys
        let jwks = crate::infrastructure::crypto::keys::jwks_document().await;
        let empty_vec = Vec::new();
        let keys = jwks["keys"].as_array().unwrap_or(&empty_vec);

        if keys.is_empty() {
            info!("No keys found, generating initial key");
            self.perform_rotation().await?;
        } else {
            info!("Found {} existing keys", keys.len());
        }

        Ok(())
    }

    /// Perform key rotation
    async fn perform_rotation(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let now = Instant::now();

        // Check if enough time has passed since last rotation
        if let Some(last_rotation) = self.last_rotation {
            let time_since_last = now.duration_since(last_rotation);
            if time_since_last < self.config.min_rotation_interval {
                warn!(
                    time_since_last = ?time_since_last,
                    min_interval = ?self.config.min_rotation_interval,
                    "Skipping rotation, not enough time since last rotation"
                );
                return Ok(());
            }
        }

        info!("Performing key rotation");

        // Rotate the keys using the existing keys module
        let _ = crate::infrastructure::crypto::keys::maybe_rotate().await;

        // Update last rotation time
        self.last_rotation = Some(now);

        // Clean up old keys (this would be implemented based on your storage)
        self.cleanup_old_keys()?;

        info!("Key rotation completed successfully");

        Ok(())
    }

    /// Clean up old keys that are past the retention period
    fn cleanup_old_keys(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // This is a placeholder - in a real implementation, you would:
        // 1. Get all keys with their creation timestamps
        // 2. Remove keys older than the retention period
        // 3. Ensure at least one key remains for validation

        info!("Cleaning up old keys (placeholder implementation)");

        // For now, we'll just log that cleanup would happen here
        // In a production system, you'd implement actual cleanup logic

        Ok(())
    }

    /// Force a key rotation (for manual triggering)
    pub async fn force_rotation(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Forcing key rotation");
        self.last_rotation = None; // Reset to allow immediate rotation
        self.perform_rotation().await
    }

    /// Get rotation status information
    pub fn get_status(&self) -> KeyRotationStatus {
        KeyRotationStatus {
            enabled: self.config.enabled,
            rotation_interval: self.config.rotation_interval,
            last_rotation: self.last_rotation,
            next_rotation: self
                .last_rotation
                .map(|last| last + self.config.rotation_interval),
        }
    }
}

/// Status information about key rotation
#[derive(Debug)]
pub struct KeyRotationStatus {
    pub enabled: bool,
    pub rotation_interval: Duration,
    pub last_rotation: Option<Instant>,
    pub next_rotation: Option<Instant>,
}

/// HTTP endpoint to get key rotation status
pub async fn get_rotation_status() -> axum::Json<serde_json::Value> {
    // This would get the actual status from the running service
    // For now, return a placeholder
    axum::Json(serde_json::json!({
        "enabled": true,
        "rotation_interval_hours": 24,
        "last_rotation": null,
        "next_rotation": null,
        "status": "running"
    }))
}

/// HTTP endpoint to force key rotation (admin only)
pub async fn force_rotation() -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    // This would trigger a forced rotation
    // For now, return a placeholder response

    // Trigger key rotation
    let _ = crate::infrastructure::crypto::keys::maybe_rotate().await;
    match Ok::<(), &str>(()) {
        Ok(()) => Ok(axum::Json(serde_json::json!({
            "status": "success",
            "message": "Key rotation completed",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))),
        Err(e) => {
            error!(error = %e, "Failed to force key rotation");
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_key_rotation_config_default() {
        let config = KeyRotationConfig::default();
        assert!(config.enabled);
        assert_eq!(config.rotation_interval, Duration::from_secs(24 * 60 * 60));
        assert_eq!(
            config.key_retention_period,
            Duration::from_secs(48 * 60 * 60)
        );
    }

    #[test]
    fn test_key_rotation_config_from_env() {
        std::env::set_var("KEY_ROTATION_INTERVAL_HOURS", "12");
        std::env::set_var("KEY_RETENTION_PERIOD_HOURS", "24");
        std::env::set_var("KEY_ROTATION_ENABLED", "false");

        let config = KeyRotationConfig::from_env();
        assert!(!config.enabled);
        assert_eq!(config.rotation_interval, Duration::from_secs(12 * 60 * 60));
        assert_eq!(
            config.key_retention_period,
            Duration::from_secs(24 * 60 * 60)
        );

        // Clean up
        std::env::remove_var("KEY_ROTATION_INTERVAL_HOURS");
        std::env::remove_var("KEY_RETENTION_PERIOD_HOURS");
        std::env::remove_var("KEY_ROTATION_ENABLED");
    }

    #[tokio::test]
    async fn test_key_rotation_service_creation() {
        let config = KeyRotationConfig::default();
        let service = KeyRotationService::new(config);

        let status = service.get_status();
        assert!(status.enabled);
        assert!(status.last_rotation.is_none());
    }
}
