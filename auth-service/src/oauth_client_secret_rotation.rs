//! OAuth Client Secret Rotation Implementation
//!
//! Provides automatic and manual client secret rotation capabilities with:
//! - Scheduled rotation based on expiry dates
//! - Emergency rotation for compromised secrets
//! - Graceful transition with multiple active secrets
//! - Comprehensive audit logging
//! - Policy-driven rotation intervals

use chrono::{DateTime, Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres, Row};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Client secret rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRotationPolicy {
    /// Enable automatic secret rotation
    pub automatic_rotation_enabled: bool,

    /// Default secret lifetime in seconds
    pub default_secret_lifetime: u64,

    /// Minimum secret lifetime in seconds
    pub minimum_secret_lifetime: u64,

    /// Maximum secret lifetime in seconds
    pub maximum_secret_lifetime: u64,

    /// Grace period for old secrets after rotation (seconds)
    pub grace_period_seconds: u64,

    /// Warning period before expiry (seconds)
    pub warning_period_seconds: u64,

    /// Maximum number of active secrets per client
    pub max_active_secrets: u32,

    /// Require rotation on security events
    pub rotate_on_security_events: bool,

    /// Notify webhook URLs on rotation
    pub notification_webhooks: Vec<String>,

    /// Emergency rotation triggers
    pub emergency_triggers: Vec<String>,
}

impl Default for SecretRotationPolicy {
    fn default() -> Self {
        Self {
            automatic_rotation_enabled: true,
            default_secret_lifetime: 86400 * 90,  // 90 days
            minimum_secret_lifetime: 86400 * 7,   // 7 days
            maximum_secret_lifetime: 86400 * 365, // 1 year
            grace_period_seconds: 86400 * 7,      // 7 days
            warning_period_seconds: 86400 * 14,   // 14 days
            max_active_secrets: 2,
            rotate_on_security_events: true,
            notification_webhooks: vec![],
            emergency_triggers: vec![
                "compromised".to_string(),
                "breach".to_string(),
                "unauthorized_access".to_string(),
            ],
        }
    }
}

/// Client secret rotation reasons
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationReason {
    Scheduled,
    Expiring,
    Compromised,
    Manual,
    Policy,
    Emergency(String),
}

impl RotationReason {
    pub fn as_str(&self) -> &str {
        match self {
            RotationReason::Scheduled => "scheduled",
            RotationReason::Expiring => "expiring",
            RotationReason::Compromised => "compromised",
            RotationReason::Manual => "manual",
            RotationReason::Policy => "policy",
            RotationReason::Emergency(_) => "emergency",
        }
    }
}

/// Client secret information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSecret {
    pub id: i64,
    pub client_id: String,
    pub secret_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub rotation_reason: Option<String>,
}

/// Secret rotation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRotationResult {
    pub client_id: String,
    pub new_secret: String,
    pub new_secret_id: i64,
    pub expires_at: DateTime<Utc>,
    pub previous_secret_expires_at: Option<DateTime<Utc>>,
    pub rotation_reason: String,
    pub created_at: DateTime<Utc>,
}

/// Secret rotation notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationNotification {
    pub client_id: String,
    pub notification_type: String,
    pub secret_expires_at: DateTime<Utc>,
    pub days_until_expiry: i64,
    pub rotation_reason: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// OAuth client secret rotation manager
pub struct ClientSecretRotationManager {
    db_pool: Pool<Postgres>,
    policy: SecretRotationPolicy,
    notification_queue: Arc<RwLock<Vec<RotationNotification>>>,
}

impl ClientSecretRotationManager {
    pub fn new(db_pool: Pool<Postgres>, policy: SecretRotationPolicy) -> Self {
        Self {
            db_pool,
            policy,
            notification_queue: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Rotate client secret
    pub async fn rotate_client_secret(
        &self,
        client_id: &str,
        reason: RotationReason,
        requested_lifetime: Option<u64>,
    ) -> Result<SecretRotationResult, SecretRotationError> {
        // Validate client exists and is active
        self.validate_client(client_id).await?;

        // Generate new secret
        let new_secret = generate_client_secret();
        let new_secret_hash = hash_secret(&new_secret);

        // Calculate expiry
        let lifetime = self.calculate_secret_lifetime(requested_lifetime)?;
        let now = Utc::now();
        let expires_at = now + Duration::seconds(lifetime as i64);

        // Start transaction
        let mut tx = self
            .db_pool
            .begin()
            .await
            .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        // Get current active secrets
        let current_secrets = self.get_active_secrets_tx(&mut tx, client_id).await?;

        // Check if we have room for a new secret
        if current_secrets.len() >= self.policy.max_active_secrets as usize {
            // Revoke the oldest secret
            if let Some(oldest) = current_secrets.iter().min_by_key(|s| s.created_at) {
                self.revoke_secret_tx(&mut tx, oldest.id, "max_secrets_exceeded")
                    .await?;
            }
        }

        // Insert new secret
        let new_secret_id = sqlx::query_scalar::<_, i64>(
            r#"
            INSERT INTO oauth_client_secrets (
                client_id, secret_hash, created_at, expires_at, 
                is_active, rotation_reason
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(client_id)
        .bind(&new_secret_hash)
        .bind(&now)
        .bind(&expires_at)
        .bind(true)
        .bind(reason.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        // Update main client table with new secret
        sqlx::query(
            r#"
            UPDATE oauth_clients 
            SET client_secret_hash = $2, client_secret_expires_at = $3, updated_at = $4
            WHERE client_id = $1
            "#,
        )
        .bind(client_id)
        .bind(&new_secret_hash)
        .bind(&expires_at)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        // Log rotation event
        sqlx::query(
            r#"
            INSERT INTO oauth_client_registrations (
                client_id, created_at, event_type, metadata
            ) VALUES ($1, $2, 'secret_rotated', $3)
            "#,
        )
        .bind(client_id)
        .bind(&now)
        .bind(serde_json::json!({
            "rotation_reason": reason.as_str(),
            "new_secret_id": new_secret_id,
            "expires_at": expires_at,
            "lifetime_seconds": lifetime
        }))
        .execute(&mut *tx)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        // Commit transaction
        tx.commit()
            .await
            .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        // Calculate previous secret expiry
        let previous_secret_expires_at = current_secrets
            .iter()
            .filter(|s| s.is_active)
            .map(|s| s.expires_at)
            .max();

        // Schedule notification
        self.schedule_rotation_notification(
            client_id,
            "secret_rotated",
            expires_at,
            Some(reason.as_str()),
        )
        .await;

        info!(
            "Client secret rotated for client: {} (reason: {}, new_secret_id: {})",
            client_id,
            reason.as_str(),
            new_secret_id
        );

        Ok(SecretRotationResult {
            client_id: client_id.to_string(),
            new_secret,
            new_secret_id,
            expires_at,
            previous_secret_expires_at,
            rotation_reason: reason.as_str().to_string(),
            created_at: now,
        })
    }

    /// Get all active secrets for a client
    pub async fn get_active_secrets(
        &self,
        client_id: &str,
    ) -> Result<Vec<ClientSecret>, SecretRotationError> {
        let mut tx = self
            .db_pool
            .begin()
            .await
            .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        let secrets = self.get_active_secrets_tx(&mut tx, client_id).await?;

        tx.commit()
            .await
            .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        Ok(secrets)
    }

    /// Check if secrets need rotation (expiring soon)
    pub async fn check_expiring_secrets(&self) -> Result<Vec<String>, SecretRotationError> {
        let warning_threshold =
            Utc::now() + Duration::seconds(self.policy.warning_period_seconds as i64);

        let client_ids: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT c.client_id 
            FROM oauth_clients c
            INNER JOIN oauth_client_secrets s ON c.client_id = s.client_id
            WHERE s.is_active = TRUE 
              AND s.expires_at <= $1
              AND c.status = 'active'
            ORDER BY s.expires_at ASC
            "#,
        )
        .bind(&warning_threshold)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        debug!("Found {} clients with expiring secrets", client_ids.len());
        Ok(client_ids)
    }

    /// Automatically rotate expiring secrets
    pub async fn rotate_expiring_secrets(
        &self,
    ) -> Result<Vec<SecretRotationResult>, SecretRotationError> {
        if !self.policy.automatic_rotation_enabled {
            return Ok(vec![]);
        }

        let expiring_clients = self.check_expiring_secrets().await?;
        let mut results = Vec::new();

        for client_id in expiring_clients {
            match self
                .rotate_client_secret(&client_id, RotationReason::Expiring, None)
                .await
            {
                Ok(result) => {
                    results.push(result);
                }
                Err(e) => {
                    error!("Failed to rotate secret for client {}: {}", client_id, e);
                    // Continue with other clients
                }
            }
        }

        if !results.is_empty() {
            info!(
                "Automatically rotated {} expiring client secrets",
                results.len()
            );
        }

        Ok(results)
    }

    /// Emergency rotation for all clients (security incident)
    pub async fn emergency_rotation_all(
        &self,
        reason: &str,
    ) -> Result<Vec<SecretRotationResult>, SecretRotationError> {
        let client_ids: Vec<String> =
            sqlx::query_scalar("SELECT client_id FROM oauth_clients WHERE status = 'active'")
                .fetch_all(&self.db_pool)
                .await
                .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        let mut results = Vec::new();
        let emergency_reason = RotationReason::Emergency(reason.to_string());

        for client_id in client_ids {
            match self
                .rotate_client_secret(&client_id, emergency_reason.clone(), None)
                .await
            {
                Ok(result) => {
                    results.push(result);
                }
                Err(e) => {
                    error!("Failed emergency rotation for client {}: {}", client_id, e);
                    // Continue with other clients
                }
            }
        }

        warn!(
            "Emergency rotation completed: {} clients rotated (reason: {})",
            results.len(),
            reason
        );

        Ok(results)
    }

    /// Revoke a specific secret
    pub async fn revoke_secret(
        &self,
        client_id: &str,
        secret_id: i64,
        reason: &str,
    ) -> Result<(), SecretRotationError> {
        let mut tx = self
            .db_pool
            .begin()
            .await
            .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        // Verify the secret belongs to the client
        let secret_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM oauth_client_secrets WHERE id = $1 AND client_id = $2)",
        )
        .bind(secret_id)
        .bind(client_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        if !secret_exists {
            return Err(SecretRotationError::SecretNotFound);
        }

        self.revoke_secret_tx(&mut tx, secret_id, reason).await?;

        // Log revocation event
        sqlx::query(
            r#"
            INSERT INTO oauth_client_registrations (
                client_id, created_at, event_type, metadata
            ) VALUES ($1, $2, 'secret_revoked', $3)
            "#,
        )
        .bind(client_id)
        .bind(Utc::now())
        .bind(serde_json::json!({
            "secret_id": secret_id,
            "revocation_reason": reason
        }))
        .execute(&mut *tx)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        info!(
            "Secret {} revoked for client {} (reason: {})",
            secret_id, client_id, reason
        );
        Ok(())
    }

    /// Cleanup expired secrets
    pub async fn cleanup_expired_secrets(&self) -> Result<u64, SecretRotationError> {
        let grace_period_end =
            Utc::now() - Duration::seconds(self.policy.grace_period_seconds as i64);

        let deleted_count = sqlx::query(
            r#"
            UPDATE oauth_client_secrets 
            SET is_active = FALSE, revoked_at = NOW()
            WHERE expires_at < $1 AND is_active = TRUE
            "#,
        )
        .bind(&grace_period_end)
        .execute(&self.db_pool)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?
        .rows_affected();

        if deleted_count > 0 {
            debug!("Cleaned up {} expired client secrets", deleted_count);
        }

        Ok(deleted_count)
    }

    /// Get rotation history for a client
    pub async fn get_rotation_history(
        &self,
        client_id: &str,
        limit: Option<u32>,
    ) -> Result<Vec<ClientSecret>, SecretRotationError> {
        let limit = limit.unwrap_or(50).min(500); // Cap at 500

        let secrets = sqlx::query(
            r#"
            SELECT id, client_id, secret_hash, created_at, expires_at, 
                   revoked_at, is_active, rotation_reason
            FROM oauth_client_secrets 
            WHERE client_id = $1 
            ORDER BY created_at DESC 
            LIMIT $2
            "#,
        )
        .bind(client_id)
        .bind(limit as i64)
        .fetch_all(&self.db_pool)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?
        .into_iter()
        .map(|row| ClientSecret {
            id: row.get("id"),
            client_id: row.get("client_id"),
            secret_hash: row.get("secret_hash"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            revoked_at: row.get("revoked_at"),
            is_active: row.get("is_active"),
            rotation_reason: row.get("rotation_reason"),
        })
        .collect();

        Ok(secrets)
    }

    /// Validate secret and return client_id if valid
    pub async fn validate_client_secret(
        &self,
        client_id: &str,
        secret: &str,
    ) -> Result<bool, SecretRotationError> {
        let secret_hash = hash_secret(secret);

        let is_valid: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM oauth_client_secrets 
                WHERE client_id = $1 
                  AND secret_hash = $2 
                  AND is_active = TRUE 
                  AND expires_at > NOW()
            )
            "#,
        )
        .bind(client_id)
        .bind(&secret_hash)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        Ok(is_valid)
    }

    /// Get pending notifications
    pub async fn get_pending_notifications(&self) -> Vec<RotationNotification> {
        let mut queue = self.notification_queue.write().await;
        let notifications = queue.clone();
        queue.clear();
        notifications
    }

    // Private helper methods

    async fn validate_client(&self, client_id: &str) -> Result<(), SecretRotationError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM oauth_clients WHERE client_id = $1 AND status = 'active')",
        )
        .bind(client_id)
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        if !exists {
            return Err(SecretRotationError::ClientNotFound);
        }

        Ok(())
    }

    fn calculate_secret_lifetime(
        &self,
        requested: Option<u64>,
    ) -> Result<u64, SecretRotationError> {
        let lifetime = requested.unwrap_or(self.policy.default_secret_lifetime);

        if lifetime < self.policy.minimum_secret_lifetime {
            return Err(SecretRotationError::InvalidLifetime(format!(
                "Lifetime too short. Minimum: {} seconds",
                self.policy.minimum_secret_lifetime
            )));
        }

        if lifetime > self.policy.maximum_secret_lifetime {
            return Err(SecretRotationError::InvalidLifetime(format!(
                "Lifetime too long. Maximum: {} seconds",
                self.policy.maximum_secret_lifetime
            )));
        }

        Ok(lifetime)
    }

    async fn get_active_secrets_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        client_id: &str,
    ) -> Result<Vec<ClientSecret>, SecretRotationError> {
        let secrets = sqlx::query(
            r#"
            SELECT id, client_id, secret_hash, created_at, expires_at, 
                   revoked_at, is_active, rotation_reason
            FROM oauth_client_secrets 
            WHERE client_id = $1 AND is_active = TRUE
            ORDER BY created_at DESC
            "#,
        )
        .bind(client_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?
        .into_iter()
        .map(|row| ClientSecret {
            id: row.get("id"),
            client_id: row.get("client_id"),
            secret_hash: row.get("secret_hash"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            revoked_at: row.get("revoked_at"),
            is_active: row.get("is_active"),
            rotation_reason: row.get("rotation_reason"),
        })
        .collect();

        Ok(secrets)
    }

    async fn revoke_secret_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        secret_id: i64,
        reason: &str,
    ) -> Result<(), SecretRotationError> {
        sqlx::query(
            r#"
            UPDATE oauth_client_secrets 
            SET is_active = FALSE, revoked_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(secret_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| SecretRotationError::DatabaseError(e.to_string()))?;

        debug!("Secret {} revoked (reason: {})", secret_id, reason);
        Ok(())
    }

    async fn schedule_rotation_notification(
        &self,
        client_id: &str,
        notification_type: &str,
        expires_at: DateTime<Utc>,
        rotation_reason: Option<&str>,
    ) {
        let days_until_expiry = (expires_at - Utc::now()).num_days();

        let notification = RotationNotification {
            client_id: client_id.to_string(),
            notification_type: notification_type.to_string(),
            secret_expires_at: expires_at,
            days_until_expiry,
            rotation_reason: rotation_reason.map(|s| s.to_string()),
            timestamp: Utc::now(),
        };

        let mut queue = self.notification_queue.write().await;
        queue.push(notification);
    }
}

/// Secret rotation errors
#[derive(Debug, thiserror::Error)]
pub enum SecretRotationError {
    #[error("Client not found")]
    ClientNotFound,

    #[error("Secret not found")]
    SecretNotFound,

    #[error("Invalid secret lifetime: {0}")]
    InvalidLifetime(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),
}

/// Utility functions
fn generate_client_secret() -> String {
    // Generate a cryptographically strong secret
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Background task for automatic secret rotation
pub async fn start_automatic_rotation_task(
    manager: Arc<ClientSecretRotationManager>,
    check_interval_seconds: u64,
) {
    let mut interval =
        tokio::time::interval(std::time::Duration::from_secs(check_interval_seconds));

    loop {
        interval.tick().await;

        // Check and rotate expiring secrets
        if let Err(e) = manager.rotate_expiring_secrets().await {
            error!("Automatic secret rotation failed: {}", e);
        }

        // Cleanup expired secrets
        if let Err(e) = manager.cleanup_expired_secrets().await {
            error!("Secret cleanup failed: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_generation() {
        let secret = generate_client_secret();
        assert_eq!(secret.len(), 64);
        assert!(secret.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_secret_hashing() {
        let secret = "test_secret";
        let hash1 = hash_secret(secret);
        let hash2 = hash_secret(secret);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex string
    }

    #[test]
    fn test_rotation_reason_as_str() {
        assert_eq!(RotationReason::Scheduled.as_str(), "scheduled");
        assert_eq!(RotationReason::Compromised.as_str(), "compromised");
        assert_eq!(
            RotationReason::Emergency("breach".to_string()).as_str(),
            "emergency"
        );
    }
}
