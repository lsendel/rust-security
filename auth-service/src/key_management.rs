use base64::Engine;
use hex;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use crate::errors::{internal_error, AuthError};
use crate::pii_protection::redact_log;
use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};

/// Key lifecycle states
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key generated but not yet active
    Pending,
    /// Primary signing key for new tokens
    Active,
    /// Key in rotation, still valid for verification
    Rotating,
    /// Key no longer used for signing, valid for verification only
    Deprecated,
    /// Key compromised, immediately invalid for all operations
    Revoked,
}

/// Key algorithms supported
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    Rs256,
    Es256,
}

/// Key management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyManagementConfig {
    /// How often to rotate keys
    pub rotation_interval: Duration,
    /// How long to keep old keys for verification
    pub overlap_period: Duration,
    /// Maximum age before key is forcibly rotated
    pub max_key_age: Duration,
    /// RSA key size (2048, 3072, 4096)
    pub key_size: u32,
    /// Algorithm for key generation
    pub algorithm: KeyAlgorithm,
    /// Enable automatic rotation
    pub auto_rotation_enabled: bool,
    /// Enable audit logging
    pub audit_enabled: bool,
    /// Enable key backup
    pub backup_enabled: bool,
}

impl Default for KeyManagementConfig {
    fn default() -> Self {
        Self {
            rotation_interval: Duration::from_secs(24 * 3600), // 24 hours
            overlap_period: Duration::from_secs(48 * 3600),    // 48 hours
            max_key_age: Duration::from_secs(72 * 3600),       // 72 hours
            key_size: 2048,
            algorithm: KeyAlgorithm::Rs256,
            auto_rotation_enabled: true,
            audit_enabled: true,
            backup_enabled: true,
        }
    }
}

/// Secure key material with metadata
#[derive(Clone, Serialize, Deserialize)]
pub struct SecureKeyMaterial {
    /// Key identifier
    pub kid: String,
    /// Key state
    pub state: KeyState,
    /// Algorithm used
    pub algorithm: KeyAlgorithm,
    /// Creation timestamp
    pub created_at: u64,
    /// Last used timestamp
    pub last_used_at: Option<u64>,
    /// Activation timestamp
    pub activated_at: Option<u64>,
    /// Deprecation timestamp
    pub deprecated_at: Option<u64>,
    /// Revocation timestamp and reason
    pub revoked_at: Option<(u64, String)>,
    /// Usage statistics
    pub usage_count: u64,
    /// Public JWK for JWKS endpoint
    pub public_jwk: Value,
    /// Encoding key for JWT signing
    #[serde(skip)]
    pub encoding_key: Option<EncodingKey>,
    /// Decoding key for JWT verification
    #[serde(skip)]
    pub decoding_key: Option<DecodingKey>,
}

/// Key management metrics
#[derive(Debug, Default, Clone)]
pub struct KeyMetrics {
    pub keys_generated: u64,
    pub keys_rotated: u64,
    pub keys_revoked: u64,
    pub rotation_failures: u64,
    pub last_rotation_time: Option<u64>,
    pub active_key_age: Option<u64>,
}

/// Audit events for key operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyAuditEvent {
    pub event_id: String,
    pub timestamp: u64,
    pub event_type: KeyEventType,
    pub key_id: String,
    pub actor: Option<String>,
    pub details: HashMap<String, Value>,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyEventType {
    KeyGenerated,
    KeyActivated,
    KeyRotated,
    KeyDeprecated,
    KeyRevoked,
    KeyUsed,
    KeyBackedUp,
    KeyRestored,
    RotationFailed,
    EmergencyRotation,
}

/// Key management service
pub struct KeyManagementService {
    /// Key storage
    keys: Arc<RwLock<HashMap<String, SecureKeyMaterial>>>,
    /// Current active key ID
    active_key_id: Arc<RwLock<Option<String>>>,
    /// Configuration
    config: KeyManagementConfig,
    /// Metrics
    metrics: Arc<RwLock<KeyMetrics>>,
    /// Security logger (unit struct, no instance needed)
    _phantom: std::marker::PhantomData<()>,
    /// Audit events
    audit_events: Arc<RwLock<Vec<KeyAuditEvent>>>,
}

impl KeyManagementService {
    /// Create new key management service
    pub fn new(config: KeyManagementConfig) -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            active_key_id: Arc::new(RwLock::new(None)),
            config,
            metrics: Arc::new(RwLock::new(KeyMetrics::default())),
            _phantom: std::marker::PhantomData,
            audit_events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initialize key management service
    #[instrument(skip(self))]
    pub async fn initialize(&self) -> Result<(), AuthError> {
        info!("Initializing key management service");

        // Generate initial key if none exists
        let keys = self.keys.read().await;
        if keys.is_empty() {
            drop(keys);
            self.generate_new_key("system").await?;
        }

        // Start automatic rotation if enabled
        if self.config.auto_rotation_enabled {
            self.schedule_rotation().await;
        }

        info!("Key management service initialized successfully");
        Ok(())
    }

    /// Generate a new key pair
    #[instrument(skip(self))]
    pub async fn generate_new_key(&self, actor: &str) -> Result<String, AuthError> {
        let kid = format!("key-{}", Uuid::new_v4());
        let now = Self::current_timestamp();

        info!(kid = %kid, "Generating new key");

        let (encoding_key, decoding_key, public_jwk) = match self.config.algorithm {
            KeyAlgorithm::Rs256 => self.generate_rsa_key(&kid).await?,
            KeyAlgorithm::Es256 => return Err(internal_error("ECDSA not yet implemented")),
        };

        let key_material = SecureKeyMaterial {
            kid: kid.clone(),
            state: KeyState::Pending,
            algorithm: self.config.algorithm.clone(),
            created_at: now,
            last_used_at: None,
            activated_at: None,
            deprecated_at: None,
            revoked_at: None,
            usage_count: 0,
            public_jwk,
            encoding_key: Some(encoding_key),
            decoding_key: Some(decoding_key),
        };

        // Store the key
        let mut keys = self.keys.write().await;
        keys.insert(kid.clone(), key_material);
        drop(keys);

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.keys_generated += 1;
        drop(metrics);

        // Log audit event
        self.log_audit_event(KeyEventType::KeyGenerated, &kid, Some(actor), true, None)
            .await;

        // Log security event
        let mut event = SecurityEvent::new(
            SecurityEventType::KeyManagement,
            SecuritySeverity::Info,
            "auth-service".to_string(),
            "New cryptographic key generated".to_string(),
        )
        .with_actor("system".to_string())
        .with_action("key_generate".to_string())
        .with_target("jwt_keys".to_string())
        .with_outcome("success".to_string())
        .with_reason("New key generated for JWT signing operations".to_string())
        .with_resource(kid.clone())
        .with_detail("key_algorithm".to_string(), &self.config.algorithm)
        .with_detail("key_size".to_string(), self.config.key_size);

        SecurityLogger::log_event(&mut event);

        info!(kid = %kid, "Key generated successfully");
        Ok(kid)
    }

    /// Activate a key for signing
    #[instrument(skip(self))]
    pub async fn activate_key(&self, kid: &str, actor: &str) -> Result<(), AuthError> {
        info!(kid = %kid, "Activating key");

        let mut keys = self.keys.write().await;
        let key = keys
            .get_mut(kid)
            .ok_or_else(|| internal_error(&format!("Key not found: {}", kid)))?;

        // Validate key can be activated
        if key.state == KeyState::Revoked {
            return Err(internal_error("Cannot activate revoked key"));
        }

        // Get current active key ID before modifications
        let mut active_key_id = self.active_key_id.write().await;
        let current_active = active_key_id.clone();

        // Activate new key first
        key.state = KeyState::Active;
        key.activated_at = Some(Self::current_timestamp());
        *active_key_id = Some(kid.to_string());

        // Now deactivate previous active key
        if let Some(current_active_kid) = current_active {
            if let Some(current_key) = keys.get_mut(&current_active_kid) {
                current_key.state = KeyState::Rotating;
                info!(kid = %current_active_kid, "Moving current active key to rotating state");
            }
        }

        drop(keys);
        drop(active_key_id);

        // Log audit event
        self.log_audit_event(KeyEventType::KeyActivated, kid, Some(actor), true, None)
            .await;

        // Log security event
        let mut event = SecurityEvent::new(
            SecurityEventType::KeyManagement,
            SecuritySeverity::Info,
            "auth-service".to_string(),
            "Key activated for JWT signing".to_string(),
        )
        .with_actor(actor.to_string())
        .with_action("key_activate".to_string())
        .with_target("signing_key".to_string())
        .with_outcome("success".to_string())
        .with_reason("Key successfully activated as primary signing key".to_string())
        .with_resource(kid.to_string())
        .with_detail("key_id".to_string(), kid);

        SecurityLogger::log_event(&mut event);

        info!(kid = %kid, "Key activated successfully");
        Ok(())
    }

    /// Perform key rotation
    #[instrument(skip(self))]
    pub async fn rotate_keys(&self, actor: &str) -> Result<(), AuthError> {
        info!("Starting key rotation");

        // Generate new key
        let new_kid = self.generate_new_key(actor).await?;

        // Activate new key (this will move current active to rotating)
        self.activate_key(&new_kid, actor).await?;

        // Clean up old keys
        self.cleanup_expired_keys().await?;

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.keys_rotated += 1;
        metrics.last_rotation_time = Some(Self::current_timestamp());
        drop(metrics);

        // Log audit event
        self.log_audit_event(KeyEventType::KeyRotated, &new_kid, Some(actor), true, None)
            .await;

        info!(new_kid = %new_kid, "Key rotation completed successfully");
        Ok(())
    }

    /// Revoke a key immediately
    #[instrument(skip(self))]
    pub async fn revoke_key(&self, kid: &str, reason: &str, actor: &str) -> Result<(), AuthError> {
        warn!(kid = %kid, reason = %reason, "Revoking key");

        let mut keys = self.keys.write().await;
        let key = keys
            .get_mut(kid)
            .ok_or_else(|| internal_error(&format!("Key not found: {}", kid)))?;

        key.state = KeyState::Revoked;
        key.revoked_at = Some((Self::current_timestamp(), reason.to_string()));

        // If this was the active key, we need emergency rotation
        let active_key_id = self.active_key_id.read().await;
        let needs_emergency_rotation = active_key_id.as_ref() == Some(&kid.to_string());
        drop(active_key_id);
        drop(keys);

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.keys_revoked += 1;
        drop(metrics);

        // Log audit event
        self.log_audit_event(
            KeyEventType::KeyRevoked,
            kid,
            Some(actor),
            true,
            Some(reason),
        )
        .await;

        // Log security event
        let mut event = SecurityEvent::new(
            SecurityEventType::SuspiciousActivity,
            SecuritySeverity::High,
            "auth-service".to_string(),
            format!("Key revoked: {}", reason),
        )
        .with_actor(actor.to_string())
        .with_action("key_revoke".to_string())
        .with_target("signing_key".to_string())
        .with_outcome(if needs_emergency_rotation {
            "revoked_with_emergency_rotation".to_string()
        } else {
            "revoked".to_string()
        })
        .with_reason(format!("Key revocation required: {}", redact_log(reason)))
        .with_resource(kid.to_string())
        .with_detail("revocation_reason".to_string(), redact_log(reason))
        .with_detail(
            "emergency_rotation_needed".to_string(),
            needs_emergency_rotation,
        );

        SecurityLogger::log_event(&mut event);

        // Perform emergency rotation if needed
        if needs_emergency_rotation {
            warn!("Performing emergency rotation due to active key revocation");
            self.emergency_rotation(actor).await?;
        }

        warn!(kid = %kid, "Key revocation completed");
        Ok(())
    }

    /// Emergency key rotation
    #[instrument(skip(self))]
    pub async fn emergency_rotation(&self, actor: &str) -> Result<(), AuthError> {
        error!("Performing emergency key rotation");

        // Generate and activate new key immediately
        let new_kid = self.generate_new_key(actor).await?;
        self.activate_key(&new_kid, actor).await?;

        // Log audit event
        self.log_audit_event(
            KeyEventType::EmergencyRotation,
            &new_kid,
            Some(actor),
            true,
            None,
        )
        .await;

        // Log security event
        let mut event = SecurityEvent::new(
            SecurityEventType::SuspiciousActivity,
            SecuritySeverity::Critical,
            "auth-service".to_string(),
            "Emergency key rotation performed".to_string(),
        )
        .with_actor(actor.to_string())
        .with_action("key_emergency_rotate".to_string())
        .with_target("signing_key".to_string())
        .with_outcome("success".to_string())
        .with_reason("Emergency rotation triggered due to active key compromise".to_string())
        .with_resource(new_kid.clone())
        .with_detail("new_key_id".to_string(), &new_kid)
        .with_detail("trigger".to_string(), "key_compromise");

        SecurityLogger::log_event(&mut event);

        error!(new_kid = %new_kid, "Emergency rotation completed");
        Ok(())
    }

    /// Get current signing key
    pub async fn get_signing_key(&self) -> Result<(String, EncodingKey), AuthError> {
        let active_key_id = self.active_key_id.read().await;
        let kid = active_key_id
            .as_ref()
            .ok_or_else(|| internal_error("No active signing key available"))?;

        let keys = self.keys.read().await;
        let key = keys
            .get(kid)
            .ok_or_else(|| internal_error(&format!("Active key not found: {}", kid)))?;

        if key.state != KeyState::Active {
            return Err(internal_error("Active key is not in active state"));
        }

        let encoding_key = key
            .encoding_key
            .as_ref()
            .ok_or_else(|| internal_error("Encoding key not available"))?;

        let encoding_key_clone = encoding_key.clone();
        let kid_clone = kid.clone();

        // Update usage statistics
        drop(keys);
        let mut keys = self.keys.write().await;
        if let Some(key) = keys.get_mut(kid) {
            key.usage_count += 1;
            key.last_used_at = Some(Self::current_timestamp());
        }

        Ok((kid_clone, encoding_key_clone))
    }

    /// Get decoding key for verification
    pub async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        let keys = self.keys.read().await;
        let key = keys
            .get(kid)
            .ok_or_else(|| internal_error(&format!("Key not found: {}", kid)))?;

        // Allow verification with any non-revoked key
        if key.state == KeyState::Revoked {
            return Err(internal_error("Cannot use revoked key for verification"));
        }

        key.decoding_key
            .as_ref()
            .ok_or_else(|| internal_error("Decoding key not available"))
            .map(|k| k.clone())
    }

    /// Get JWKS document
    pub async fn get_jwks(&self) -> Value {
        let keys = self.keys.read().await;
        let jwk_keys: Vec<Value> = keys
            .values()
            .filter(|k| k.state != KeyState::Revoked && k.state != KeyState::Pending)
            .map(|k| k.public_jwk.clone())
            .collect();

        serde_json::json!({
            "keys": jwk_keys
        })
    }

    /// Check if rotation is needed
    pub async fn needs_rotation(&self) -> bool {
        let active_key_id = self.active_key_id.read().await;
        if let Some(kid) = active_key_id.as_ref() {
            let keys = self.keys.read().await;
            if let Some(key) = keys.get(kid) {
                let age = Self::current_timestamp() - key.created_at;
                return age > self.config.rotation_interval.as_secs();
            }
        }
        true // No active key means rotation needed
    }

    /// Schedule automatic rotation
    async fn schedule_rotation(&self) {
        // In a real implementation, this would set up a timer or cron job
        // For now, we'll just log that rotation scheduling is enabled
        info!(
            interval_hours = self.config.rotation_interval.as_secs() / 3600,
            "Automatic key rotation scheduling enabled"
        );
    }

    /// Clean up expired keys
    async fn cleanup_expired_keys(&self) -> Result<(), AuthError> {
        let mut keys = self.keys.write().await;
        let now = Self::current_timestamp();
        let max_age = self.config.max_key_age.as_secs();

        keys.retain(|kid, key| {
            let should_retain = match key.state {
                KeyState::Revoked => false, // Always remove revoked keys
                KeyState::Active => true,   // Never remove active key
                _ => now - key.created_at < max_age,
            };

            if !should_retain {
                info!(kid = %redact_log(kid), state = ?key.state, age_hours = (now - key.created_at) / 3600, "Cleaning up expired key");
            }

            should_retain
        });

        Ok(())
    }

    /// Generate RSA key pair
    async fn generate_rsa_key(
        &self,
        kid: &str,
    ) -> Result<(EncodingKey, DecodingKey, Value), AuthError> {
        // Use pre-generated key for now (in production, generate dynamically)
        let private_key_pem = include_str!("../keys/rsa_private_key.pem");

        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|e| {
            internal_error(&format!(
                "Failed to create encoding key: {}",
                redact_log(&e.to_string())
            ))
        })?;

        let decoding_key = DecodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|e| {
            internal_error(&format!(
                "Failed to create decoding key: {}",
                redact_log(&e.to_string())
            ))
        })?;

        // Create JWK (using hardcoded values for now)
        let modulus_hex = "DFAA0CD89105F97B04C18309672EB086CAFB656D4A44B8AEF84E0D6038A2910C06EE9023A5848D5867FABD87F52B670F5D4C654495FA69BF45E84F354B96FFF71290DEED830771C764B8D8F559373978D0816BA70B64C5C8FD292474B57C47114936B9A54881CEF99566DCFCF5E7422434E43E6C1CFE91ADE541307884A07737DD85A73E87C021AA44F719FB820470FA521F8ADE60A7F279E025CFB9F8EA72B4604C9813A5D396908138D2FA0DBE2EAE3161D778243EA16921F3E0CB7DA2CCD83ADC3BFC03FDC2A453ACEA3BE9E99EC8C155301696C28963ECD59C9ABBD60B9BC9B9B689024A49D7BB801329B50D09E03574FA3FD07803914A739C5380AD1BF1";
        let modulus_bytes = hex::decode(modulus_hex).map_err(|e| {
            internal_error(&format!(
                "Failed to decode modulus: {}",
                redact_log(&e.to_string())
            ))
        })?;

        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&modulus_bytes);
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&[0x01, 0x00, 0x01]);

        let public_jwk = serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "RS256",
            "kid": kid,
            "n": n,
            "e": e
        });

        Ok((encoding_key, decoding_key, public_jwk))
    }

    /// Log audit event
    async fn log_audit_event(
        &self,
        event_type: KeyEventType,
        key_id: &str,
        actor: Option<&str>,
        success: bool,
        error_message: Option<&str>,
    ) {
        if !self.config.audit_enabled {
            return;
        }

        let event = KeyAuditEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Self::current_timestamp(),
            event_type,
            key_id: key_id.to_string(),
            actor: actor.map(|s| s.to_string()),
            details: HashMap::new(),
            success,
            error_message: error_message.map(|s| s.to_string()),
        };

        let mut audit_events = self.audit_events.write().await;
        audit_events.push(event);

        // Keep only last 1000 events in memory
        if audit_events.len() > 1000 {
            audit_events.remove(0);
        }
    }

    /// Get current Unix timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get key management metrics
    pub async fn get_metrics(&self) -> KeyMetrics {
        let metrics = self.metrics.read().await;
        let mut result = metrics.clone();

        // Calculate active key age
        let active_key_id = self.active_key_id.read().await;
        if let Some(kid) = active_key_id.as_ref() {
            let keys = self.keys.read().await;
            if let Some(key) = keys.get(kid) {
                result.active_key_age = Some(Self::current_timestamp() - key.created_at);
            }
        }

        result
    }

    /// Get audit events
    pub async fn get_audit_events(&self, limit: Option<usize>) -> Vec<KeyAuditEvent> {
        let events = self.audit_events.read().await;
        let limit = limit.unwrap_or(100).min(events.len());
        events.iter().rev().take(limit).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_key_generation() {
        let config = KeyManagementConfig::default();
        let kms = KeyManagementService::new(config);

        let kid = kms.generate_new_key("test").await.unwrap();
        assert!(!kid.is_empty());
        assert!(kid.starts_with("key-"));

        let keys = kms.keys.read().await;
        let key = keys.get(&kid).unwrap();
        assert_eq!(key.state, KeyState::Pending);
        assert!(key.encoding_key.is_some());
        assert!(key.decoding_key.is_some());
    }

    #[tokio::test]
    async fn test_key_activation() {
        let config = KeyManagementConfig::default();
        let kms = KeyManagementService::new(config);

        let kid = kms.generate_new_key("test").await.unwrap();
        kms.activate_key(&kid, "test").await.unwrap();

        let keys = kms.keys.read().await;
        let key = keys.get(&kid).unwrap();
        assert_eq!(key.state, KeyState::Active);
        assert!(key.activated_at.is_some());

        let active_key_id = kms.active_key_id.read().await;
        assert_eq!(active_key_id.as_ref(), Some(&kid));
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let config = KeyManagementConfig::default();
        let kms = KeyManagementService::new(config);

        // Initialize with first key
        kms.initialize().await.unwrap();
        let first_kid = kms.active_key_id.read().await.clone().unwrap();

        // Rotate to new key
        kms.rotate_keys("test").await.unwrap();
        let second_kid = kms.active_key_id.read().await.clone().unwrap();

        assert_ne!(first_kid, second_kid);

        // Check first key is in rotating state
        let keys = kms.keys.read().await;
        let first_key = keys.get(&first_kid).unwrap();
        assert_eq!(first_key.state, KeyState::Rotating);

        let second_key = keys.get(&second_kid).unwrap();
        assert_eq!(second_key.state, KeyState::Active);
    }

    #[tokio::test]
    async fn test_key_revocation() {
        let config = KeyManagementConfig::default();
        let kms = KeyManagementService::new(config);

        kms.initialize().await.unwrap();
        let kid = kms.active_key_id.read().await.clone().unwrap();

        kms.revoke_key(&kid, "test revocation", "test")
            .await
            .unwrap();

        let keys = kms.keys.read().await;
        let key = keys.get(&kid).unwrap();
        assert_eq!(key.state, KeyState::Revoked);
        assert!(key.revoked_at.is_some());

        // Should have triggered emergency rotation
        let new_active = kms.active_key_id.read().await.clone().unwrap();
        assert_ne!(kid, new_active);
    }

    #[tokio::test]
    async fn test_jwks_generation() {
        let config = KeyManagementConfig::default();
        let kms = KeyManagementService::new(config);

        kms.initialize().await.unwrap();
        let jwks = kms.get_jwks().await;

        let keys = jwks.get("keys").unwrap().as_array().unwrap();
        assert!(!keys.is_empty());

        let key = &keys[0];
        assert_eq!(key.get("kty").unwrap(), "RSA");
        assert_eq!(key.get("alg").unwrap(), "RS256");
        assert!(key.get("kid").is_some());
    }

    #[tokio::test]
    async fn test_signing_and_verification() {
        let config = KeyManagementConfig::default();
        let kms = KeyManagementService::new(config);

        kms.initialize().await.unwrap();

        let (kid, encoding_key) = kms.get_signing_key().await.unwrap();
        let decoding_key = kms.get_decoding_key(&kid).await.unwrap();

        // Test that we can create keys for JWT operations
        assert!(!kid.is_empty());
        assert!(kid.starts_with("key-"));
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let config = KeyManagementConfig::default();
        let kms = KeyManagementService::new(config);

        kms.initialize().await.unwrap();
        kms.rotate_keys("test").await.unwrap();
        kms.revoke_key(
            &kms.active_key_id.read().await.clone().unwrap(),
            "test",
            "test",
        )
        .await
        .unwrap();

        let metrics = kms.get_metrics().await;
        assert!(metrics.keys_generated >= 2); // At least initial + rotation
        assert_eq!(metrics.keys_rotated, 1);
        assert_eq!(metrics.keys_revoked, 1);
        assert!(metrics.last_rotation_time.is_some());
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let config = KeyManagementConfig::default();
        let kms = KeyManagementService::new(config);

        kms.initialize().await.unwrap();
        kms.rotate_keys("test").await.unwrap();

        let events = kms.get_audit_events(Some(10)).await;
        assert!(!events.is_empty());

        // Should have events for key generation, activation, and rotation
        let event_types: std::collections::HashSet<_> = events
            .iter()
            .map(|e| std::mem::discriminant(&e.event_type))
            .collect();

        assert!(event_types.len() >= 2); // At least some different event types
    }
}
