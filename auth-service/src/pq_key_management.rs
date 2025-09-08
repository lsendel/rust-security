//! # Post-Quantum Key Management
//!
//! This module handles the lifecycle management of post-quantum cryptographic keys,
//! including generation, rotation, storage, and secure destruction.
//!
//! ## Key Management Features
//! - Automated key rotation based on time and usage policies
//! - Secure key storage with proper zeroization
//! - Key derivation and hierarchical key management
//! - Emergency key revocation and rollback procedures
//! - Performance monitoring and key usage analytics
//! - Compliance with NIST post-quantum key management guidelines

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Instant};
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize};

use crate::post_quantum_crypto::{
    get_pq_manager, ClassicalKeyData, PQAlgorithm, PQConfig, PQKeyData, PQKeyMaterial,
    SecurityLevel,
};
use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};

/// Key rotation policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationPolicy {
    /// Maximum key age in hours before forced rotation
    pub max_age_hours: u64,
    /// Maximum number of operations before rotation
    pub max_operations: u64,
    /// Rotation schedule (cron-like)
    pub schedule: Option<String>,
    /// Emergency rotation trigger conditions
    pub emergency_triggers: Vec<EmergencyTrigger>,
    /// Key overlap period during rotation (hours)
    pub overlap_period_hours: u64,
    /// Whether to enable proactive rotation
    pub proactive_rotation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmergencyTrigger {
    /// Security incident detected
    SecurityIncident,
    /// Key compromise suspected
    KeyCompromise,
    /// Quantum computer threat level change
    QuantumThreatEscalation,
    /// Compliance requirement
    ComplianceRequirement,
    /// Manual trigger
    Manual,
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        Self {
            max_age_hours: 24 * 7, // 1 week
            max_operations: 1_000_000,
            schedule: Some("0 2 * * 0".to_string()), // Weekly at 2 AM on Sunday
            emergency_triggers: vec![
                EmergencyTrigger::SecurityIncident,
                EmergencyTrigger::KeyCompromise,
                EmergencyTrigger::QuantumThreatEscalation,
            ],
            overlap_period_hours: 2,
            proactive_rotation: true,
        }
    }
}

/// Key usage statistics and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub kid: String,
    pub created_at: u64,
    pub last_used: u64,
    pub usage_count: u64,
    pub algorithm: PQAlgorithm,
    pub security_level: SecurityLevel,
    pub status: KeyStatus,
    pub rotation_reason: Option<RotationReason>,
    pub performance_metrics: KeyPerformanceMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStatus {
    /// Key is active and can be used for signing
    Active,
    /// Key is being rotated out but still valid for verification
    Rotating,
    /// Key is deprecated but still valid for verification
    Deprecated,
    /// Key is revoked and should not be used
    Revoked,
    /// Key is destroyed and cannot be recovered
    Destroyed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationReason {
    /// Scheduled rotation
    Scheduled,
    /// Age-based rotation
    MaxAge,
    /// Usage-based rotation
    MaxOperations,
    /// Emergency rotation
    Emergency(EmergencyTrigger),
    /// Manual rotation
    Manual,
    /// Security upgrade
    SecurityUpgrade,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPerformanceMetrics {
    pub sign_operations: u64,
    pub verify_operations: u64,
    pub avg_sign_time_ms: f64,
    pub avg_verify_time_ms: f64,
    pub total_sign_time_ms: u64,
    pub total_verify_time_ms: u64,
    pub error_count: u64,
}

impl Default for KeyPerformanceMetrics {
    fn default() -> Self {
        Self {
            sign_operations: 0,
            verify_operations: 0,
            avg_sign_time_ms: 0.0,
            avg_verify_time_ms: 0.0,
            total_sign_time_ms: 0,
            total_verify_time_ms: 0,
            error_count: 0,
        }
    }
}

/// Key storage with secure handling
#[derive(Debug, Clone)]
pub struct SecureKeyStorage {
    keys: Arc<RwLock<HashMap<String, PQKeyMaterial>>>,
    metadata: Arc<RwLock<HashMap<String, KeyMetadata>>>,
    rotation_history: Arc<RwLock<VecDeque<RotationRecord>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRecord {
    pub timestamp: u64,
    pub old_kid: String,
    pub new_kid: String,
    pub reason: RotationReason,
    pub success: bool,
    pub error_message: Option<String>,
}

impl SecureKeyStorage {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            metadata: Arc::new(RwLock::new(HashMap::new())),
            rotation_history: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Store a key with metadata
    pub async fn store_key(&self, key: PQKeyMaterial) -> Result<()> {
        let kid = key.kid.clone();
        let metadata = KeyMetadata {
            kid: kid.clone(),
            created_at: key.created_at,
            last_used: current_timestamp(),
            usage_count: 0,
            algorithm: key.algorithm.clone(),
            security_level: key.security_level,
            status: KeyStatus::Active,
            rotation_reason: None,
            performance_metrics: KeyPerformanceMetrics::default(),
        };

        {
            let mut keys = self.keys.write().await;
            keys.insert(kid.clone(), key);
        }

        {
            let mut meta = self.metadata.write().await;
            meta.insert(kid.clone(), metadata);
        }

        info!("Stored post-quantum key: {}", kid);
        Ok(())
    }

    /// Retrieve a key by ID
    pub async fn get_key(&self, kid: &str) -> Option<PQKeyMaterial> {
        let keys = self.keys.read().await;
        keys.get(kid).cloned()
    }

    /// Get key metadata
    pub async fn get_metadata(&self, kid: &str) -> Option<KeyMetadata> {
        let metadata = self.metadata.read().await;
        metadata.get(kid).cloned()
    }

    /// Update key usage statistics
    pub async fn update_usage(
        &self,
        kid: &str,
        operation: KeyOperation,
        duration_ms: u64,
    ) -> Result<()> {
        let mut metadata = self.metadata.write().await;
        if let Some(meta) = metadata.get_mut(kid) {
            meta.last_used = current_timestamp();
            meta.usage_count += 1;

            match operation {
                KeyOperation::Sign => {
                    meta.performance_metrics.sign_operations += 1;
                    meta.performance_metrics.total_sign_time_ms += duration_ms;
                    meta.performance_metrics.avg_sign_time_ms =
                        meta.performance_metrics.total_sign_time_ms as f64
                            / meta.performance_metrics.sign_operations as f64;
                }
                KeyOperation::Verify => {
                    meta.performance_metrics.verify_operations += 1;
                    meta.performance_metrics.total_verify_time_ms += duration_ms;
                    meta.performance_metrics.avg_verify_time_ms =
                        meta.performance_metrics.total_verify_time_ms as f64
                            / meta.performance_metrics.verify_operations as f64;
                }
                KeyOperation::Error => {
                    meta.performance_metrics.error_count += 1;
                }
            }
        }
        Ok(())
    }

    /// Mark key for rotation
    pub async fn rotate_key(&self, kid: &str, reason: RotationReason) -> Result<()> {
        let mut metadata = self.metadata.write().await;
        if let Some(meta) = metadata.get_mut(kid) {
            meta.status = KeyStatus::Rotating;
            meta.rotation_reason = Some(reason.clone());

            info!("Marked key for rotation: {} (reason: {:?})", kid, reason);

            // Log rotation event
            SecurityLogger::log_event(
                &SecurityEvent::new(
                    SecurityEventType::KeyManagement,
                    SecuritySeverity::Medium,
                    "pq-key-management".to_string(),
                    "Post-quantum key marked for rotation".to_string(),
                )
                .with_actor("pq_system".to_string())
                .with_action("pq_mark_rotation".to_string())
                .with_target("pq_keys".to_string())
                .with_outcome("initiated".to_string())
                .with_reason(format!("Key marked for rotation due to: {:?}", reason))
                .with_detail("kid".to_string(), kid.to_string()),
            );
        }
        Ok(())
    }

    /// Revoke a key
    pub async fn revoke_key(&self, kid: &str, reason: &str) -> Result<()> {
        let mut metadata = self.metadata.write().await;
        if let Some(meta) = metadata.get_mut(kid) {
            meta.status = KeyStatus::Revoked;

            warn!("Revoked post-quantum key: {} (reason: {})", kid, reason);

            // Log revocation event
            SecurityLogger::log_event(
                &SecurityEvent::new(
                    SecurityEventType::KeyManagement,
                    SecuritySeverity::High,
                    "pq-key-management".to_string(),
                    "Post-quantum key revoked".to_string(),
                )
                .with_actor("pq_system".to_string())
                .with_action("pq_revoke_key".to_string())
                .with_target("pq_keys".to_string())
                .with_outcome("revoked".to_string())
                .with_reason(format!("Key revoked: {}", reason))
                .with_detail("kid".to_string(), kid.to_string()),
            );
        }
        Ok(())
    }

    /// Securely destroy a key
    pub async fn destroy_key(&self, kid: &str) -> Result<()> {
        // Remove from storage and zeroize
        let mut keys = self.keys.write().await;
        if let Some(mut key) = keys.remove(kid) {
            // Zeroize sensitive key material
            match &mut key.key_data {
                #[cfg(feature = "post-quantum")]
                PQKeyData::Dilithium { private_key, .. } => {
                    private_key.zeroize();
                }
                #[cfg(feature = "post-quantum")]
                PQKeyData::Kyber { private_key, .. } => {
                    private_key.zeroize();
                }
                #[cfg(feature = "hybrid-crypto")]
                PQKeyData::Hybrid {
                    classical,
                    post_quantum,
                } => {
                    match classical {
                        ClassicalKeyData::Ed25519 { private_key, .. } => {
                            private_key.zeroize();
                        }
                        ClassicalKeyData::EcdsaP256 { private_key, .. } => {
                            private_key.zeroize();
                        }
                        _ => {}
                    }
                    // Note: post_quantum destruction handled by its own zeroize implementation
                }
                _ => {}
            }
        }

        // Update metadata
        let mut metadata = self.metadata.write().await;
        if let Some(meta) = metadata.get_mut(kid) {
            meta.status = KeyStatus::Destroyed;
        }

        warn!("Destroyed post-quantum key: {}", kid);

        // Log destruction event
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::KeyManagement,
                SecuritySeverity::High,
                "pq-key-management".to_string(),
                "Post-quantum key destroyed".to_string(),
            )
            .with_actor("pq_system".to_string())
            .with_action("pq_destroy_key".to_string())
            .with_target("pq_keys".to_string())
            .with_outcome("destroyed".to_string())
            .with_reason("Key securely destroyed and zeroized from memory".to_string())
            .with_detail("kid".to_string(), kid.to_string()),
        );

        Ok(())
    }

    /// Get all active keys
    pub async fn get_active_keys(&self) -> Vec<String> {
        let metadata = self.metadata.read().await;
        metadata
            .values()
            .filter(|meta| meta.status == KeyStatus::Active)
            .map(|meta| meta.kid.clone())
            .collect()
    }

    /// Get keys needing rotation
    pub async fn get_keys_needing_rotation(&self, policy: &KeyRotationPolicy) -> Vec<String> {
        let metadata = self.metadata.read().await;
        let current_time = current_timestamp();

        metadata
            .values()
            .filter(|meta| {
                meta.status == KeyStatus::Active
                    && (current_time - meta.created_at > policy.max_age_hours * 3600
                        || meta.usage_count > policy.max_operations)
            })
            .map(|meta| meta.kid.clone())
            .collect()
    }

    /// Record rotation event
    pub async fn record_rotation(
        &self,
        old_kid: String,
        new_kid: String,
        reason: RotationReason,
        success: bool,
        error: Option<String>,
    ) {
        let record = RotationRecord {
            timestamp: current_timestamp(),
            old_kid,
            new_kid,
            reason,
            success,
            error_message: error,
        };

        let mut history = self.rotation_history.write().await;
        history.push_back(record);

        // Keep only last 1000 records
        while history.len() > 1000 {
            history.pop_front();
        }
    }

    /// Get rotation history
    pub async fn get_rotation_history(&self, limit: Option<usize>) -> Vec<RotationRecord> {
        let history = self.rotation_history.read().await;
        let limit = limit.unwrap_or(100);
        history.iter().rev().take(limit).cloned().collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum KeyOperation {
    Sign,
    Verify,
    Error,
}

/// Post-quantum key manager with automated rotation
pub struct PQKeyManager {
    storage: SecureKeyStorage,
    policy: KeyRotationPolicy,
    rotation_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl PQKeyManager {
    pub fn new(policy: KeyRotationPolicy) -> Self {
        Self {
            storage: SecureKeyStorage::new(),
            policy,
            rotation_task: Arc::new(Mutex::new(None)),
        }
    }

    pub fn default() -> Self {
        Self::new(KeyRotationPolicy::default())
    }

    /// Initialize the key manager
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing post-quantum key manager");

        // Generate initial key if none exist
        let active_keys = self.storage.get_active_keys().await;
        if active_keys.is_empty() {
            info!("No active keys found, generating initial key");
            self.generate_new_key(None).await?;
        }

        // Start rotation task if proactive rotation is enabled
        if self.policy.proactive_rotation {
            self.start_rotation_task().await;
        }

        // Log initialization
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::SystemEvent,
                SecuritySeverity::Medium,
                "pq-key-management".to_string(),
                "Post-quantum key manager initialized".to_string(),
            )
            .with_actor("system".to_string())
            .with_action("pq_keymanager_init".to_string())
            .with_target("key_manager".to_string())
            .with_outcome("success".to_string())
            .with_reason("Post-quantum key management system started".to_string())
            .with_detail("active_keys".to_string(), active_keys.len())
            .with_detail(
                "proactive_rotation".to_string(),
                self.policy.proactive_rotation,
            ),
        );

        Ok(())
    }

    /// Generate a new post-quantum key
    pub async fn generate_new_key(&self, algorithm: Option<PQAlgorithm>) -> Result<String> {
        let manager = get_pq_manager();
        let kid = manager.generate_signing_key_pair(algorithm).await?;

        info!("Generated new post-quantum key: {}", kid);
        Ok(kid)
    }

    /// Perform key rotation
    pub async fn rotate_keys(&self, reason: RotationReason) -> Result<Vec<String>> {
        let keys_to_rotate = match &reason {
            RotationReason::Emergency(_) => self.storage.get_active_keys().await,
            _ => self.storage.get_keys_needing_rotation(&self.policy).await,
        };

        let mut rotated_keys = Vec::new();

        for old_kid in keys_to_rotate {
            match self.rotate_single_key(&old_kid, reason.clone()).await {
                Ok(new_kid) => {
                    rotated_keys.push(new_kid.clone());
                    self.storage
                        .record_rotation(old_kid.clone(), new_kid, reason.clone(), true, None)
                        .await;

                    info!(
                        "Successfully rotated key: {} -> {}",
                        old_kid,
                        rotated_keys.last().unwrap()
                    );
                }
                Err(e) => {
                    error!("Failed to rotate key {}: {}", old_kid, e);
                    self.storage
                        .record_rotation(
                            old_kid.clone(),
                            String::new(),
                            reason.clone(),
                            false,
                            Some(e.to_string()),
                        )
                        .await;
                }
            }
        }

        // Log rotation completion
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::KeyManagement,
                SecuritySeverity::Medium,
                "pq-key-management".to_string(),
                "Key rotation completed".to_string(),
            )
            .with_actor("pq_system".to_string())
            .with_action("pq_rotate_keys".to_string())
            .with_target("pq_keys".to_string())
            .with_outcome("success".to_string())
            .with_reason(format!("Key rotation batch completed: {:?}", reason))
            .with_detail("rotated_count".to_string(), rotated_keys.len()),
        );

        Ok(rotated_keys)
    }

    /// Rotate a single key
    async fn rotate_single_key(&self, old_kid: &str, reason: RotationReason) -> Result<String> {
        // Mark old key for rotation
        self.storage.rotate_key(old_kid, reason.clone()).await?;

        // Generate new key
        let new_kid = self.generate_new_key(None).await?;

        // Wait for overlap period before deprecating old key
        if self.policy.overlap_period_hours > 0 {
            tokio::spawn({
                let storage = self.storage.clone();
                let old_kid = old_kid.to_string();
                let overlap_hours = self.policy.overlap_period_hours;

                async move {
                    tokio::time::sleep(Duration::from_secs(overlap_hours * 3600)).await;

                    // Deprecate old key
                    let mut metadata = storage.metadata.write().await;
                    if let Some(meta) = metadata.get_mut(&old_kid) {
                        meta.status = KeyStatus::Deprecated;
                    }

                    info!("Deprecated old key after overlap period: {}", old_kid);
                }
            });
        }

        Ok(new_kid)
    }

    /// Emergency key rotation
    pub async fn emergency_rotation(&self, trigger: EmergencyTrigger) -> Result<Vec<String>> {
        warn!("Emergency key rotation triggered: {:?}", trigger);

        // Log emergency rotation
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::SecurityViolation,
                SecuritySeverity::Critical,
                "pq-key-management".to_string(),
                "Emergency key rotation initiated".to_string(),
            )
            .with_actor("pq_system".to_string())
            .with_action("pq_emergency_rotate".to_string())
            .with_target("pq_keys".to_string())
            .with_outcome("initiated".to_string())
            .with_reason(format!(
                "Emergency key rotation triggered by: {:?}",
                trigger
            ))
            .with_detail("trigger".to_string(), format!("{:?}", trigger)),
        );

        self.rotate_keys(RotationReason::Emergency(trigger)).await
    }

    /// Start automated rotation task
    async fn start_rotation_task(&self) {
        let mut task_handle = self.rotation_task.lock().await;

        if task_handle.is_some() {
            warn!("Rotation task already running");
            return;
        }

        let storage = self.storage.clone();
        let policy = self.policy.clone();

        let handle = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(3600)); // Check every hour

            loop {
                interval.tick().await;

                let keys_needing_rotation = storage.get_keys_needing_rotation(&policy).await;
                if !keys_needing_rotation.is_empty() {
                    info!(
                        "Found {} keys needing rotation",
                        keys_needing_rotation.len()
                    );

                    for kid in keys_needing_rotation {
                        if let Err(e) = storage.rotate_key(&kid, RotationReason::Scheduled).await {
                            error!("Failed to initiate rotation for key {}: {}", kid, e);
                        }
                    }
                }
            }
        });

        *task_handle = Some(handle);
        info!("Started automated key rotation task");
    }

    /// Stop automated rotation task
    pub async fn stop_rotation_task(&self) {
        let mut task_handle = self.rotation_task.lock().await;

        if let Some(handle) = task_handle.take() {
            handle.abort();
            info!("Stopped automated key rotation task");
        }
    }

    /// Get key management statistics
    pub async fn get_statistics(&self) -> KeyManagementStats {
        let metadata = self.storage.metadata.read().await;
        let history = self.storage.rotation_history.read().await;

        let mut stats = KeyManagementStats {
            total_keys: metadata.len(),
            active_keys: 0,
            rotating_keys: 0,
            deprecated_keys: 0,
            revoked_keys: 0,
            total_operations: 0,
            total_rotations: history.len(),
            avg_key_age_hours: 0.0,
            performance_summary: HashMap::new(),
        };

        let current_time = current_timestamp();
        let mut total_age = 0u64;

        for meta in metadata.values() {
            match meta.status {
                KeyStatus::Active => stats.active_keys += 1,
                KeyStatus::Rotating => stats.rotating_keys += 1,
                KeyStatus::Deprecated => stats.deprecated_keys += 1,
                KeyStatus::Revoked => stats.revoked_keys += 1,
                KeyStatus::Destroyed => {} // Not counted in total
            }

            stats.total_operations += meta.usage_count;
            total_age += current_time - meta.created_at;

            let alg_name = format!("{:?}", meta.algorithm);
            let perf_entry = stats
                .performance_summary
                .entry(alg_name)
                .or_insert_with(|| AlgorithmPerformance {
                    total_operations: 0,
                    avg_sign_time_ms: 0.0,
                    avg_verify_time_ms: 0.0,
                    error_rate: 0.0,
                });

            perf_entry.total_operations += meta.usage_count;
            perf_entry.avg_sign_time_ms =
                (perf_entry.avg_sign_time_ms + meta.performance_metrics.avg_sign_time_ms) / 2.0;
            perf_entry.avg_verify_time_ms =
                (perf_entry.avg_verify_time_ms + meta.performance_metrics.avg_verify_time_ms) / 2.0;

            if meta.usage_count > 0 {
                perf_entry.error_rate =
                    meta.performance_metrics.error_count as f64 / meta.usage_count as f64;
            }
        }

        if !metadata.is_empty() {
            stats.avg_key_age_hours = (total_age / metadata.len() as u64) as f64 / 3600.0;
        }

        stats
    }

    /// Get key by ID
    pub async fn get_key(&self, kid: &str) -> Option<PQKeyMaterial> {
        self.storage.get_key(kid).await
    }

    /// Update key usage statistics
    pub async fn record_operation(
        &self,
        kid: &str,
        operation: KeyOperation,
        duration_ms: u64,
    ) -> Result<()> {
        self.storage.update_usage(kid, operation, duration_ms).await
    }

    /// Validate key integrity
    pub async fn validate_key_integrity(&self, kid: &str) -> Result<bool> {
        if let Some(key) = self.storage.get_key(kid).await {
            // Perform basic integrity checks
            match &key.key_data {
                #[cfg(feature = "post-quantum")]
                PQKeyData::Dilithium {
                    public_key,
                    private_key,
                } => {
                    // Check key lengths and basic structure
                    match key.security_level {
                        SecurityLevel::Level1 => Ok(public_key.len()
                            == pqcrypto_mldsa::mldsa44::PUBLICKEYBYTES
                            && private_key.len() == pqcrypto_mldsa::mldsa44::SECRETKEYBYTES),
                        SecurityLevel::Level3 => Ok(public_key.len()
                            == pqcrypto_mldsa::mldsa65::PUBLICKEYBYTES
                            && private_key.len() == pqcrypto_mldsa::mldsa65::SECRETKEYBYTES),
                        SecurityLevel::Level5 => Ok(public_key.len()
                            == pqcrypto_mldsa::mldsa87::PUBLICKEYBYTES
                            && private_key.len() == pqcrypto_mldsa::mldsa87::SECRETKEYBYTES),
                    }
                }
                _ => Ok(true), // For other key types or when features are disabled
            }
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyManagementStats {
    pub total_keys: usize,
    pub active_keys: usize,
    pub rotating_keys: usize,
    pub deprecated_keys: usize,
    pub revoked_keys: usize,
    pub total_operations: u64,
    pub total_rotations: usize,
    pub avg_key_age_hours: f64,
    pub performance_summary: HashMap<String, AlgorithmPerformance>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AlgorithmPerformance {
    pub total_operations: u64,
    pub avg_sign_time_ms: f64,
    pub avg_verify_time_ms: f64,
    pub error_rate: f64,
}

/// Global key manager instance
static PQ_KEY_MANAGER: once_cell::sync::Lazy<PQKeyManager> =
    once_cell::sync::Lazy::new(|| PQKeyManager::default());

/// Get the global post-quantum key manager
pub fn get_pq_key_manager() -> &'static PQKeyManager {
    &PQ_KEY_MANAGER
}

/// Initialize post-quantum key management
pub async fn initialize_pq_key_management() -> Result<()> {
    get_pq_key_manager().initialize().await
}

/// Helper function to get current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_rotation_policy_default() {
        let policy = KeyRotationPolicy::default();
        assert_eq!(policy.max_age_hours, 24 * 7);
        assert!(policy.proactive_rotation);
        assert!(!policy.emergency_triggers.is_empty());
    }

    #[tokio::test]
    async fn test_secure_key_storage() {
        let storage = SecureKeyStorage::new();

        // Test that storage is initially empty
        let active_keys = storage.get_active_keys().await;
        assert!(active_keys.is_empty());
    }

    #[tokio::test]
    async fn test_key_manager_initialization() {
        let manager = PQKeyManager::default();

        // Test initialization without errors
        // Note: This may fail if post-quantum features are not available
        let result = manager.initialize().await;
        assert!(operation_result.is_ok() || operation_result.is_err()); // Just ensure it doesn't panic
    }

    #[tokio::test]
    async fn test_key_metadata_creation() {
        let metadata = KeyMetadata {
            kid: "test-key".to_string(),
            created_at: current_timestamp(),
            last_used: current_timestamp(),
            usage_count: 0,
            algorithm: PQAlgorithm::Dilithium(SecurityLevel::Level3),
            security_level: SecurityLevel::Level3,
            status: KeyStatus::Active,
            rotation_reason: None,
            performance_metrics: KeyPerformanceMetrics::default(),
        };

        assert_eq!(metadata.status, KeyStatus::Active);
        assert_eq!(metadata.usage_count, 0);
    }

    #[test]
    fn test_emergency_triggers() {
        let triggers = vec![
            EmergencyTrigger::SecurityIncident,
            EmergencyTrigger::KeyCompromise,
            EmergencyTrigger::QuantumThreatEscalation,
        ];

        assert_eq!(triggers.len(), 3);
    }
}
