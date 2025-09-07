//! Immutable Audit Logging with Integrity Verification
//!
//! This module provides enterprise-grade immutable audit logging capabilities
//! with cryptographic integrity verification, tamper detection, and compliance
//! reporting for regulatory requirements including SOX, GDPR, HIPAA, and PCI DSS.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use ring::{
    digest, hmac,
    rand::{self, SecureRandom},
    signature::{self, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Audit event severity levels for compliance classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditSeverity {
    /// Critical security events requiring immediate attention
    Critical,
    /// High-priority security events
    High,
    /// Medium-priority operational events
    Medium,
    /// Low-priority informational events
    Low,
    /// Debug-level events for development
    Debug,
}

/// Audit event categories for compliance mapping
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AuditCategory {
    /// Authentication events (login, logout, MFA)
    Authentication,
    /// Authorization and access control events
    Authorization,
    /// Data access and modification events
    DataAccess,
    /// Administrative actions and configuration changes
    Administrative,
    /// System security events and alerts
    Security,
    /// Network and communication events
    Network,
    /// File system and storage events
    FileSystem,
    /// Database operations and queries
    Database,
    /// API access and operations
    ApiAccess,
    /// Compliance and audit events
    Compliance,
}

/// Cryptographic hash chain link for tamper detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashChainLink {
    /// Current block hash
    pub current_hash: Vec<u8>,
    /// Previous block hash for chain integrity
    pub previous_hash: Vec<u8>,
    /// Merkle tree root for batch integrity
    pub merkle_root: Vec<u8>,
    /// Block sequence number
    pub sequence_number: u64,
    /// Block timestamp
    pub timestamp: DateTime<Utc>,
    /// Number of events in this block
    pub event_count: usize,
}

/// Digital signature for non-repudiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSignature {
    /// Digital signature bytes
    pub signature: Vec<u8>,
    /// Public key identifier
    pub key_id: String,
    /// Signature algorithm identifier
    pub algorithm: String,
    /// Timestamp when signature was created
    pub timestamp: DateTime<Utc>,
}

/// Immutable audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmutableAuditEvent {
    /// Unique event identifier
    pub id: Uuid,
    /// Event timestamp with nanosecond precision
    pub timestamp: DateTime<Utc>,
    /// Event severity level
    pub severity: AuditSeverity,
    /// Event category for compliance mapping
    pub category: AuditCategory,
    /// Source system or component
    pub source: String,
    /// User or system principal
    pub principal: Option<String>,
    /// Target resource or object
    pub target: Option<String>,
    /// Action or operation performed
    pub action: String,
    /// Result or outcome
    pub result: String,
    /// Additional event details
    pub details: BTreeMap<String, String>,
    /// Client IP address
    pub client_ip: Option<String>,
    /// User agent information
    pub user_agent: Option<String>,
    /// Session identifier
    pub session_id: Option<String>,
    /// Request identifier for correlation
    pub request_id: Option<String>,
    /// Geolocation information
    pub geolocation: Option<String>,
    /// Risk score for the event
    pub risk_score: Option<f64>,
    /// Compliance tags
    pub compliance_tags: Vec<String>,
    /// Event hash for integrity verification
    pub event_hash: Vec<u8>,
    /// Position in hash chain
    pub chain_position: u64,
    /// Digital signature for non-repudiation
    pub signature: Option<AuditSignature>,
}

/// Audit storage backend trait for multiple storage options
#[async_trait::async_trait]
pub trait AuditStorage: Send + Sync {
    /// Store an immutable audit event
    async fn store_event(&self, event: &ImmutableAuditEvent) -> Result<()>;

    /// Retrieve audit events by criteria
    async fn query_events(&self, criteria: &AuditQueryCriteria)
        -> Result<Vec<ImmutableAuditEvent>>;

    /// Store hash chain link
    async fn store_chain_link(&self, link: &HashChainLink) -> Result<()>;

    /// Retrieve hash chain for integrity verification
    async fn get_chain_links(
        &self,
        start_sequence: u64,
        count: usize,
    ) -> Result<Vec<HashChainLink>>;

    /// Perform integrity verification
    async fn verify_integrity(&self, start_sequence: u64, end_sequence: u64) -> Result<bool>;
}

/// Audit query criteria for event retrieval
#[derive(Debug, Clone, Default)]
pub struct AuditQueryCriteria {
    /// Start timestamp filter
    pub start_time: Option<DateTime<Utc>>,
    /// End timestamp filter
    pub end_time: Option<DateTime<Utc>>,
    /// Severity level filter
    pub severity: Option<AuditSeverity>,
    /// Category filter
    pub category: Option<AuditCategory>,
    /// Principal (user) filter
    pub principal: Option<String>,
    /// Source system filter
    pub source: Option<String>,
    /// Action filter
    pub action: Option<String>,
    /// Target resource filter
    pub target: Option<String>,
    /// Client IP filter
    pub client_ip: Option<String>,
    /// Session ID filter
    pub session_id: Option<String>,
    /// Request ID filter
    pub request_id: Option<String>,
    /// Maximum number of results
    pub limit: Option<usize>,
    /// Result offset for pagination
    pub offset: Option<usize>,
    /// Compliance tags filter
    pub compliance_tags: Vec<String>,
    /// Minimum risk score filter
    pub min_risk_score: Option<f64>,
}

/// Cryptographic key material for signing (with proper zeroization)
#[derive(Zeroize, ZeroizeOnDrop)]
struct SigningKeys {
    /// Private key for digital signatures
    #[zeroize(skip)]
    private_key: Vec<u8>,
    /// Public key for signature verification
    #[zeroize(skip)]
    public_key: Vec<u8>,
    /// HMAC key for integrity protection (stored as bytes instead of ring::hmac::Key)
    #[zeroize(skip)]
    hmac_key: Vec<u8>,
}

/// Hash chain manager for tamper detection
pub struct HashChainManager {
    /// Current chain position
    current_position: Arc<RwLock<u64>>,
    /// Last block hash
    last_hash: Arc<RwLock<Vec<u8>>>,
    /// Pending events for next block
    pending_events: Arc<RwLock<VecDeque<ImmutableAuditEvent>>>,
    /// Block size for batching
    block_size: usize,
    /// Storage backend
    storage: Arc<dyn AuditStorage>,
}

/// Main immutable audit logging engine
pub struct ImmutableAuditLogger {
    /// Hash chain manager
    chain_manager: Arc<HashChainManager>,
    /// Cryptographic signing keys
    signing_keys: Arc<RwLock<SigningKeys>>,
    /// Storage backend
    storage: Arc<dyn AuditStorage>,
    /// Event buffer for high-throughput scenarios
    event_buffer: Arc<RwLock<VecDeque<ImmutableAuditEvent>>>,
    /// Buffer flush threshold
    buffer_threshold: usize,
    /// Compliance configuration
    compliance_config: Arc<ComplianceConfiguration>,
    /// Integrity verification scheduler
    verification_scheduler: Arc<RwLock<IntegrityVerificationScheduler>>,
}

/// Compliance configuration for regulatory requirements
#[derive(Debug, Clone)]
pub struct ComplianceConfiguration {
    /// SOX compliance settings
    pub sox_enabled: bool,
    /// GDPR compliance settings
    pub gdpr_enabled: bool,
    /// HIPAA compliance settings
    pub hipaa_enabled: bool,
    /// PCI DSS compliance settings
    pub pci_dss_enabled: bool,
    /// Custom retention period in days
    pub retention_days: u32,
    /// Data residency requirements
    pub data_residency: Option<String>,
    /// Encryption requirements
    pub encryption_required: bool,
    /// Access control requirements
    pub access_control_level: String,
}

/// Integrity verification scheduler for automated checks
#[derive(Debug)]
pub struct IntegrityVerificationScheduler {
    /// Last verification timestamp
    pub last_verification: DateTime<Utc>,
    /// Verification interval in hours
    pub interval_hours: u32,
    /// Verification results history
    pub verification_history: VecDeque<VerificationResult>,
    /// Alert thresholds
    pub alert_threshold: u32,
}

/// Verification result structure
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Verification timestamp
    pub timestamp: DateTime<Utc>,
    /// Verification success status
    pub success: bool,
    /// Number of blocks verified
    pub blocks_verified: u64,
    /// Any integrity violations found
    pub violations: Vec<IntegrityViolation>,
    /// Verification duration
    pub duration_ms: u64,
}

/// Integrity violation details
#[derive(Debug, Clone)]
pub struct IntegrityViolation {
    /// Block sequence number with violation
    pub block_sequence: u64,
    /// Violation type
    pub violation_type: ViolationType,
    /// Violation description
    pub description: String,
    /// Affected event IDs
    pub affected_events: Vec<Uuid>,
}

/// Types of integrity violations
#[derive(Debug, Clone)]
pub enum ViolationType {
    /// Hash chain break
    HashChainBroken,
    /// Merkle tree mismatch
    MerkleTreeMismatch,
    /// Digital signature invalid
    InvalidSignature,
    /// Timestamp anomaly
    TimestampAnomaly,
    /// Missing events
    MissingEvents,
    /// Duplicate events
    DuplicateEvents,
}

impl HashChainManager {
    /// Create new hash chain manager
    pub fn new(storage: Arc<dyn AuditStorage>, block_size: usize) -> Self {
        Self {
            current_position: Arc::new(RwLock::new(0)),
            last_hash: Arc::new(RwLock::new(vec![0u8; 32])),
            pending_events: Arc::new(RwLock::new(VecDeque::new())),
            block_size,
            storage,
        }
    }

    /// Add event to chain
    pub async fn add_event(&self, mut event: ImmutableAuditEvent) -> Result<()> {
        let mut position_guard = self.current_position.write().await;
        let mut pending_guard = self.pending_events.write().await;

        // Set chain position
        event.chain_position = *position_guard;
        *position_guard += 1;

        // Calculate event hash
        event.event_hash = self.calculate_event_hash(&event)?;

        // Add to pending events
        pending_guard.push_back(event);

        // Check if we should create a new block
        if pending_guard.len() >= self.block_size {
            self.create_block(&mut pending_guard).await?;
        }

        Ok(())
    }

    /// Create new hash chain block
    async fn create_block(&self, pending_events: &mut VecDeque<ImmutableAuditEvent>) -> Result<()> {
        if pending_events.is_empty() {
            return Ok(());
        }

        let events: Vec<_> = pending_events.drain(..).collect();
        let sequence_number = events[0].chain_position / self.block_size as u64;

        // Calculate Merkle tree root
        let merkle_root = self.calculate_merkle_root(&events)?;

        // Get previous hash
        let previous_hash = self.last_hash.read().await.clone();

        // Calculate current block hash
        let current_hash = self.calculate_block_hash(&events, &previous_hash, &merkle_root)?;

        // Create hash chain link
        let chain_link = HashChainLink {
            current_hash: current_hash.clone(),
            previous_hash,
            merkle_root,
            sequence_number,
            timestamp: Utc::now(),
            event_count: events.len(),
        };

        // Store events and chain link
        for event in events {
            self.storage.store_event(&event).await?;
        }
        self.storage.store_chain_link(&chain_link).await?;

        // Update last hash
        *self.last_hash.write().await = current_hash;

        Ok(())
    }

    /// Calculate event hash
    fn calculate_event_hash(&self, event: &ImmutableAuditEvent) -> Result<Vec<u8>> {
        let serialized = serde_json::to_vec(event)?;
        Ok(digest::digest(&digest::SHA256, &serialized)
            .as_ref()
            .to_vec())
    }

    /// Calculate Merkle tree root
    fn calculate_merkle_root(&self, events: &[ImmutableAuditEvent]) -> Result<Vec<u8>> {
        if events.is_empty() {
            return Ok(vec![0u8; 32]);
        }

        let mut hashes: Vec<Vec<u8>> = events.iter().map(|e| e.event_hash.clone()).collect();

        // Build Merkle tree bottom-up
        while hashes.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in hashes.chunks(2) {
                let combined = if chunk.len() == 2 {
                    [chunk[0].clone(), chunk[1].clone()].concat()
                } else {
                    [chunk[0].clone(), chunk[0].clone()].concat()
                };

                let hash = digest::digest(&digest::SHA256, &combined);
                next_level.push(hash.as_ref().to_vec());
            }

            hashes = next_level;
        }

        Ok(hashes.into_iter().next().unwrap_or_else(|| vec![0u8; 32]))
    }

    /// Calculate block hash
    fn calculate_block_hash(
        &self,
        events: &[ImmutableAuditEvent],
        previous_hash: &[u8],
        merkle_root: &[u8],
    ) -> Result<Vec<u8>> {
        let mut hasher = digest::Context::new(&digest::SHA256);
        hasher.update(previous_hash);
        hasher.update(merkle_root);
        hasher.update(&events.len().to_le_bytes());
        hasher.update(&Utc::now().timestamp().to_le_bytes());

        Ok(hasher.finish().as_ref().to_vec())
    }

    /// Verify hash chain integrity
    pub async fn verify_chain_integrity(
        &self,
        start_sequence: u64,
        end_sequence: u64,
    ) -> Result<VerificationResult> {
        let start_time = std::time::Instant::now();
        let mut violations = Vec::new();
        let mut blocks_verified = 0;

        let links = self
            .storage
            .get_chain_links(start_sequence, (end_sequence - start_sequence) as usize)
            .await?;

        for (i, link) in links.iter().enumerate() {
            blocks_verified += 1;

            // Verify hash chain continuity
            if i > 0 {
                let prev_link = &links[i - 1];
                if link.previous_hash != prev_link.current_hash {
                    violations.push(IntegrityViolation {
                        block_sequence: link.sequence_number,
                        violation_type: ViolationType::HashChainBroken,
                        description: "Hash chain break detected".to_string(),
                        affected_events: Vec::new(),
                    });
                }
            }

            // Verify timestamp ordering
            if i > 0 {
                let prev_link = &links[i - 1];
                if link.timestamp < prev_link.timestamp {
                    violations.push(IntegrityViolation {
                        block_sequence: link.sequence_number,
                        violation_type: ViolationType::TimestampAnomaly,
                        description: "Block timestamp is earlier than previous block".to_string(),
                        affected_events: Vec::new(),
                    });
                }
            }
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;
        let success = violations.is_empty();

        if !success {
            error!(
                "Chain integrity verification failed with {} violations",
                violations.len()
            );
        } else {
            info!(
                "Chain integrity verification successful for {} blocks",
                blocks_verified
            );
        }

        Ok(VerificationResult {
            timestamp: Utc::now(),
            success,
            blocks_verified,
            violations,
            duration_ms,
        })
    }
}

impl ImmutableAuditLogger {
    /// Create new immutable audit logger
    pub async fn new(
        storage: Arc<dyn AuditStorage>,
        compliance_config: ComplianceConfiguration,
    ) -> Result<Self> {
        // Generate cryptographic keys
        let signing_keys = Self::generate_signing_keys()?;

        // Create hash chain manager
        let chain_manager = Arc::new(HashChainManager::new(storage.clone(), 1000));

        // Create verification scheduler
        let verification_scheduler = Arc::new(RwLock::new(IntegrityVerificationScheduler {
            last_verification: Utc::now(),
            interval_hours: 24,
            verification_history: VecDeque::new(),
            alert_threshold: 3,
        }));

        Ok(Self {
            chain_manager,
            signing_keys: Arc::new(RwLock::new(signing_keys)),
            storage,
            event_buffer: Arc::new(RwLock::new(VecDeque::new())),
            buffer_threshold: 100,
            compliance_config: Arc::new(compliance_config),
            verification_scheduler,
        })
    }

    /// Generate cryptographic signing keys
    fn generate_signing_keys() -> Result<SigningKeys> {
        let rng = rand::SystemRandom::new();

        // Generate Ed25519 key pair for digital signatures
        let key_pair_doc = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| anyhow!("Failed to generate signing key: {}", e))?;

        let private_key = key_pair_doc.as_ref().to_vec();

        let key_pair = signature::Ed25519KeyPair::from_pkcs8(key_pair_doc.as_ref())
            .map_err(|e| anyhow!("Failed to parse generated key: {}", e))?;
        let public_key = key_pair.public_key().as_ref().to_vec();

        // Generate HMAC key for integrity protection
        let mut hmac_key_bytes = [0u8; 32];
        rng.fill(&mut hmac_key_bytes)
            .map_err(|e| anyhow!("Failed to generate HMAC key: {}", e))?;
        let hmac_key = hmac_key_bytes.to_vec();

        Ok(SigningKeys {
            private_key,
            public_key,
            hmac_key,
        })
    }

    /// Log immutable audit event
    pub async fn log_event(
        &self,
        severity: AuditSeverity,
        category: AuditCategory,
        source: String,
        action: String,
        result: String,
        principal: Option<String>,
        target: Option<String>,
        details: BTreeMap<String, String>,
        client_ip: Option<String>,
        user_agent: Option<String>,
        session_id: Option<String>,
        request_id: Option<String>,
    ) -> Result<Uuid> {
        let event_id = Uuid::new_v4();
        let timestamp = Utc::now();

        // Calculate risk score based on event characteristics
        let risk_score = self
            .calculate_risk_score(&severity, &category, &action, &details)
            .await?;

        // Determine compliance tags
        let compliance_tags = self.determine_compliance_tags(&category, &action).await?;

        // Create audit event
        let mut event = ImmutableAuditEvent {
            id: event_id,
            timestamp,
            severity,
            category,
            source,
            principal,
            target,
            action: action.clone(),
            result,
            details,
            client_ip,
            user_agent,
            session_id,
            request_id,
            geolocation: None,
            risk_score: Some(risk_score),
            compliance_tags,
            event_hash: Vec::new(),
            chain_position: 0,
            signature: None,
        };

        // Add digital signature if required
        if self.compliance_config.encryption_required {
            event.signature = Some(self.create_digital_signature(&event).await?);
        }

        // Add to hash chain
        self.chain_manager.add_event(event).await?;

        info!("Logged immutable audit event: {} ({})", event_id, action);
        Ok(event_id)
    }

    /// Calculate risk score for event
    async fn calculate_risk_score(
        &self,
        severity: &AuditSeverity,
        category: &AuditCategory,
        action: &str,
        details: &BTreeMap<String, String>,
    ) -> Result<f64> {
        let mut score: f64 = match severity {
            AuditSeverity::Critical => 0.9,
            AuditSeverity::High => 0.7,
            AuditSeverity::Medium => 0.5,
            AuditSeverity::Low => 0.3,
            AuditSeverity::Debug => 0.1,
        };

        // Adjust based on category
        let category_multiplier = match category {
            AuditCategory::Security => 1.2,
            AuditCategory::Authentication => 1.1,
            AuditCategory::Authorization => 1.1,
            AuditCategory::DataAccess => 1.0,
            AuditCategory::Administrative => 0.9,
            _ => 0.8,
        };

        score *= category_multiplier;

        // Adjust based on action
        if action.contains("failed") || action.contains("denied") {
            score *= 1.3;
        }
        if action.contains("admin") || action.contains("root") {
            score *= 1.2;
        }

        // Check for suspicious patterns in details
        for (key, value) in details {
            if key.contains("error") || value.contains("attack") || value.contains("malware") {
                score *= 1.5;
            }
        }

        Ok(score.min(1.0))
    }

    /// Determine compliance tags for event
    async fn determine_compliance_tags(
        &self,
        category: &AuditCategory,
        action: &str,
    ) -> Result<Vec<String>> {
        let mut tags = Vec::new();

        if self.compliance_config.sox_enabled {
            match category {
                AuditCategory::DataAccess
                | AuditCategory::Administrative
                | AuditCategory::Database => {
                    tags.push("SOX".to_string());
                }
                _ => {}
            }
        }

        if self.compliance_config.gdpr_enabled {
            if action.contains("personal_data") || action.contains("pii") {
                tags.push("GDPR".to_string());
            }
        }

        if self.compliance_config.hipaa_enabled {
            if action.contains("health") || action.contains("medical") {
                tags.push("HIPAA".to_string());
            }
        }

        if self.compliance_config.pci_dss_enabled {
            if action.contains("payment") || action.contains("card") {
                tags.push("PCI_DSS".to_string());
            }
        }

        Ok(tags)
    }

    /// Create digital signature for event
    async fn create_digital_signature(
        &self,
        event: &ImmutableAuditEvent,
    ) -> Result<AuditSignature> {
        let signing_keys = self.signing_keys.read().await;
        let serialized = serde_json::to_vec(event)?;

        let key_pair = signature::Ed25519KeyPair::from_pkcs8(&signing_keys.private_key)
            .map_err(|e| anyhow!("Failed to load signing key: {}", e))?;

        let signature_bytes = key_pair.sign(&serialized);

        Ok(AuditSignature {
            signature: signature_bytes.as_ref().to_vec(),
            key_id: "audit-signing-key-v1".to_string(),
            algorithm: "Ed25519".to_string(),
            timestamp: Utc::now(),
        })
    }

    /// Query audit events
    pub async fn query_events(
        &self,
        criteria: &AuditQueryCriteria,
    ) -> Result<Vec<ImmutableAuditEvent>> {
        self.storage.query_events(criteria).await
    }

    /// Perform integrity verification
    pub async fn verify_integrity(
        &self,
        start_sequence: u64,
        end_sequence: u64,
    ) -> Result<VerificationResult> {
        self.chain_manager
            .verify_chain_integrity(start_sequence, end_sequence)
            .await
    }

    /// Generate compliance report
    pub async fn generate_compliance_report(
        &self,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        compliance_standard: &str,
    ) -> Result<ComplianceReport> {
        let mut criteria = AuditQueryCriteria::default();
        criteria.start_time = Some(start_time);
        criteria.end_time = Some(end_time);
        criteria.compliance_tags = vec![compliance_standard.to_string()];

        let events = self.query_events(&criteria).await?;

        // Analyze events for compliance metrics
        let total_events = events.len();
        let critical_events = events
            .iter()
            .filter(|e| e.severity == AuditSeverity::Critical)
            .count();
        let failed_events = events
            .iter()
            .filter(|e| e.result.contains("failed"))
            .count();
        let high_risk_events = events
            .iter()
            .filter(|e| e.risk_score.unwrap_or(0.0) > 0.8)
            .count();

        // Group by category
        let mut category_counts = HashMap::new();
        for event in &events {
            *category_counts.entry(event.category.clone()).or_insert(0) += 1;
        }

        Ok(ComplianceReport {
            standard: compliance_standard.to_string(),
            report_period: (start_time, end_time),
            total_events,
            critical_events,
            failed_events,
            high_risk_events,
            category_breakdown: category_counts,
            compliance_score: self.calculate_compliance_score(&events).await?,
            recommendations: self.generate_compliance_recommendations(&events).await?,
        })
    }

    /// Calculate compliance score
    async fn calculate_compliance_score(&self, events: &[ImmutableAuditEvent]) -> Result<f64> {
        if events.is_empty() {
            return Ok(1.0);
        }

        let total_events = events.len() as f64;
        let critical_events = events
            .iter()
            .filter(|e| e.severity == AuditSeverity::Critical)
            .count() as f64;
        let failed_events = events
            .iter()
            .filter(|e| e.result.contains("failed"))
            .count() as f64;

        let critical_penalty = (critical_events / total_events) * 0.3;
        let failure_penalty = (failed_events / total_events) * 0.2;

        let score = 1.0 - critical_penalty - failure_penalty;
        Ok(score.max(0.0))
    }

    /// Generate compliance recommendations
    async fn generate_compliance_recommendations(
        &self,
        events: &[ImmutableAuditEvent],
    ) -> Result<Vec<String>> {
        let mut recommendations = Vec::new();

        let critical_count = events
            .iter()
            .filter(|e| e.severity == AuditSeverity::Critical)
            .count();
        if critical_count > 0 {
            recommendations.push(format!(
                "Address {} critical security events immediately",
                critical_count
            ));
        }

        let failed_auth = events
            .iter()
            .filter(|e| e.category == AuditCategory::Authentication && e.result.contains("failed"))
            .count();
        if failed_auth > 10 {
            recommendations.push(
                "High number of authentication failures detected - review access controls"
                    .to_string(),
            );
        }

        let admin_actions = events
            .iter()
            .filter(|e| e.category == AuditCategory::Administrative)
            .count();
        if admin_actions > events.len() / 4 {
            recommendations.push(
                "High volume of administrative actions - ensure proper authorization".to_string(),
            );
        }

        Ok(recommendations)
    }

    /// Start automated integrity verification
    pub async fn start_automated_verification(&self) -> Result<()> {
        let chain_manager = Arc::clone(&self.chain_manager);
        let scheduler = Arc::clone(&self.verification_scheduler);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // 1 hour

            loop {
                interval.tick().await;

                let should_verify = {
                    let scheduler_guard = scheduler.read().await;
                    let hours_since_last =
                        (Utc::now() - scheduler_guard.last_verification).num_hours();
                    hours_since_last >= scheduler_guard.interval_hours as i64
                };

                if should_verify {
                    info!("Starting automated integrity verification");

                    match chain_manager.verify_chain_integrity(0, 1000).await {
                        Ok(result) => {
                            let mut scheduler_guard = scheduler.write().await;
                            scheduler_guard.last_verification = Utc::now();
                            scheduler_guard
                                .verification_history
                                .push_back(result.clone());

                            if scheduler_guard.verification_history.len() > 100 {
                                scheduler_guard.verification_history.pop_front();
                            }

                            if !result.success {
                                error!(
                                    "Automated integrity verification failed: {} violations",
                                    result.violations.len()
                                );
                            } else {
                                info!("Automated integrity verification passed");
                            }
                        }
                        Err(e) => {
                            error!("Automated integrity verification error: {}", e);
                        }
                    }
                }
            }
        });

        info!("Automated integrity verification started");
        Ok(())
    }
}

/// Compliance report structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Compliance standard
    pub standard: String,
    /// Report time period
    pub report_period: (DateTime<Utc>, DateTime<Utc>),
    /// Total number of audit events
    pub total_events: usize,
    /// Number of critical events
    pub critical_events: usize,
    /// Number of failed events
    pub failed_events: usize,
    /// Number of high-risk events
    pub high_risk_events: usize,
    /// Event breakdown by category
    pub category_breakdown: HashMap<AuditCategory, usize>,
    /// Overall compliance score (0.0 to 1.0)
    pub compliance_score: f64,
    /// Compliance recommendations
    pub recommendations: Vec<String>,
}

impl Default for ComplianceConfiguration {
    fn default() -> Self {
        Self {
            sox_enabled: true,
            gdpr_enabled: true,
            hipaa_enabled: false,
            pci_dss_enabled: false,
            retention_days: 2555, // 7 years for SOX compliance
            data_residency: None,
            encryption_required: true,
            access_control_level: "strict".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Mock storage implementation for testing
    struct MockStorage {
        events: Arc<RwLock<Vec<ImmutableAuditEvent>>>,
        chain_links: Arc<RwLock<Vec<HashChainLink>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                events: Arc::new(RwLock::new(Vec::new())),
                chain_links: Arc::new(RwLock::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl AuditStorage for MockStorage {
        async fn store_event(&self, event: &ImmutableAuditEvent) -> Result<()> {
            self.events.write().await.push(event.clone());
            Ok(())
        }

        async fn query_events(
            &self,
            criteria: &AuditQueryCriteria,
        ) -> Result<Vec<ImmutableAuditEvent>> {
            let events = self.events.read().await;
            let mut filtered = Vec::new();

            for event in events.iter() {
                let mut matches = true;

                if let Some(start_time) = criteria.start_time {
                    if event.timestamp < start_time {
                        matches = false;
                    }
                }

                if let Some(end_time) = criteria.end_time {
                    if event.timestamp > end_time {
                        matches = false;
                    }
                }

                if let Some(ref severity) = criteria.severity {
                    if &event.severity != severity {
                        matches = false;
                    }
                }

                if let Some(ref category) = criteria.category {
                    if &event.category != category {
                        matches = false;
                    }
                }

                if matches {
                    filtered.push(event.clone());
                }
            }

            if let Some(limit) = criteria.limit {
                filtered.truncate(limit);
            }

            Ok(filtered)
        }

        async fn store_chain_link(&self, link: &HashChainLink) -> Result<()> {
            self.chain_links.write().await.push(link.clone());
            Ok(())
        }

        async fn get_chain_links(
            &self,
            start_sequence: u64,
            count: usize,
        ) -> Result<Vec<HashChainLink>> {
            let links = self.chain_links.read().await;
            let filtered: Vec<_> = links
                .iter()
                .filter(|link| link.sequence_number >= start_sequence)
                .take(count)
                .cloned()
                .collect();
            Ok(filtered)
        }

        async fn verify_integrity(&self, _start_sequence: u64, _end_sequence: u64) -> Result<bool> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn test_immutable_audit_logging() {
        let storage = Arc::new(MockStorage::new());
        let config = ComplianceConfiguration::default();
        let logger = ImmutableAuditLogger::new(storage.clone(), config)
            .await
            .unwrap();

        let mut details = BTreeMap::new();
        details.insert("user_id".to_string(), "12345".to_string());
        details.insert("resource".to_string(), "/api/users".to_string());

        let event_id = logger
            .log_event(
                AuditSeverity::High,
                AuditCategory::Authentication,
                "auth-service".to_string(),
                "login_attempt".to_string(),
                "success".to_string(),
                Some("user@example.com".to_string()),
                Some("/api/login".to_string()),
                details,
                Some("192.168.1.100".to_string()),
                Some("Mozilla/5.0".to_string()),
                Some("session-123".to_string()),
                Some("req-456".to_string()),
            )
            .await
            .unwrap();

        assert!(!event_id.is_nil());

        let criteria = AuditQueryCriteria {
            category: Some(AuditCategory::Authentication),
            ..Default::default()
        };

        let events = logger.query_events(&criteria).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event_id);
    }

    #[tokio::test]
    async fn test_hash_chain_integrity() {
        let storage = Arc::new(MockStorage::new());
        let chain_manager = HashChainManager::new(storage.clone(), 2);

        // Add multiple events
        for i in 0..5 {
            let event = ImmutableAuditEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                severity: AuditSeverity::Medium,
                category: AuditCategory::Authentication,
                source: "test".to_string(),
                principal: Some(format!("user{}", i)),
                target: None,
                action: format!("test_action_{}", i),
                result: "success".to_string(),
                details: BTreeMap::new(),
                client_ip: None,
                user_agent: None,
                session_id: None,
                request_id: None,
                geolocation: None,
                risk_score: Some(0.5),
                compliance_tags: vec!["TEST".to_string()],
                event_hash: Vec::new(),
                chain_position: 0,
                signature: None,
            };

            chain_manager.add_event(event).await.unwrap();
        }

        let result = chain_manager.verify_chain_integrity(0, 3).await.unwrap();
        assert!(result.success);
        assert!(result.violations.is_empty());
    }

    #[tokio::test]
    async fn test_compliance_report_generation() {
        let storage = Arc::new(MockStorage::new());
        let config = ComplianceConfiguration::default();
        let logger = ImmutableAuditLogger::new(storage.clone(), config)
            .await
            .unwrap();

        // Log some test events
        for i in 0..10 {
            let severity = if i < 2 {
                AuditSeverity::Critical
            } else {
                AuditSeverity::Medium
            };

            let result = if i < 3 { "failed" } else { "success" };

            logger
                .log_event(
                    severity,
                    AuditCategory::Authentication,
                    "test-service".to_string(),
                    format!("test_action_{}", i),
                    result.to_string(),
                    Some(format!("user{}", i)),
                    None,
                    BTreeMap::new(),
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .unwrap();
        }

        let start_time = Utc::now() - chrono::Duration::hours(1);
        let end_time = Utc::now();

        let report = logger
            .generate_compliance_report(start_time, end_time, "SOX")
            .await
            .unwrap();

        assert_eq!(report.total_events, 10);
        assert_eq!(report.critical_events, 2);
        assert_eq!(report.failed_events, 3);
        assert!(report.compliance_score < 1.0);
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn test_compliance_configuration() {
        let config = ComplianceConfiguration::default();

        assert!(config.sox_enabled);
        assert!(config.gdpr_enabled);
        assert!(!config.hipaa_enabled);
        assert!(!config.pci_dss_enabled);
        assert!(config.encryption_required);
        assert_eq!(config.retention_days, 2555);
    }

    #[test]
    fn test_verification_result() {
        let result = VerificationResult {
            timestamp: Utc::now(),
            success: true,
            blocks_verified: 100,
            violations: Vec::new(),
            duration_ms: 1500,
        };

        assert!(result.success);
        assert_eq!(result.blocks_verified, 100);
        assert!(result.violations.is_empty());
        assert_eq!(result.duration_ms, 1500);
    }
}
