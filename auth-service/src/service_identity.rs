//! Service Account and Non-Human Identity Management
//!
//! Implements secure management for service accounts, API keys, and AI agents
//! to prevent `OAuth` token compromise attacks like the Salesloft breach.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

use crate::shared::error::AppError;
// Security monitoring types are now part of the security_monitoring module
use crate::security_monitoring::{AlertSeverity, SecurityAlert, SecurityAlertType};

/// Identity type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityType {
    /// Human user account
    Human { user_id: String, mfa_enabled: bool },
    /// Service account for backend services
    ServiceAccount {
        service_name: String,
        environment: Environment,
        owner_team: String,
    },
    /// API key for external integrations
    ApiKey {
        client_id: String,
        integration_type: String,
    },
    /// AI agent or bot
    AiAgent {
        agent_id: String,
        model_type: String,
        capabilities: Vec<String>,
    },
    /// Machine workload (container, VM, etc.)
    MachineWorkload {
        workload_id: String,
        orchestrator: String,
        namespace: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

/// Service identity with enhanced security controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceIdentity {
    pub id: Uuid,
    pub identity_type: IdentityType,
    pub created_at: DateTime<Utc>,
    pub last_authenticated: Option<DateTime<Utc>>,
    pub last_rotated: Option<DateTime<Utc>>,

    /// Security constraints
    pub max_token_lifetime_seconds: u64,
    pub allowed_scopes: HashSet<String>,
    pub allowed_ips: Option<Vec<String>>,
    pub allowed_hours: Option<(u8, u8)>, // (start_hour, end_hour) in UTC

    /// Risk and compliance
    pub risk_score: f32,
    pub requires_attestation: bool,
    pub requires_continuous_auth: bool,

    /// Behavioral baseline
    pub baseline_established: bool,
    pub baseline_metrics: Option<BehavioralBaseline>,

    /// Status
    pub status: IdentityStatus,
    pub suspension_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralBaseline {
    pub avg_requests_per_minute: f64,
    pub common_endpoints: Vec<String>,
    pub typical_request_sizes: (usize, usize), // (min, max)
    pub typical_hours: Vec<u8>,
    pub typical_source_ips: HashSet<String>,
    pub established_at: DateTime<Utc>,
    pub confidence_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityStatus {
    Active,
    Suspended,
    PendingRotation,
    Compromised,
    Decommissioned,
}

/// Just-In-Time (JIT) access request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitAccessRequest {
    pub identity_id: Uuid,
    pub requested_scopes: Vec<String>,
    pub justification: String,
    pub duration_seconds: u64,
    pub request_context: RequestContext,
    pub approval_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub source_ip: String,
    pub user_agent: Option<String>,
    pub request_id: String,
    pub parent_span_id: Option<String>,
    pub attestation_data: Option<HashMap<String, String>>,
}

/// JIT access token with minimal privileges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitToken {
    pub token_id: Uuid,
    pub identity_id: Uuid,
    pub granted_scopes: Vec<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub request_context: RequestContext,
    pub revocable: bool,
    pub usage_count: u32,
    pub max_usage: Option<u32>,
}

/// Service identity manager with comprehensive security controls
#[derive(Clone)]
pub struct ServiceIdentityManager {
    identities: Arc<RwLock<HashMap<Uuid, ServiceIdentity>>>,
    jit_tokens: Arc<RwLock<HashMap<Uuid, JitToken>>>,
    monitoring: Arc<dyn SecurityMonitoring>,
    policy_engine: Arc<PolicyEngine>,
}

/// Security monitoring trait for service accounts
#[async_trait]
pub trait SecurityMonitoring: Send + Sync {
    async fn log_authentication(&self, identity: &ServiceIdentity, success: bool);
    async fn check_anomaly(&self, identity: &ServiceIdentity, context: &RequestContext) -> bool;
    async fn raise_alert(&self, alert: SecurityAlert);
    async fn update_baseline(&self, identity_id: Uuid, metrics: BehavioralBaseline);
}

/// Policy engine for access control decisions
pub struct PolicyEngine {
    policies: Arc<RwLock<Vec<AccessPolicy>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub id: String,
    pub name: String,
    pub applies_to: Vec<IdentityType>,
    pub conditions: Vec<PolicyCondition>,
    pub effect: PolicyEffect,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCondition {
    TimeWindow {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },
    IpWhitelist(Vec<String>),
    ScopeRestriction(Vec<String>),
    RiskScoreThreshold(f32),
    RequireMfa,
    RequireAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEffect {
    Allow,
    Deny,
    RequireApproval,
}

impl ServiceIdentityManager {
    pub fn new(monitoring: Arc<dyn SecurityMonitoring>) -> Self {
        Self {
            identities: Arc::new(RwLock::new(HashMap::new())),
            jit_tokens: Arc::new(RwLock::new(HashMap::new())),
            monitoring,
            policy_engine: Arc::new(PolicyEngine::new()),
        }
    }

    /// Register a new service identity
    pub async fn register_identity(
        &self,
        identity_type: IdentityType,
        config: IdentityConfig,
    ) -> Result<ServiceIdentity, crate::shared::error::AppError> {
        let identity = ServiceIdentity {
            id: Uuid::new_v4(),
            identity_type: identity_type.clone(),
            created_at: Utc::now(),
            last_authenticated: None,
            last_rotated: None,
            max_token_lifetime_seconds: self.get_max_lifetime(&identity_type),
            allowed_scopes: config.allowed_scopes,
            allowed_ips: config.allowed_ips,
            allowed_hours: config.allowed_hours,
            risk_score: 0.0,
            requires_attestation: self.requires_attestation(&identity_type),
            requires_continuous_auth: self.requires_continuous_auth(&identity_type),
            baseline_established: false,
            baseline_metrics: None,
            status: IdentityStatus::Active,
            suspension_reason: None,
        };

        let identity_id = identity.id;
        let mut identities = self.identities.write().await;
        identities.insert(identity_id, identity.clone());
        drop(identities); // Release lock early

        info!("Registered new service identity: {:?}", identity_id);
        Ok(identity)
    }

    /// Request JIT access token
    pub async fn request_jit_access(
        &self,
        request: JitAccessRequest,
    ) -> Result<JitToken, crate::shared::error::AppError> {
        // Validate identity exists and is active
        let identities = self.identities.read().await;
        let identity =
            identities
                .get(&request.identity_id)
                .ok_or_else(|| crate::shared::error::AppError::InvalidRequest {
                    reason: format!("Identity not found: {}", request.identity_id),
                })?;

        if identity.status != IdentityStatus::Active {
            return Err(crate::shared::error::AppError::Forbidden {
                reason: format!("Identity suspended: {}", request.identity_id),
            });
        }

        // Check for anomalies
        if self
            .monitoring
            .check_anomaly(identity, &request.request_context)
            .await
        {
            self.monitoring
                .raise_alert(SecurityAlert {
                    id: Uuid::new_v4().to_string(),
                    alert_type: SecurityAlertType::AnomalousPattern,
                    severity: AlertSeverity::High,
                    title: format!("Anomalous JIT request from {:?}", identity.identity_type),
                    description: "Suspicious JIT access request detected".to_string(),
                    timestamp: Utc::now().timestamp() as u64,
                    source_ip: Some(request.request_context.source_ip.clone()),
                    destination_ip: None,
                    source: "ServiceIdentityManager".to_string(),
                    user_id: None,
                    client_id: Some(request.identity_id.to_string()),
                    metadata: HashMap::new(),
                    resolved: false,
                    resolution_notes: None,
                })
                .await;

            return Err(crate::shared::error::AppError::AnomalyDetected);
        }

        // Apply policy engine
        let policy_decision = self.policy_engine.evaluate(identity, &request).await?;

        if policy_decision == PolicyEffect::Deny {
            return Err(crate::shared::error::AppError::PolicyDenied);
        }

        if policy_decision == PolicyEffect::RequireApproval && !request.approval_required {
            return Err(crate::shared::error::AppError::ApprovalRequired);
        }

        // Calculate token lifetime (minimum of requested and max allowed)
        let lifetime = std::cmp::min(
            request.duration_seconds,
            identity.max_token_lifetime_seconds,
        );

        // Filter scopes to only allowed ones
        let granted_scopes: Vec<String> = request
            .requested_scopes
            .into_iter()
            .filter(|s| identity.allowed_scopes.contains(s))
            .collect();

        let token = JitToken {
            token_id: Uuid::new_v4(),
            identity_id: identity.id,
            granted_scopes,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(lifetime as i64),
            request_context: request.request_context,
            revocable: true,
            usage_count: 0,
            max_usage: Some(100), // Limit usage to prevent abuse
        };

        let mut tokens = self.jit_tokens.write().await;
        tokens.insert(token.token_id, token.clone());

        info!("Issued JIT token for identity {:?}", identity.id);
        Ok(token)
    }

    /// Validate and track token usage
    pub async fn validate_token(
        &self,
        token_id: Uuid,
        context: &RequestContext,
    ) -> Result<bool, crate::shared::error::AppError> {
        let mut tokens = self.jit_tokens.write().await;

        if let Some(token) = tokens.get_mut(&token_id) {
            // Check expiration
            if Utc::now() > token.expires_at {
                tokens.remove(&token_id);
                return Ok(false);
            }

            // Check usage limit
            token.usage_count += 1;
            if let Some(max) = token.max_usage {
                if token.usage_count > max {
                    warn!("Token {:?} exceeded usage limit", token_id);
                    tokens.remove(&token_id);
                    return Ok(false);
                }
            }

            // Validate context matches (IP, etc.)
            if token.request_context.source_ip != context.source_ip {
                warn!("Token {:?} used from different IP", token_id);
                return Ok(false);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Revoke all tokens for a compromised identity
    pub async fn revoke_identity_tokens(&self, identity_id: Uuid) -> Result<u32, crate::shared::error::AppError> {
        let mut tokens = self.jit_tokens.write().await;
        let mut revoked = 0;

        tokens.retain(|_, token| {
            if token.identity_id == identity_id {
                revoked += 1;
                false
            } else {
                true
            }
        });

        // Update identity status
        let mut identities = self.identities.write().await;
        if let Some(identity) = identities.get_mut(&identity_id) {
            identity.status = IdentityStatus::Compromised;
            identity.suspension_reason = Some("Tokens revoked due to compromise".to_string());
        }

        warn!(
            "Revoked {} tokens for compromised identity {:?}",
            revoked, identity_id
        );
        Ok(revoked)
    }

    /// Rotate credentials for an identity
    pub async fn rotate_credentials(&self, identity_id: Uuid) -> Result<(), crate::shared::error::AppError> {
        let mut identities = self.identities.write().await;

        if let Some(identity) = identities.get_mut(&identity_id) {
            identity.last_rotated = Some(Utc::now());
            identity.status = IdentityStatus::PendingRotation;

            // Revoke existing tokens
            self.revoke_identity_tokens(identity_id).await?;

            info!(
                "Initiated credential rotation for identity {:?}",
                identity_id
            );
            Ok(())
        } else {
            Err(crate::shared::error::AppError::IdentityNotFound)
        }
    }

    /// Helper: Determine max token lifetime based on identity type
    const fn get_max_lifetime(&self, identity_type: &IdentityType) -> u64 {
        match identity_type {
            IdentityType::Human { .. } => 900, // 15 minutes
            IdentityType::ServiceAccount {
                environment: Environment::Production,
                ..
            } => 3600, // 1 hour
            IdentityType::ServiceAccount { .. } => 7200, // 2 hours for non-prod
            IdentityType::ApiKey { .. } => 1800, // 30 minutes
            IdentityType::AiAgent { .. } => 300, // 5 minutes - highest risk
            IdentityType::MachineWorkload { .. } => 600, // 10 minutes
        }
    }

    /// Helper: Check if identity requires attestation
    const fn requires_attestation(&self, identity_type: &IdentityType) -> bool {
        matches!(
            identity_type,
            IdentityType::AiAgent { .. } | IdentityType::MachineWorkload { .. }
        )
    }

    /// Helper: Check if identity requires continuous auth
    const fn requires_continuous_auth(&self, identity_type: &IdentityType) -> bool {
        matches!(
            identity_type,
            IdentityType::AiAgent { .. }
                | IdentityType::ServiceAccount {
                    environment: Environment::Production,
                    ..
                }
        )
    }
}

/// Configuration for creating a service identity
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    pub allowed_scopes: HashSet<String>,
    pub allowed_ips: Option<Vec<String>>,
    pub allowed_hours: Option<(u8, u8)>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn evaluate(
        &self,
        identity: &ServiceIdentity,
        request: &JitAccessRequest,
    ) -> Result<PolicyEffect, crate::shared::error::AppError> {
        let policies = self.policies.read().await;

        // Find applicable policies sorted by priority
        let mut applicable: Vec<_> = policies
            .iter()
            .filter(|p| self.applies_to_identity(p, &identity.identity_type))
            .collect();

        applicable.sort_by_key(|p| -p.priority);

        // Evaluate policies in priority order
        for policy in applicable {
            if self.conditions_met(policy, identity, request) {
                return Ok(policy.effect.clone());
            }
        }

        // Default allow if no policies match
        Ok(PolicyEffect::Allow)
    }

    fn applies_to_identity(&self, policy: &AccessPolicy, identity_type: &IdentityType) -> bool {
        // Check if policy applies to this identity type
        policy
            .applies_to
            .iter()
            .any(|t| std::mem::discriminant(t) == std::mem::discriminant(identity_type))
    }

    fn conditions_met(
        &self,
        policy: &AccessPolicy,
        identity: &ServiceIdentity,
        request: &JitAccessRequest,
    ) -> bool {
        policy.conditions.iter().all(|condition| match condition {
            PolicyCondition::RiskScoreThreshold(threshold) => identity.risk_score <= *threshold,
            PolicyCondition::ScopeRestriction(allowed) => {
                request.requested_scopes.iter().all(|s| allowed.contains(s))
            }
            PolicyCondition::IpWhitelist(ips) => ips.contains(&request.request_context.source_ip),
            PolicyCondition::RequireAttestation => {
                request.request_context.attestation_data.is_some()
            }
            _ => true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_identity_max_lifetime() {
        let manager = ServiceIdentityManager::new(Arc::new(MockMonitoring));

        // AI agents should have shortest lifetime
        let ai_type = IdentityType::AiAgent {
            agent_id: "test-ai".to_string(),
            model_type: "gpt-4".to_string(),
            capabilities: vec!["read".to_string()],
        };

        assert_eq!(manager.get_max_lifetime(&ai_type), 300); // 5 minutes
    }

    struct MockMonitoring;

    #[async_trait]
    impl SecurityMonitoring for MockMonitoring {
        async fn log_authentication(&self, _: &ServiceIdentity, _: bool) {}
        async fn check_anomaly(&self, _: &ServiceIdentity, _: &RequestContext) -> bool {
            false
        }
        async fn raise_alert(&self, _: SecurityAlert) {}
        async fn update_baseline(&self, _: Uuid, _: BehavioralBaseline) {}
    }
}
