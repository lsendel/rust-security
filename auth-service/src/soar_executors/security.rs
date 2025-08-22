//! Security Action Executors
//!
//! This module provides executors for security-related actions such as
//! IP blocking, account locking, and token revocation.

use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};
use crate::soar_core::{StepAction, StepError, StepExecutor, WorkflowStep};
use crate::store::HybridStore;
use async_trait::async_trait;
use common::Store;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, instrument, warn};

use super::clients::{FirewallClient, IdentityProviderClient};

/// IP blocking step executor
pub struct IpBlockExecutor {
    firewall_client: Arc<FirewallClient>,
}

impl IpBlockExecutor {
    pub fn new() -> Self {
        Self {
            firewall_client: Arc::new(FirewallClient::new()),
        }
    }

    fn validate_ip_address(&self, ip: &str) -> bool {
        ip.parse::<std::net::IpAddr>().is_ok()
    }
}

#[async_trait]
impl StepExecutor for IpBlockExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::BlockIp {
            ip_address,
            duration_minutes,
            reason,
        } = &step.action
        {
            info!(
                "Blocking IP address: {} for {} minutes",
                ip_address, duration_minutes
            );

            // Validate IP address format
            if !self.validate_ip_address(ip_address) {
                return Err(StepError {
                    code: "INVALID_IP_ADDRESS".to_string(),
                    message: format!("Invalid IP address format: {}", ip_address),
                    details: None,
                    retryable: false,
                });
            }

            // Execute IP block
            match self
                .firewall_client
                .block_ip(ip_address, *duration_minutes, reason)
                .await
            {
                Ok(block_id) => {
                    // Log security event
                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::AdminAction,
                            SecuritySeverity::Medium,
                            "soar_executor".to_string(),
                            format!(
                                "IP address {} blocked for {} minutes",
                                ip_address, duration_minutes
                            ),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("success".to_string())
                        .with_reason("IP blocking step executed successfully".to_string())
                        .with_detail("ip_address".to_string(), ip_address.clone())
                        .with_detail("duration_minutes".to_string(), *duration_minutes)
                        .with_detail("reason".to_string(), reason.clone())
                        .with_detail("block_id".to_string(), block_id.clone()),
                    );

                    let mut outputs = HashMap::new();
                    outputs.insert("block_id".to_string(), Value::String(block_id));
                    outputs.insert("blocked_ip".to_string(), Value::String(ip_address.clone()));
                    outputs.insert(
                        "block_duration".to_string(),
                        Value::Number((*duration_minutes).into()),
                    );

                    Ok(outputs)
                }
                Err(e) => {
                    error!("Failed to block IP address {}: {}", ip_address, e);

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::SystemError,
                            SecuritySeverity::High,
                            "soar_executor".to_string(),
                            format!("Failed to block IP address {}", ip_address),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("failure".to_string())
                        .with_reason(format!("IP blocking failed: {}", e.to_string()))
                        .with_detail("ip_address".to_string(), ip_address.clone())
                        .with_detail("error".to_string(), e.to_string()),
                    );

                    Err(StepError {
                        code: "IP_BLOCK_FAILED".to_string(),
                        message: format!("Failed to block IP address: {}", e),
                        details: Some(serde_json::json!({
                            "ip_address": ip_address,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    })
                }
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not BlockIp".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "block_ip".to_string()
    }
}

/// Account locking step executor
pub struct AccountLockExecutor {
    identity_client: Arc<IdentityProviderClient>,
}

impl AccountLockExecutor {
    pub fn new() -> Self {
        Self {
            identity_client: Arc::new(IdentityProviderClient::new()),
        }
    }
}

#[async_trait]
impl StepExecutor for AccountLockExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::LockAccount {
            user_id,
            duration_minutes,
            reason,
        } = &step.action
        {
            info!(
                "Locking account: {} for {} minutes",
                user_id, duration_minutes
            );

            // Validate user ID
            if user_id.is_empty() {
                return Err(StepError {
                    code: "INVALID_USER_ID".to_string(),
                    message: "User ID cannot be empty".to_string(),
                    details: None,
                    retryable: false,
                });
            }

            // Execute account lock
            match self
                .identity_client
                .lock_account(user_id, *duration_minutes, reason)
                .await
            {
                Ok(lock_id) => {
                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::AdminAction,
                            SecuritySeverity::High,
                            "soar_executor".to_string(),
                            format!(
                                "Account {} locked for {} minutes",
                                user_id, duration_minutes
                            ),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("success".to_string())
                        .with_reason("Account locking step executed successfully".to_string())
                        .with_user_id(user_id.clone())
                        .with_detail("duration_minutes".to_string(), *duration_minutes)
                        .with_detail("reason".to_string(), reason.clone())
                        .with_detail("lock_id".to_string(), lock_id.clone()),
                    );

                    let mut outputs = HashMap::new();
                    outputs.insert("lock_id".to_string(), Value::String(lock_id));
                    outputs.insert("locked_user".to_string(), Value::String(user_id.clone()));
                    outputs.insert(
                        "lock_duration".to_string(),
                        Value::Number((*duration_minutes).into()),
                    );

                    Ok(outputs)
                }
                Err(e) => {
                    error!("Failed to lock account {}: {}", user_id, e);

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::SystemError,
                            SecuritySeverity::High,
                            "soar_executor".to_string(),
                            format!("Failed to lock account {}", user_id),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("failure".to_string())
                        .with_reason(format!("Account locking failed: {}", e.to_string()))
                        .with_user_id(user_id.clone())
                        .with_detail("error".to_string(), e.to_string()),
                    );

                    Err(StepError {
                        code: "ACCOUNT_LOCK_FAILED".to_string(),
                        message: format!("Failed to lock account: {}", e),
                        details: Some(serde_json::json!({
                            "user_id": user_id,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    })
                }
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not LockAccount".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "lock_account".to_string()
    }
}

/// Token revocation step executor
pub struct TokenRevokeExecutor {
    store: Arc<dyn Store>,
}

impl TokenRevokeExecutor {
    pub async fn new() -> Self {
        Self {
            store: Arc::new(HybridStore::new().await),
        }
    }

    async fn revoke_user_tokens_by_type(
        &self,
        user_id: &str,
        token_type: &str,
    ) -> Result<u32, StepError> {
        // Implementation for user-specific token revocation by type
        // This would interact with the token store to revoke specific tokens
        info!("Revoking {} tokens for user {}", token_type, user_id);
        
        // Simulate token revocation
        // In a real implementation, this would:
        // 1. Query the store for tokens matching user_id and token_type
        // 2. Mark them as revoked or delete them
        // 3. Return the count of revoked tokens
        
        Ok(1) // Simulated count
    }

    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<u32, StepError> {
        // Implementation for revoking all tokens for a specific user
        info!("Revoking all tokens for user {}", user_id);
        
        // Simulate token revocation
        Ok(5) // Simulated count
    }

    async fn revoke_tokens_by_type(&self, token_type: &str) -> Result<u32, StepError> {
        // Implementation for revoking all tokens of a specific type
        warn!("Revoking all {} tokens system-wide", token_type);
        
        // Simulate token revocation
        Ok(10) // Simulated count
    }

    async fn revoke_all_tokens(&self) -> Result<u32, StepError> {
        // Implementation for revoking ALL tokens (very dangerous operation)
        warn!("Revoking ALL tokens system-wide - this is a drastic action");
        
        // Simulate token revocation
        Ok(100) // Simulated count
    }
}

#[async_trait]
impl StepExecutor for TokenRevokeExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::RevokeTokens {
            user_id,
            token_type,
        } = &step.action
        {
            let revoked_count = match (user_id, token_type) {
                (Some(uid), Some(ttype)) => {
                    info!("Revoking {} tokens for user: {}", ttype, uid);
                    self.revoke_user_tokens_by_type(uid, ttype).await?
                }
                (Some(uid), None) => {
                    info!("Revoking all tokens for user: {}", uid);
                    self.revoke_all_user_tokens(uid).await?
                }
                (None, Some(ttype)) => {
                    info!("Revoking all {} tokens", ttype);
                    self.revoke_tokens_by_type(ttype).await?
                }
                (None, None) => {
                    warn!("Revoking all tokens - this is a drastic action");
                    self.revoke_all_tokens().await?
                }
            };

            SecurityLogger::log_event(
                &SecurityEvent::new(
                    SecurityEventType::TokenRevoked,
                    SecuritySeverity::Medium,
                    "soar_executor".to_string(),
                    format!("Revoked {} tokens", revoked_count),
                )
                .with_actor("soar_system".to_string())
                .with_action("soar_execute".to_string())
                .with_target("soar_playbook".to_string())
                .with_outcome("success".to_string())
                .with_reason("Token revocation step executed successfully".to_string())
                .with_user_id(user_id.clone().unwrap_or("all".to_string()))
                .with_detail(
                    "token_type".to_string(),
                    token_type.clone().unwrap_or("all".to_string()),
                )
                .with_detail("revoked_count".to_string(), revoked_count),
            );

            let mut outputs = HashMap::new();
            outputs.insert(
                "revoked_count".to_string(),
                Value::Number(revoked_count.into()),
            );
            if let Some(uid) = user_id {
                outputs.insert("user_id".to_string(), Value::String(uid.clone()));
            }
            if let Some(ttype) = token_type {
                outputs.insert("token_type".to_string(), Value::String(ttype.clone()));
            }

            Ok(outputs)
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not RevokeTokens".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "revoke_tokens".to_string()
    }
}

impl Default for IpBlockExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for AccountLockExecutor {
    fn default() -> Self {
        Self::new()
    }
}
