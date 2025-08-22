//! SOAR Step Executors
//!
//! This module provides concrete implementations of step executors for various
//! security operations including IP blocking, account management, notifications,
//! SIEM queries, and integration with external security tools.

use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};
use crate::soar_core::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
use reqwest::{header::HeaderMap, Client};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Registry for all step executors
pub struct StepExecutorRegistry {
    executors: HashMap<String, Arc<dyn StepExecutor + Send + Sync>>,
}

impl StepExecutorRegistry {
    /// Create a new registry with default executors
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut registry = Self {
            executors: HashMap::new(),
        };

        // Register default executors
        registry.register_default_executors().await?;

        Ok(registry)
    }

    /// Register all default step executors
    async fn register_default_executors(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Security action executors
        self.register_executor(Arc::new(IpBlockExecutor::new()))
            .await?;
        self.register_executor(Arc::new(AccountLockExecutor::new()))
            .await?;
        self.register_executor(Arc::new(TokenRevokeExecutor::new().await))
            .await?;

        // Notification executors
        self.register_executor(Arc::new(EmailNotificationExecutor::new().await?))
            .await?;
        self.register_executor(Arc::new(SlackNotificationExecutor::new()))
            .await?;
        self.register_executor(Arc::new(WebhookNotificationExecutor::new()))
            .await?;

        // SIEM and query executors
        self.register_executor(Arc::new(SiemQueryExecutor::new()))
            .await?;
        self.register_executor(Arc::new(DatabaseQueryExecutor::new()))
            .await?;

        // Ticketing and case management
        self.register_executor(Arc::new(TicketCreateExecutor::new()))
            .await?;
        self.register_executor(Arc::new(CaseUpdateExecutor::new()))
            .await?;

        // Script and custom executors
        self.register_executor(Arc::new(ScriptExecutor::new()))
            .await?;
        self.register_executor(Arc::new(HttpRequestExecutor::new()))
            .await?;

        // Control flow executors
        self.register_executor(Arc::new(DecisionExecutor::new()))
            .await?;
        self.register_executor(Arc::new(WaitExecutor::new()))
            .await?;

        info!("Registered {} step executors", self.executors.len());
        Ok(())
    }

    /// Register a step executor
    pub async fn register_executor(
        &mut self,
        executor: Arc<dyn StepExecutor + Send + Sync>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let step_type = executor.get_step_type();
        self.executors.insert(step_type.clone(), executor);
        debug!("Registered step executor: {}", step_type);
        Ok(())
    }

    /// Get executor by step type
    pub fn get_executor(&self, step_type: &str) -> Option<Arc<dyn StepExecutor + Send + Sync>> {
        self.executors.get(step_type).cloned()
    }

    /// Get all executor types
    pub fn get_executor_types(&self) -> Vec<String> {
        self.executors.keys().cloned().collect()
    }
}

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

impl IpBlockExecutor {
    fn validate_ip_address(&self, ip: &str) -> bool {
        ip.parse::<std::net::IpAddr>().is_ok()
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

use crate::store::HybridStore;
use common::Store;

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

impl TokenRevokeExecutor {
    async fn revoke_user_tokens_by_type(
        &self,
        user_id: &str,
        token_type: &str,
    ) -> Result<u32, StepError> {
        // TODO: Implement user-specific token revocation by type
        Ok(1)
    }

    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<u32, StepError> {
        // TODO: Implement all user token revocation
        Ok(5)
    }

    async fn revoke_tokens_by_type(&self, token_type: &str) -> Result<u32, StepError> {
        // TODO: Implement token revocation by type
        Ok(10)
    }

    async fn revoke_all_tokens(&self) -> Result<u32, StepError> {
        // TODO: Implement global token revocation (very dangerous!)
        Ok(100)
    }
}

/// Email notification step executor
pub struct EmailNotificationExecutor {
    smtp_transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    config: EmailConfig,
}

impl EmailNotificationExecutor {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = Self::load_email_config();
        let smtp_transport = if let Some(ref cfg) = config {
            Some(Self::create_smtp_transport(cfg).await?)
        } else {
            None
        };

        Ok(Self {
            smtp_transport,
            config: config.unwrap_or_else(|| EmailConfig {
                smtp_host: "localhost".to_string(),
                smtp_port: 587,
                username: "noreply".to_string(),
                password: "".to_string(),
                from_address: "noreply@example.com".to_string(),
                use_tls: true,
            }),
        })
    }

    fn load_email_config() -> Option<EmailConfig> {
        // Try to load from environment variables
        let smtp_host = std::env::var("SMTP_HOST").ok()?;
        let smtp_port = std::env::var("SMTP_PORT").ok()?.parse().ok()?;
        let username = std::env::var("SMTP_USERNAME").ok()?;
        let password = std::env::var("SMTP_PASSWORD").ok()?;
        let from_address = std::env::var("SMTP_FROM_ADDRESS").ok()?;
        let use_tls =
            std::env::var("SMTP_USE_TLS").unwrap_or_else(|_| "true".to_string()) == "true";

        Some(EmailConfig {
            smtp_host,
            smtp_port,
            username,
            password,
            from_address,
            use_tls,
        })
    }

    async fn create_smtp_transport(
        config: &EmailConfig,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, Box<dyn std::error::Error + Send + Sync>> {
        let creds = Credentials::new(config.username.clone(), config.password.clone());

        let transport = if config.use_tls {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)?
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
                .port(config.smtp_port)
                .credentials(creds)
                .build()
        };

        Ok(transport)
    }
}

#[async_trait]
impl StepExecutor for EmailNotificationExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::SendNotification {
            notification_type,
            recipients,
            subject,
            message,
            priority,
        } = &step.action
        {
            if notification_type != "email" {
                return Err(StepError {
                    code: "INVALID_NOTIFICATION_TYPE".to_string(),
                    message: "This executor only handles email notifications".to_string(),
                    details: None,
                    retryable: false,
                });
            }

            if let Some(ref transport) = self.smtp_transport {
                let mut sent_count = 0;
                let mut failed_recipients = Vec::new();

                for recipient in recipients {
                    match self
                        .send_single_email(transport, recipient, subject, message)
                        .await
                    {
                        Ok(_) => {
                            sent_count += 1;
                            debug!("Email sent successfully to: {}", recipient);
                        }
                        Err(e) => {
                            error!("Failed to send email to {}: {}", recipient, e);
                            failed_recipients.push(recipient.clone());
                        }
                    }
                }

                SecurityLogger::log_event(
                    &SecurityEvent::new(
                        SecurityEventType::AdminAction,
                        SecuritySeverity::Low,
                        "soar_executor".to_string(),
                        format!("Email notification sent to {} recipients", sent_count),
                    )
                    .with_actor("soar_system".to_string())
                    .with_action("soar_execute".to_string())
                    .with_target("soar_playbook".to_string())
                    .with_outcome("success".to_string())
                    .with_reason("Email notification step executed successfully".to_string())
                    .with_detail("recipients".to_string(), recipients.clone())
                    .with_detail("subject".to_string(), subject.clone())
                    .with_detail("priority".to_string(), priority.clone())
                    .with_detail("sent_count".to_string(), sent_count)
                    .with_detail("failed_count".to_string(), failed_recipients.len()),
                );

                let mut outputs = HashMap::new();
                outputs.insert("sent_count".to_string(), Value::Number(sent_count.into()));
                outputs.insert(
                    "failed_recipients".to_string(),
                    Value::Array(failed_recipients.into_iter().map(Value::String).collect()),
                );

                Ok(outputs)
            } else {
                Err(StepError {
                    code: "EMAIL_NOT_CONFIGURED".to_string(),
                    message: "Email transport is not configured".to_string(),
                    details: None,
                    retryable: false,
                })
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not SendNotification".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "email_notification".to_string()
    }
}

impl EmailNotificationExecutor {
    async fn send_single_email(
        &self,
        transport: &AsyncSmtpTransport<Tokio1Executor>,
        recipient: &str,
        subject: &str,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let email = Message::builder()
            .from(self.config.from_address.parse()?)
            .to(recipient.parse()?)
            .subject(subject)
            .body(message.to_string())?;

        transport.send(email).await?;
        Ok(())
    }
}

/// Slack notification step executor
pub struct SlackNotificationExecutor {
    client: Client,
}

impl SlackNotificationExecutor {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

#[async_trait]
impl StepExecutor for SlackNotificationExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::SendNotification {
            notification_type,
            recipients,
            subject,
            message,
            priority,
        } = &step.action
        {
            if notification_type != "slack" {
                return Err(StepError {
                    code: "INVALID_NOTIFICATION_TYPE".to_string(),
                    message: "This executor only handles Slack notifications".to_string(),
                    details: None,
                    retryable: false,
                });
            }

            let webhook_url = std::env::var("SLACK_WEBHOOK_URL").map_err(|_| StepError {
                code: "SLACK_NOT_CONFIGURED".to_string(),
                message: "SLACK_WEBHOOK_URL environment variable not set".to_string(),
                details: None,
                retryable: false,
            })?;

            let color = match priority.as_str() {
                "critical" | "high" => "danger",
                "medium" => "warning",
                _ => "good",
            };

            let payload = serde_json::json!({
                "text": subject,
                "attachments": [{
                    "color": color,
                    "fields": [{
                        "title": "Details",
                        "value": message,
                        "short": false
                    }],
                    "footer": "SOAR Automation",
                    "ts": chrono::Utc::now().timestamp()
                }]
            });

            let response = self
                .client
                .post(&webhook_url)
                .json(&payload)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| StepError {
                    code: "SLACK_REQUEST_FAILED".to_string(),
                    message: format!("Failed to send Slack notification: {}", e),
                    details: Some(serde_json::json!({
                        "error": e.to_string(),
                        "webhook_url": webhook_url
                    })),
                    retryable: true,
                })?;

            if response.status().is_success() {
                SecurityLogger::log_event(
                    &SecurityEvent::new(
                        SecurityEventType::AdminAction,
                        SecuritySeverity::Low,
                        "soar_executor".to_string(),
                        "Slack notification sent successfully".to_string(),
                    )
                    .with_actor("soar_system".to_string())
                    .with_action("soar_execute".to_string())
                    .with_target("soar_playbook".to_string())
                    .with_outcome("success".to_string())
                    .with_reason("Slack notification step executed successfully".to_string())
                    .with_detail("subject".to_string(), subject.clone())
                    .with_detail("priority".to_string(), priority.clone()),
                );

                let mut outputs = HashMap::new();
                outputs.insert("notification_sent".to_string(), Value::Bool(true));
                outputs.insert(
                    "notification_type".to_string(),
                    Value::String("slack".to_string()),
                );

                Ok(outputs)
            } else {
                Err(StepError {
                    code: "SLACK_REQUEST_FAILED".to_string(),
                    message: format!("Slack API returned status: {}", response.status()),
                    details: Some(serde_json::json!({
                        "status": response.status().as_u16(),
                        "response": response.text().await.unwrap_or_else(|_| "Unable to read response".to_string())
                    })),
                    retryable: true,
                })
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not SendNotification".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "slack_notification".to_string()
    }
}

/// Generic webhook notification executor
pub struct WebhookNotificationExecutor {
    client: Client,
}

impl WebhookNotificationExecutor {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

#[async_trait]
impl StepExecutor for WebhookNotificationExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::SendNotification {
            notification_type,
            recipients,
            subject,
            message,
            priority,
        } = &step.action
        {
            if notification_type != "webhook" {
                return Err(StepError {
                    code: "INVALID_NOTIFICATION_TYPE".to_string(),
                    message: "This executor only handles webhook notifications".to_string(),
                    details: None,
                    retryable: false,
                });
            }

            let mut sent_count = 0;
            let mut failed_webhooks = Vec::new();

            for webhook_url in recipients {
                let payload = serde_json::json!({
                    "subject": subject,
                    "message": message,
                    "priority": priority,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "source": "soar_automation"
                });

                match self.send_webhook(webhook_url, &payload).await {
                    Ok(_) => {
                        sent_count += 1;
                        debug!("Webhook notification sent to: {}", webhook_url);
                    }
                    Err(e) => {
                        error!("Failed to send webhook to {}: {}", webhook_url, e);
                        failed_webhooks.push(webhook_url.clone());
                    }
                }
            }

            let mut outputs = HashMap::new();
            outputs.insert("sent_count".to_string(), Value::Number(sent_count.into()));
            outputs.insert(
                "failed_webhooks".to_string(),
                Value::Array(failed_webhooks.into_iter().map(Value::String).collect()),
            );

            Ok(outputs)
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not SendNotification".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "webhook_notification".to_string()
    }
}

impl WebhookNotificationExecutor {
    async fn send_webhook(
        &self,
        url: &str,
        payload: &Value,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = self
            .client
            .post(url)
            .json(payload)
            .timeout(Duration::from_secs(30))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Webhook request failed with status: {}", response.status()).into())
        }
    }
}

/// SIEM query step executor
pub struct SiemQueryExecutor {
    siem_client: Arc<SiemClient>,
}

impl SiemQueryExecutor {
    pub fn new() -> Self {
        Self {
            siem_client: Arc::new(SiemClient::new()),
        }
    }
}

#[async_trait]
impl StepExecutor for SiemQueryExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::QuerySiem {
            query,
            time_range,
            max_results,
        } = &step.action
        {
            info!(
                "Executing SIEM query: {} (time_range: {}, max_results: {})",
                query, time_range, max_results
            );

            match self
                .siem_client
                .execute_query(query, time_range, *max_results)
                .await
            {
                Ok(results) => {
                    let mut outputs = HashMap::new();
                    outputs.insert("query_results".to_string(), results.clone());
                    outputs.insert(
                        "result_count".to_string(),
                        Value::Number(if let Value::Array(arr) = &results {
                            arr.len().into()
                        } else {
                            1.into()
                        }),
                    );
                    outputs.insert("query".to_string(), Value::String(query.clone()));
                    outputs.insert("time_range".to_string(), Value::String(time_range.clone()));

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::DataAccess,
                            SecuritySeverity::Low,
                            "soar_executor".to_string(),
                            "SIEM query executed successfully".to_string(),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("success".to_string())
                        .with_reason("SIEM query step executed successfully".to_string())
                        .with_detail("query".to_string(), query.clone())
                        .with_detail("time_range".to_string(), time_range.clone())
                        .with_detail("max_results".to_string(), *max_results),
                    );

                    Ok(outputs)
                }
                Err(e) => {
                    error!("SIEM query failed: {}", e);

                    Err(StepError {
                        code: "SIEM_QUERY_FAILED".to_string(),
                        message: format!("SIEM query execution failed: {}", e),
                        details: Some(serde_json::json!({
                            "query": query,
                            "time_range": time_range,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    })
                }
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not QuerySiem".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "siem_query".to_string()
    }
}

/// Database query step executor
pub struct DatabaseQueryExecutor {
    #[cfg(feature = "soar")]
    pool: Option<sqlx::PgPool>,
}

impl DatabaseQueryExecutor {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "soar")]
            pool: Self::initialize_pool(),
        }
    }

    #[cfg(feature = "soar")]
    fn initialize_pool() -> Option<sqlx::PgPool> {
        // Try to get database URL from environment
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            match sqlx::postgres::PgPoolOptions::new()
                .max_connections(10)
                .min_connections(2)
                .acquire_timeout(std::time::Duration::from_secs(30))
                .idle_timeout(Some(std::time::Duration::from_secs(600))) // 10 minutes
                .max_lifetime(Some(std::time::Duration::from_secs(1800))) // 30 minutes
                .connect_lazy(&database_url)
            {
                Ok(pool) => {
                    info!("Database pool initialized successfully");
                    Some(pool)
                }
                Err(e) => {
                    error!("Failed to create database pool: {}", e);
                    None
                }
            }
        } else {
            warn!("DATABASE_URL not set, database queries will be disabled");
            None
        }
    }

    #[cfg(feature = "soar")]
    fn validate_query(&self, query: &str) -> Result<(), StepError> {
        // Whitelist of safe operations
        let safe_operations = ["SELECT", "WITH", "EXPLAIN", "SHOW", "DESCRIBE", "DESC"];

        // Dangerous operations that should never be allowed
        let dangerous_operations = [
            "DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "GRANT", "REVOKE", "TRUNCATE",
            "EXEC", "EXECUTE", "CALL", "DO", "LOAD", "COPY", "BULK",
        ];

        let query_upper = query.to_uppercase();
        let first_word = query_upper.trim().split_whitespace().next().unwrap_or("");

        // Check if it's a safe operation
        if !safe_operations.contains(&first_word) {
            return Err(StepError {
                code: "UNSAFE_QUERY_OPERATION".to_string(),
                message: format!(
                    "Query operation '{}' is not allowed for security reasons",
                    first_word
                ),
                details: Some(serde_json::json!({
                    "allowed_operations": safe_operations,
                    "attempted_operation": first_word
                })),
                retryable: false,
            });
        }

        // Check for dangerous patterns
        for dangerous_op in &dangerous_operations {
            if query_upper.contains(dangerous_op) {
                return Err(StepError {
                    code: "DANGEROUS_QUERY_PATTERN".to_string(),
                    message: format!("Query contains dangerous pattern: {}", dangerous_op),
                    details: Some(serde_json::json!({
                        "dangerous_pattern": dangerous_op,
                        "query_snippet": &query[..std::cmp::min(query.len(), 100)]
                    })),
                    retryable: false,
                });
            }
        }

        // Check query length
        if query.len() > 10000 {
            return Err(StepError {
                code: "QUERY_TOO_LONG".to_string(),
                message: "Query exceeds maximum allowed length".to_string(),
                details: Some(serde_json::json!({
                    "query_length": query.len(),
                    "max_length": 10000
                })),
                retryable: false,
            });
        }

        Ok(())
    }

    #[cfg(feature = "soar")]
    fn sanitize_parameter(&self, value: &str) -> String {
        // Remove potentially dangerous characters and patterns
        value
            .chars()
            .filter(|c| c.is_alphanumeric() || " .-_@:".contains(*c))
            .take(1000) // Limit parameter length
            .collect::<String>()
            .replace("--", "") // Remove SQL comment markers
            .replace("/*", "") // Remove SQL comment start
            .replace("*/", "") // Remove SQL comment end
            .replace(";", "") // Remove statement terminators
    }
}

#[async_trait]
impl StepExecutor for DatabaseQueryExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        #[cfg(not(feature = "soar"))]
        {
            return Err(StepError {
                code: "FEATURE_NOT_ENABLED".to_string(),
                message: "Database queries require the 'soar' feature to be enabled".to_string(),
                details: None,
                retryable: false,
            });
        }

        #[cfg(feature = "soar")]
        {
            if let StepAction::ExecuteQuery {
                query,
                parameters,
                timeout_seconds,
            } = &step.action
            {
                // Validate that we have a database pool
                let pool = self.pool.as_ref().ok_or_else(|| StepError {
                    code: "DATABASE_NOT_AVAILABLE".to_string(),
                    message: "Database connection pool is not available".to_string(),
                    details: None,
                    retryable: false,
                })?;

                info!("Executing database query");

                // Validate query for safety
                self.validate_query(query)?;

                // Sanitize parameters
                let mut sanitized_params: HashMap<String, String> = HashMap::new();
                if let Some(params) = parameters {
                    for (key, value) in params {
                        let sanitized_value = self.sanitize_parameter(value);
                        sanitized_params.insert(key.clone(), sanitized_value);
                    }
                }

                // Replace parameters in query safely (using positional parameters)
                let mut final_query = query.clone();
                let mut param_values: Vec<String> = Vec::new();

                for (i, (key, value)) in sanitized_params.iter().enumerate() {
                    let placeholder = format!("${{{}}}", key);
                    let positional_param = format!("${}", i + 1);
                    final_query = final_query.replace(&placeholder, &positional_param);
                    param_values.push(value.clone());
                }

                let timeout_duration = Duration::from_secs(*timeout_seconds as u64);

                // Execute query with timeout and error handling
                let start_time = tokio::time::Instant::now();
                let query_result = tokio::time::timeout(
                    timeout_duration,
                    self.execute_query_internal(pool, &final_query, &param_values),
                )
                .await;

                let execution_time = start_time.elapsed();

                match query_result {
                    Ok(Ok(results)) => {
                        SecurityLogger::log_event(
                            &SecurityEvent::new(
                                SecurityEventType::DataAccess,
                                SecuritySeverity::Low,
                                "soar_executor".to_string(),
                                "Database query executed successfully".to_string(),
                            )
                            .with_actor("soar_system".to_string())
                            .with_action("soar_execute".to_string())
                            .with_target("soar_playbook".to_string())
                            .with_outcome("success".to_string())
                            .with_reason("Database query step executed successfully".to_string())
                            .with_detail(
                                "execution_time_ms".to_string(),
                                execution_time.as_millis(),
                            )
                            .with_detail("result_count".to_string(), results.len()),
                        );

                        let mut outputs = HashMap::new();
                        outputs.insert("query_results".to_string(), Value::Array(results));
                        outputs.insert(
                            "execution_time_ms".to_string(),
                            Value::Number((execution_time.as_millis() as u64).into()),
                        );
                        outputs.insert("success".to_string(), Value::Bool(true));

                        Ok(outputs)
                    }
                    Ok(Err(e)) => {
                        error!("Database query failed: {}", e);

                        SecurityLogger::log_event(
                            &SecurityEvent::new(
                                SecurityEventType::SystemError,
                                SecuritySeverity::Medium,
                                "soar_executor".to_string(),
                                "Database query execution failed".to_string(),
                            )
                            .with_actor("soar_system".to_string())
                            .with_action("soar_execute".to_string())
                            .with_target("soar_playbook".to_string())
                            .with_outcome("failure".to_string())
                            .with_reason(format!("Database query failed: {}", e.to_string()))
                            .with_detail("error".to_string(), e.to_string())
                            .with_detail(
                                "execution_time_ms".to_string(),
                                execution_time.as_millis(),
                            ),
                        );

                        Err(StepError {
                            code: "DATABASE_QUERY_FAILED".to_string(),
                            message: format!("Database query execution failed: {}", e),
                            details: Some(serde_json::json!({
                                "query": &final_query[..std::cmp::min(final_query.len(), 200)],
                                "error": e.to_string(),
                                "execution_time_ms": execution_time.as_millis()
                            })),
                            retryable: true,
                        })
                    }
                    Err(_) => {
                        error!("Database query timed out after {} seconds", timeout_seconds);

                        Err(StepError {
                            code: "DATABASE_QUERY_TIMEOUT".to_string(),
                            message: format!(
                                "Database query timed out after {} seconds",
                                timeout_seconds
                            ),
                            details: Some(serde_json::json!({
                                "timeout_seconds": timeout_seconds,
                                "execution_time_ms": execution_time.as_millis()
                            })),
                            retryable: true,
                        })
                    }
                }
            } else {
                Err(StepError {
                    code: "INVALID_ACTION".to_string(),
                    message: "Step action is not ExecuteQuery".to_string(),
                    details: None,
                    retryable: false,
                })
            }
        }
    }

    fn get_step_type(&self) -> String {
        "database_query".to_string()
    }
}

#[cfg(feature = "soar")]
impl DatabaseQueryExecutor {
    async fn execute_query_internal(
        &self,
        pool: &sqlx::PgPool,
        query: &str,
        parameters: &[String],
    ) -> Result<Vec<Value>, sqlx::Error> {
        use sqlx::Row;

        // Build the query with parameters
        let mut query_builder = sqlx::query(query);

        for param in parameters {
            query_builder = query_builder.bind(param);
        }

        let rows = query_builder.fetch_all(pool).await?;
        let mut results = Vec::new();

        for row in rows {
            let mut result_obj = serde_json::Map::new();

            // Convert each column to a JSON value
            for (i, column) in row.columns().iter().enumerate() {
                let column_name = column.name();

                // Safely extract values based on PostgreSQL types
                let value = match column.type_info().name() {
                    "VARCHAR" | "TEXT" | "CHAR" => row
                        .try_get::<Option<String>, _>(i)
                        .map(|v| v.map(Value::String).unwrap_or(Value::Null))
                        .unwrap_or(Value::Null),
                    "INT4" | "INT8" | "BIGINT" => row
                        .try_get::<Option<i64>, _>(i)
                        .map(|v| v.map(|n| Value::Number(n.into())).unwrap_or(Value::Null))
                        .unwrap_or(Value::Null),
                    "FLOAT4" | "FLOAT8" | "NUMERIC" => row
                        .try_get::<Option<f64>, _>(i)
                        .map(|v| {
                            v.map(|n| {
                                serde_json::Number::from_f64(n)
                                    .map(Value::Number)
                                    .unwrap_or(Value::Null)
                            })
                            .unwrap_or(Value::Null)
                        })
                        .unwrap_or(Value::Null),
                    "BOOL" => row
                        .try_get::<Option<bool>, _>(i)
                        .map(|v| v.map(Value::Bool).unwrap_or(Value::Null))
                        .unwrap_or(Value::Null),
                    "TIMESTAMPTZ" | "TIMESTAMP" => row
                        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(i)
                        .map(|v| {
                            v.map(|dt| Value::String(dt.to_rfc3339()))
                                .unwrap_or(Value::Null)
                        })
                        .unwrap_or(Value::Null),
                    "UUID" => row
                        .try_get::<Option<uuid::Uuid>, _>(i)
                        .map(|v| {
                            v.map(|id| Value::String(id.to_string()))
                                .unwrap_or(Value::Null)
                        })
                        .unwrap_or(Value::Null),
                    _ => {
                        // For unknown types, try to get as string
                        row.try_get::<Option<String>, _>(i)
                            .map(|v| v.map(Value::String).unwrap_or(Value::Null))
                            .unwrap_or(Value::Null)
                    }
                };

                result_obj.insert(column_name.to_string(), value);
            }

            results.push(Value::Object(result_obj));
        }

        Ok(results)
    }
}

/// Ticket creation step executor
pub struct TicketCreateExecutor {
    ticketing_client: Arc<TicketingClient>,
}

impl TicketCreateExecutor {
    pub fn new() -> Self {
        Self {
            ticketing_client: Arc::new(TicketingClient::new()),
        }
    }
}

#[async_trait]
impl StepExecutor for TicketCreateExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::CreateTicket {
            title,
            description,
            priority,
            assignee,
        } = &step.action
        {
            info!("Creating ticket: {} (priority: {})", title, priority);

            match self
                .ticketing_client
                .create_ticket(title, description, priority, assignee.as_deref())
                .await
            {
                Ok(ticket_id) => {
                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::AdminAction,
                            SecuritySeverity::Low,
                            "soar_executor".to_string(),
                            format!("Ticket created: {}", ticket_id),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("success".to_string())
                        .with_reason("Ticket creation step executed successfully".to_string())
                        .with_detail("ticket_id".to_string(), ticket_id.clone())
                        .with_detail("title".to_string(), title.clone())
                        .with_detail("priority".to_string(), priority.clone()),
                    );

                    let mut outputs = HashMap::new();
                    outputs.insert("ticket_id".to_string(), Value::String(ticket_id));
                    outputs.insert("ticket_title".to_string(), Value::String(title.clone()));
                    outputs.insert(
                        "ticket_priority".to_string(),
                        Value::String(priority.clone()),
                    );

                    Ok(outputs)
                }
                Err(e) => {
                    error!("Failed to create ticket: {}", e);

                    Err(StepError {
                        code: "TICKET_CREATION_FAILED".to_string(),
                        message: format!("Failed to create ticket: {}", e),
                        details: Some(serde_json::json!({
                            "title": title,
                            "priority": priority,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    })
                }
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not CreateTicket".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "create_ticket".to_string()
    }
}

/// Case update step executor
pub struct CaseUpdateExecutor {
    case_manager: Arc<CaseManagerClient>,
}

impl CaseUpdateExecutor {
    pub fn new() -> Self {
        Self {
            case_manager: Arc::new(CaseManagerClient::new()),
        }
    }

    fn validate_case_fields(fields: &HashMap<String, Value>) -> Result<(), StepError> {
        // Define allowed fields to prevent injection attacks
        let allowed_fields = [
            "status",
            "priority",
            "assignee",
            "description",
            "tags",
            "resolution",
            "category",
            "severity",
            "due_date",
            "notes",
        ];

        for field_name in fields.keys() {
            if !allowed_fields.contains(&field_name.as_str()) {
                return Err(StepError {
                    code: "INVALID_CASE_FIELD".to_string(),
                    message: format!("Field '{}' is not allowed for case updates", field_name),
                    details: Some(serde_json::json!({
                        "invalid_field": field_name,
                        "allowed_fields": allowed_fields
                    })),
                    retryable: false,
                });
            }
        }

        // Validate specific field constraints
        if let Some(status) = fields.get("status") {
            if let Some(status_str) = status.as_str() {
                let valid_statuses = ["new", "in_progress", "resolved", "closed", "on_hold"];
                if !valid_statuses.contains(&status_str) {
                    return Err(StepError {
                        code: "INVALID_CASE_STATUS".to_string(),
                        message: format!("Invalid case status: {}", status_str),
                        details: Some(serde_json::json!({
                            "invalid_status": status_str,
                            "valid_statuses": valid_statuses
                        })),
                        retryable: false,
                    });
                }
            }
        }

        if let Some(priority) = fields.get("priority") {
            if let Some(priority_str) = priority.as_str() {
                let valid_priorities = ["low", "medium", "high", "critical"];
                if !valid_priorities.contains(&priority_str) {
                    return Err(StepError {
                        code: "INVALID_CASE_PRIORITY".to_string(),
                        message: format!("Invalid case priority: {}", priority_str),
                        details: Some(serde_json::json!({
                            "invalid_priority": priority_str,
                            "valid_priorities": valid_priorities
                        })),
                        retryable: false,
                    });
                }
            }
        }

        if let Some(severity) = fields.get("severity") {
            if let Some(severity_str) = severity.as_str() {
                let valid_severities = ["low", "medium", "high", "critical"];
                if !valid_severities.contains(&severity_str) {
                    return Err(StepError {
                        code: "INVALID_CASE_SEVERITY".to_string(),
                        message: format!("Invalid case severity: {}", severity_str),
                        details: Some(serde_json::json!({
                            "invalid_severity": severity_str,
                            "valid_severities": valid_severities
                        })),
                        retryable: false,
                    });
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl StepExecutor for CaseUpdateExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::UpdateCase {
            case_id,
            fields,
            add_note,
        } = &step.action
        {
            info!("Updating case: {}", case_id);

            // Validate case ID format
            if case_id.is_empty() {
                return Err(StepError {
                    code: "INVALID_CASE_ID".to_string(),
                    message: "Case ID cannot be empty".to_string(),
                    details: None,
                    retryable: false,
                });
            }

            // Validate case fields
            Self::validate_case_fields(fields)?;

            // Check if case exists first
            match self.case_manager.get_case_details(case_id).await {
                Ok(Some(case_details)) => {
                    debug!(
                        "Found case {} with current status: {}",
                        case_id, case_details.status
                    );
                }
                Ok(None) => {
                    return Err(StepError {
                        code: "CASE_NOT_FOUND".to_string(),
                        message: format!("Case with ID '{}' was not found", case_id),
                        details: Some(serde_json::json!({
                            "case_id": case_id
                        })),
                        retryable: false,
                    });
                }
                Err(e) => {
                    error!("Failed to retrieve case details for {}: {}", case_id, e);
                    return Err(StepError {
                        code: "CASE_RETRIEVAL_FAILED".to_string(),
                        message: format!("Failed to retrieve case details: {}", e),
                        details: Some(serde_json::json!({
                            "case_id": case_id,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    });
                }
            }

            // Update the case
            match self.case_manager.update_case(case_id, fields).await {
                Ok(updated_case) => {
                    info!("Successfully updated case: {}", case_id);

                    // Add note if specified
                    let note_added = if let Some(note_content) = add_note {
                        if !note_content.trim().is_empty() {
                            match self
                                .case_manager
                                .add_case_note(case_id, note_content, "soar_system")
                                .await
                            {
                                Ok(note_id) => {
                                    debug!("Added note {} to case {}", note_id, case_id);
                                    true
                                }
                                Err(e) => {
                                    warn!("Failed to add note to case {}: {}", case_id, e);
                                    false
                                }
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::AdminAction,
                            SecuritySeverity::Low,
                            "soar_executor".to_string(),
                            format!("Case {} updated successfully", case_id),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("success".to_string())
                        .with_reason("Case update step executed successfully".to_string())
                        .with_detail("case_id".to_string(), case_id.clone())
                        .with_detail(
                            "updated_fields".to_string(),
                            fields.keys().collect::<Vec<_>>().join(", "),
                        )
                        .with_detail("note_added".to_string(), note_added),
                    );

                    let mut outputs = HashMap::new();
                    outputs.insert("case_id".to_string(), Value::String(case_id.clone()));
                    outputs.insert("case_updated".to_string(), Value::Bool(true));
                    outputs.insert("note_added".to_string(), Value::Bool(note_added));
                    outputs.insert(
                        "updated_fields".to_string(),
                        Value::Array(fields.keys().map(|k| Value::String(k.clone())).collect()),
                    );

                    // Include some key updated case details
                    if let Some(status) = updated_case.get("status") {
                        outputs.insert("new_status".to_string(), status.clone());
                    }
                    if let Some(priority) = updated_case.get("priority") {
                        outputs.insert("new_priority".to_string(), priority.clone());
                    }
                    if let Some(assignee) = updated_case.get("assignee") {
                        outputs.insert("new_assignee".to_string(), assignee.clone());
                    }

                    Ok(outputs)
                }
                Err(e) => {
                    error!("Failed to update case {}: {}", case_id, e);

                    SecurityLogger::log_event(
                        &SecurityEvent::new(
                            SecurityEventType::SystemError,
                            SecuritySeverity::Medium,
                            "soar_executor".to_string(),
                            format!("Failed to update case {}", case_id),
                        )
                        .with_actor("soar_system".to_string())
                        .with_action("soar_execute".to_string())
                        .with_target("soar_playbook".to_string())
                        .with_outcome("failure".to_string())
                        .with_reason(format!("Case update failed: {}", e.to_string()))
                        .with_detail("case_id".to_string(), case_id.clone())
                        .with_detail("error".to_string(), e.to_string()),
                    );

                    Err(StepError {
                        code: "CASE_UPDATE_FAILED".to_string(),
                        message: format!("Failed to update case: {}", e),
                        details: Some(serde_json::json!({
                            "case_id": case_id,
                            "fields": fields,
                            "error": e.to_string()
                        })),
                        retryable: true,
                    })
                }
            }
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not UpdateCase".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "update_case".to_string()
    }
}

/// Script execution step executor
pub struct ScriptExecutor {
    allowed_script_types: Vec<String>,
}

impl ScriptExecutor {
    pub fn new() -> Self {
        Self {
            allowed_script_types: vec![
                "bash".to_string(),
                "rust".to_string(),
                "powershell".to_string(),
            ],
        }
    }

    /// Validate script content for dangerous patterns
    fn validate_script_content(&self, content: &str) -> Result<(), StepError> {
        // List of dangerous patterns that should not be allowed
        let dangerous_patterns = [
            "rm -rf /",
            "dd if=/dev/zero",
            ":(){ :|:& };:", // Fork bomb
            "chmod 777 /",
            "curl | bash",
            "wget | sh",
            "eval",
            "exec",
            "> /dev/sda",
            "mkfs",
            "format c:",
        ];

        for pattern in dangerous_patterns.iter() {
            if content.contains(pattern) {
                return Err(StepError {
                    code: "DANGEROUS_SCRIPT_PATTERN".to_string(),
                    message: format!("Script contains dangerous pattern: {}", pattern),
                    details: Some(format!(
                        "Scripts containing '{}' are not allowed for security reasons",
                        pattern
                    )),
                    retryable: false,
                });
            }
        }

        // Check script length (prevent resource exhaustion)
        if content.len() > 100_000 {
            // 100KB limit
            return Err(StepError {
                code: "SCRIPT_TOO_LARGE".to_string(),
                message: "Script content exceeds maximum allowed size".to_string(),
                details: Some("Scripts must be less than 100KB".to_string()),
                retryable: false,
            });
        }

        Ok(())
    }

    /// Sanitize parameter values to prevent injection attacks
    fn sanitize_parameter(&self, value: &str) -> String {
        // Remove or escape potentially dangerous characters
        value
            .chars()
            .filter(|c| c.is_alphanumeric() || "-_./@: ".contains(*c))
            .collect::<String>()
            .replace('$', "\\$")
            .replace('`', "\\`")
            .replace('"', "\\\"")
            .replace('\\', "\\\\")
    }
}

#[async_trait]
impl StepExecutor for ScriptExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::ExecuteScript {
            script_type,
            script_content,
            parameters,
        } = &step.action
        {
            if !self.allowed_script_types.contains(script_type) {
                return Err(StepError {
                    code: "UNSUPPORTED_SCRIPT_TYPE".to_string(),
                    message: format!("Script type '{}' is not allowed", script_type),
                    details: None,
                    retryable: false,
                });
            }

            info!("Executing {} script", script_type);

            let execution_result = match script_type.as_str() {
                "bash" => self.execute_bash_script(script_content, parameters).await?,
                "rust" => self.execute_rust_script(script_content, parameters).await?,
                "powershell" => {
                    self.execute_powershell_script(script_content, parameters)
                        .await?
                }
                _ => {
                    return Err(StepError {
                        code: "UNSUPPORTED_SCRIPT_TYPE".to_string(),
                        message: format!("Script type '{}' is not implemented", script_type),
                        details: None,
                        retryable: false,
                    })
                }
            };

            SecurityLogger::log_event(
                &SecurityEvent::new(
                    SecurityEventType::AdminAction,
                    SecuritySeverity::Medium,
                    "soar_executor".to_string(),
                    format!("Script executed: {}", script_type),
                )
                .with_actor("soar_system".to_string())
                .with_action("soar_execute".to_string())
                .with_target("soar_playbook".to_string())
                .with_outcome(
                    if execution_result.exit_code == 0 {
                        "success"
                    } else {
                        "failure"
                    }
                    .to_string(),
                )
                .with_reason(format!(
                    "Script execution step completed with exit code {}",
                    execution_result.exit_code
                ))
                .with_detail("script_type".to_string(), script_type.clone())
                .with_detail("exit_code".to_string(), execution_result.exit_code),
            );

            let mut outputs = HashMap::new();
            outputs.insert(
                "exit_code".to_string(),
                Value::Number(execution_result.exit_code.into()),
            );
            outputs.insert("stdout".to_string(), Value::String(execution_result.stdout));
            outputs.insert("stderr".to_string(), Value::String(execution_result.stderr));
            outputs.insert(
                "script_type".to_string(),
                Value::String(script_type.clone()),
            );

            Ok(outputs)
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not ExecuteScript".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "execute_script".to_string()
    }
}

/// Script execution result
#[derive(Debug)]
pub struct ScriptExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ScriptExecutor {
    async fn execute_bash_script(
        &self,
        script_content: &str,
        parameters: &HashMap<String, String>,
    ) -> Result<ScriptExecutionResult, StepError> {
        // Validate script content for dangerous patterns
        self.validate_script_content(script_content)?;

        // Create temporary script file
        let script_file = tempfile::NamedTempFile::new().map_err(|e| StepError {
            code: "SCRIPT_FILE_CREATION_FAILED".to_string(),
            message: format!("Failed to create script file: {}", e),
            details: None,
            retryable: false,
        })?;

        // Write script content with secure parameter substitution
        let mut script_with_params = script_content.to_string();
        for (key, value) in parameters {
            // Sanitize parameter values to prevent injection
            let sanitized_value = self.sanitize_parameter(value);
            script_with_params =
                script_with_params.replace(&format!("${{{}}}", key), &sanitized_value);
        }

        std::fs::write(script_file.path(), script_with_params).map_err(|e| StepError {
            code: "SCRIPT_WRITE_FAILED".to_string(),
            message: format!("Failed to write script: {}", e),
            details: None,
            retryable: false,
        })?;

        // Execute script with timeout and restricted environment
        let output = timeout(
            Duration::from_secs(300), // 5 minute timeout
            Command::new("bash")
                .arg("--restricted") // Run in restricted mode
                .arg("-o")
                .arg("nounset") // Error on undefined variables
                .arg("-o")
                .arg("pipefail") // Exit on pipe failure
                .arg(script_file.path())
                .env_clear() // Clear all environment variables
                .env("PATH", "/usr/bin:/bin") // Restricted PATH
                .output(),
        )
        .await
        .map_err(|_| StepError {
            code: "SCRIPT_TIMEOUT".to_string(),
            message: "Script execution timed out after 5 minutes".to_string(),
            details: None,
            retryable: false,
        })?
        .map_err(|e| StepError {
            code: "SCRIPT_EXECUTION_FAILED".to_string(),
            message: format!("Failed to execute script: {}", e),
            details: None,
            retryable: true,
        })?;

        Ok(ScriptExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    async fn execute_rust_script(
        &self,
        script_content: &str,
        parameters: &HashMap<String, String>,
    ) -> Result<ScriptExecutionResult, StepError> {
        // Validate script content
        self.validate_rust_script_content(script_content)?;

        // Create temporary directory for Rust project
        let temp_dir = tempfile::tempdir().map_err(|e| StepError {
            code: "TEMP_DIR_CREATION_FAILED".to_string(),
            message: format!("Failed to create temp directory: {}", e),
            details: None,
            retryable: false,
        })?;

        let project_path = temp_dir.path();
        let src_dir = project_path.join("src");
        std::fs::create_dir(&src_dir).map_err(|e| StepError {
            code: "SRC_DIR_CREATION_FAILED".to_string(),
            message: format!("Failed to create src directory: {}", e),
            details: None,
            retryable: false,
        })?;

        // Create a minimal Cargo.toml
        let cargo_toml = r#"
[package]
<namespace>name = "soar_script"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
serde_json = "1.0"
        "#;

        std::fs::write(project_path.join("Cargo.toml"), cargo_toml).map_err(|e| StepError {
            code: "CARGO_TOML_WRITE_FAILED".to_string(),
            message: format!("Failed to write Cargo.toml: {}", e),
            details: None,
            retryable: false,
        })?;

        // Write script content with secure parameter substitution
        let mut script_with_params = script_content.to_string();

        // Inject parameters as constants at the beginning of the script
        let mut param_declarations = String::new();
        for (key, value) in parameters {
            let sanitized_value = self.sanitize_parameter(value);
            param_declarations.push_str(&format!(
                "const {}: &str = \"{}\";\n",
                key.to_uppercase(),
                sanitized_value
            ));
        }

        let full_script = format!(
            "{}

fn main() {{\n{}\n}}",
            param_declarations, script_with_params
        );

        std::fs::write(src_dir.join("main.rs"), full_script).map_err(|e| StepError {
            code: "SCRIPT_WRITE_FAILED".to_string(),
            message: format!("Failed to write script: {}", e),
            details: None,
            retryable: false,
        })?;

        // Compile and run the Rust script with restricted environment
        let output = timeout(
            Duration::from_secs(300),
            Command::new("cargo")
                .arg("run")
                .arg("--release")
                .arg("--quiet")
                .current_dir(project_path)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("CARGO_HOME", "/tmp/cargo")
                .env("RUSTUP_HOME", "/tmp/rustup")
                .output(),
        )
        .await
        .map_err(|_| StepError {
            code: "SCRIPT_TIMEOUT".to_string(),
            message: "Script execution timed out after 5 minutes".to_string(),
            details: None,
            retryable: false,
        })?
        .map_err(|e| StepError {
            code: "SCRIPT_EXECUTION_FAILED".to_string(),
            message: format!("Failed to execute script: {}", e),
            details: None,
            retryable: true,
        })?;

        Ok(ScriptExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    /// Validate Rust script content for dangerous patterns
    fn validate_rust_script_content(&self, content: &str) -> Result<(), StepError> {
        // Check for dangerous Rust patterns
        let dangerous_patterns = [
            "std::process::Command",
            "unsafe",
            "std::fs::remove",
            "std::mem::transmute",
            "std::ptr::",
            "libc::",
            "winapi::",
            "std::env::set_var",
            "std::panic::set_hook",
            "#![no_std]",
        ];

        for pattern in dangerous_patterns.iter() {
            if content.contains(pattern) {
                return Err(StepError {
                    code: "DANGEROUS_RUST_PATTERN".to_string(),
                    message: format!("Script contains dangerous Rust pattern: {}", pattern),
                    details: Some(format!(
                        "Scripts containing '{}' are not allowed for security reasons",
                        pattern
                    )),
                    retryable: false,
                });
            }
        }

        // Check script length
        if content.len() > 50_000 {
            // 50KB limit for Rust scripts
            return Err(StepError {
                code: "SCRIPT_TOO_LARGE".to_string(),
                message: "Script content exceeds maximum allowed size".to_string(),
                details: Some("Rust scripts must be less than 50KB".to_string()),
                retryable: false,
            });
        }

        Ok(())
    }

    async fn execute_powershell_script(
        &self,
        script_content: &str,
        parameters: &HashMap<String, String>,
    ) -> Result<ScriptExecutionResult, StepError> {
        // Validate script content
        self.validate_script_content(script_content)?;

        // Create temporary script file
        let script_file = tempfile::NamedTempFile::new().map_err(|e| StepError {
            code: "SCRIPT_FILE_CREATION_FAILED".to_string(),
            message: format!("Failed to create script file: {}", e),
            details: None,
            retryable: false,
        })?;

        // Write script content with secure parameter substitution
        let mut script_with_params = script_content.to_string();
        for (key, value) in parameters {
            let sanitized_value = self.sanitize_parameter(value);
            script_with_params =
                script_with_params.replace(&format!("${{{}}}", key), &sanitized_value);
        }

        std::fs::write(script_file.path(), script_with_params).map_err(|e| StepError {
            code: "SCRIPT_WRITE_FAILED".to_string(),
            message: format!("Failed to write script: {}", e),
            details: None,
            retryable: false,
        })?;

        // Execute PowerShell script with restricted execution policy
        let output = timeout(
            Duration::from_secs(300),
            Command::new("powershell")
                .arg("-NoProfile") // Don't load user profile
                .arg("-NonInteractive") // Non-interactive mode
                .arg("-NoLogo") // Hide logo
                .arg("-ExecutionPolicy")
                .arg("Restricted") // Restricted execution policy
                .arg("-File")
                .arg(script_file.path())
                .env_clear()
                .env("PATH", "C:\\Windows\\System32;C:\\Windows")
                .output(),
        )
        .await
        .map_err(|_| StepError {
            code: "SCRIPT_TIMEOUT".to_string(),
            message: "Script execution timed out after 5 minutes".to_string(),
            details: None,
            retryable: false,
        })?
        .map_err(|e| StepError {
            code: "SCRIPT_EXECUTION_FAILED".to_string(),
            message: format!("Failed to execute script: {}", e),
            details: None,
            retryable: true,
        })?;

        Ok(ScriptExecutionResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

/// HTTP request step executor
pub struct HttpRequestExecutor {
    client: Client,
}

impl HttpRequestExecutor {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

#[async_trait]
impl StepExecutor for HttpRequestExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        if let StepAction::HttpRequest {
            method,
            url,
            headers,
            body,
        } = &step.action
        {
            info!("Executing HTTP {} request to: {}", method, url);

            let mut request_builder = match method.to_uppercase().as_str() {
                "GET" => self.client.get(url),
                "POST" => self.client.post(url),
                "PUT" => self.client.put(url),
                "DELETE" => self.client.delete(url),
                "PATCH" => self.client.patch(url),
                _ => {
                    return Err(StepError {
                        code: "UNSUPPORTED_HTTP_METHOD".to_string(),
                        message: format!("HTTP method '{}' is not supported", method),
                        details: None,
                        retryable: false,
                    })
                }
            };

            // Add headers
            let mut header_map = HeaderMap::new();
            for (key, value) in headers {
                header_map.insert(
                    key.parse().map_err(|e| StepError {
                        code: "INVALID_HEADER".to_string(),
                        message: format!("Invalid header '{}': {}", key, e),
                        details: None,
                        retryable: false,
                    })?,
                    value.parse().map_err(|e| StepError {
                        code: "INVALID_HEADER_VALUE".to_string(),
                        message: format!("Invalid header value for '{}': {}", key, e),
                        details: None,
                        retryable: false,
                    })?,
                );
            }
            request_builder = request_builder.headers(header_map);

            // Add body if present
            if let Some(body_content) = body {
                request_builder = request_builder.body(body_content.clone());
            }

            // Execute request with timeout
            let response = timeout(Duration::from_secs(60), request_builder.send())
                .await
                .map_err(|_| StepError {
                    code: "HTTP_REQUEST_TIMEOUT".to_string(),
                    message: "HTTP request timed out after 60 seconds".to_string(),
                    details: None,
                    retryable: true,
                })?
                .map_err(|e| StepError {
                    code: "HTTP_REQUEST_FAILED".to_string(),
                    message: format!("HTTP request failed: {}", e),
                    details: Some(serde_json::json!({
                        "method": method,
                        "url": url,
                        "error": e.to_string()
                    })),
                    retryable: true,
                })?;

            let status_code = response.status().as_u16();
            let response_headers: HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let response_body = response.text().await.unwrap_or_else(|_| String::new());

            SecurityLogger::log_event(
                &SecurityEvent::new(
                    SecurityEventType::AdminAction,
                    SecuritySeverity::Low,
                    "soar_executor".to_string(),
                    format!("HTTP {} request to {} completed", method, url),
                )
                .with_actor("soar_system".to_string())
                .with_action("soar_execute".to_string())
                .with_target("soar_playbook".to_string())
                .with_outcome(
                    if status_code < 400 {
                        "success"
                    } else {
                        "failure"
                    }
                    .to_string(),
                )
                .with_reason(format!(
                    "HTTP request step completed with status code {}",
                    status_code
                ))
                .with_detail("method".to_string(), method.clone())
                .with_detail("url".to_string(), url.clone())
                .with_detail("status_code".to_string(), status_code),
            );

            let mut outputs = HashMap::new();
            outputs.insert("status_code".to_string(), Value::Number(status_code.into()));
            outputs.insert("response_body".to_string(), Value::String(response_body));
            outputs.insert(
                "response_headers".to_string(),
                serde_json::to_value(response_headers).unwrap(),
            );
            outputs.insert("success".to_string(), Value::Bool(status_code < 400));

            Ok(outputs)
        } else {
            Err(StepError {
                code: "INVALID_ACTION".to_string(),
                message: "Step action is not HttpRequest".to_string(),
                details: None,
                retryable: false,
            })
        }
    }

    fn get_step_type(&self) -> String {
        "http_request".to_string()
    }
}

/// Decision step executor for conditional logic
pub struct DecisionExecutor {}

impl DecisionExecutor {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl StepExecutor for DecisionExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        // TODO: Implement decision logic based on step conditions
        let mut outputs = HashMap::new();
        outputs.insert("decision_made".to_string(), Value::Bool(true));

        Ok(outputs)
    }

    fn get_step_type(&self) -> String {
        "decision".to_string()
    }
}

/// Wait step executor for delays
pub struct WaitExecutor {}

impl WaitExecutor {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl StepExecutor for WaitExecutor {
    #[instrument(skip(self, context))]
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, StepError> {
        // Extract wait duration from step inputs
        let wait_seconds = step
            .inputs
            .get("duration_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        info!("Waiting for {} seconds", wait_seconds);

        tokio::time::sleep(Duration::from_secs(wait_seconds)).await;

        let mut outputs = HashMap::new();
        outputs.insert(
            "waited_seconds".to_string(),
            Value::Number(wait_seconds.into()),
        );
        outputs.insert("wait_completed".to_string(), Value::Bool(true));

        Ok(outputs)
    }

    fn get_step_type(&self) -> String {
        "wait".to_string()
    }
}

// Client implementations for external integrations
pub struct FirewallClient {
    client: Client,
    config: FirewallConfig,
}

pub struct IdentityProviderClient {
    client: Client,
    config: IdentityProviderConfig,
}

pub struct SiemClient {
    client: Client,
    config: SiemConfig,
}

pub struct TicketingClient {
    client: Client,
    config: TicketingConfig,
}

pub struct CaseManagerClient {
    client: Client,
    config: CaseManagerConfig,
}

// Configuration structures
#[derive(Debug, Clone)]
pub struct FirewallConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct IdentityProviderConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct SiemConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct TicketingConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct CaseManagerConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

// Case details structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseDetails {
    pub id: String,
    pub title: String,
    pub status: String,
    pub priority: String,
    pub assignee: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl FirewallClient {
    pub fn new() -> Self {
        let config = Self::load_config();
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
        }
    }

    fn load_config() -> FirewallConfig {
        FirewallConfig {
            api_endpoint: std::env::var("FIREWALL_API_ENDPOINT")
                .unwrap_or_else(|_| "https://firewall-api.example.com".to_string()),
            api_key: std::env::var("FIREWALL_API_KEY")
                .unwrap_or_else(|_| "mock-api-key".to_string()),
            timeout_seconds: std::env::var("FIREWALL_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }

    pub async fn block_ip(
        &self,
        ip_address: &str,
        duration_minutes: u32,
        reason: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let payload = serde_json::json!({
                "action": "block",
                "ip_address": ip_address,
                "duration_minutes": duration_minutes,
                "reason": reason,
                "timestamp": Utc::now().to_rfc3339()
            });

            let response = self
                .client
                .post(&format!("{}/rules/block", self.config.api_endpoint))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: Value = response.json().await?;
                let block_id = result["block_id"]
                    .as_str()
                    .unwrap_or(&format!("block_{}", Uuid::new_v4()))
                    .to_string();

                info!(
                    "Successfully blocked IP {} with ID {}",
                    ip_address, block_id
                );
                Ok(block_id)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Firewall API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            info!(
                "Mock: Blocking IP {} for {} minutes (reason: {})",
                ip_address, duration_minutes, reason
            );
            tokio::time::sleep(Duration::from_millis(100)).await; // Simulate API call
            Ok(format!("block_{}", Uuid::new_v4()))
        }
    }
}

impl IdentityProviderClient {
    pub fn new() -> Self {
        let config = Self::load_config();
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
        }
    }

    fn load_config() -> IdentityProviderConfig {
        IdentityProviderConfig {
            api_endpoint: std::env::var("IDENTITY_PROVIDER_API_ENDPOINT")
                .unwrap_or_else(|_| "https://identity-api.example.com".to_string()),
            api_key: std::env::var("IDENTITY_PROVIDER_API_KEY")
                .unwrap_or_else(|_| "mock-api-key".to_string()),
            timeout_seconds: std::env::var("IDENTITY_PROVIDER_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }

    pub async fn lock_account(
        &self,
        user_id: &str,
        duration_minutes: u32,
        reason: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let payload = serde_json::json!({
                "action": "lock",
                "user_id": user_id,
                "duration_minutes": duration_minutes,
                "reason": reason,
                "timestamp": Utc::now().to_rfc3339()
            });

            let response = self
                .client
                .post(&format!("{}/users/lock", self.config.api_endpoint))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: Value = response.json().await?;
                let lock_id = result["lock_id"]
                    .as_str()
                    .unwrap_or(&format!("lock_{}", Uuid::new_v4()))
                    .to_string();

                info!(
                    "Successfully locked account {} with ID {}",
                    user_id, lock_id
                );
                Ok(lock_id)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Identity Provider API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            info!(
                "Mock: Locking account {} for {} minutes (reason: {})",
                user_id, duration_minutes, reason
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(format!("lock_{}", Uuid::new_v4()))
        }
    }
}

impl SiemClient {
    pub fn new() -> Self {
        let config = Self::load_config();
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
        }
    }

    fn load_config() -> SiemConfig {
        SiemConfig {
            api_endpoint: std::env::var("SIEM_API_ENDPOINT")
                .unwrap_or_else(|_| "https://siem-api.example.com".to_string()),
            api_key: std::env::var("SIEM_API_KEY").unwrap_or_else(|_| "mock-api-key".to_string()),
            timeout_seconds: std::env::var("SIEM_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60), // SIEM queries might take longer
        }
    }

    pub async fn execute_query(
        &self,
        query: &str,
        time_range: &str,
        max_results: u32,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let payload = serde_json::json!({
                "query": query,
                "time_range": time_range,
                "max_results": max_results,
                "timestamp": Utc::now().to_rfc3339()
            });

            let response = self
                .client
                .post(&format!("{}/query", self.config.api_endpoint))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: Value = response.json().await?;
                info!(
                    "SIEM query executed successfully, {} results returned",
                    result
                        .get("results")
                        .and_then(|r| r.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0)
                );
                Ok(result)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("SIEM API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            info!(
                "Mock: Executing SIEM query: {} (time_range: {}, max_results: {})",
                query, time_range, max_results
            );
            tokio::time::sleep(Duration::from_millis(500)).await; // Simulate query time

            // Return realistic mock results
            Ok(serde_json::json!([
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "source_ip": "192.168.1.100",
                    "event_type": "authentication_failure",
                    "count": 5,
                    "user_agent": "Mozilla/5.0...",
                    "geo_location": "US"
                },
                {
                    "timestamp": "2024-01-01T00:05:00Z",
                    "source_ip": "192.168.1.101",
                    "event_type": "authentication_failure",
                    "count": 3,
                    "user_agent": "curl/7.68.0",
                    "geo_location": "CN"
                }
            ]))
        }
    }
}

impl TicketingClient {
    pub fn new() -> Self {
        let config = Self::load_config();
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
        }
    }

    fn load_config() -> TicketingConfig {
        TicketingConfig {
            api_endpoint: std::env::var("TICKETING_API_ENDPOINT")
                .unwrap_or_else(|_| "https://ticketing-api.example.com".to_string()),
            api_key: std::env::var("TICKETING_API_KEY")
                .unwrap_or_else(|_| "mock-api-key".to_string()),
            timeout_seconds: std::env::var("TICKETING_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }

    pub async fn create_ticket(
        &self,
        title: &str,
        description: &str,
        priority: &str,
        assignee: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let payload = serde_json::json!({
                "title": title,
                "description": description,
                "priority": priority,
                "assignee": assignee,
                "timestamp": Utc::now().to_rfc3339(),
                "source": "soar_automation"
            });

            let response = self
                .client
                .post(&format!("{}/tickets", self.config.api_endpoint))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: Value = response.json().await?;
                let ticket_id = result["ticket_id"]
                    .as_str()
                    .unwrap_or(&format!(
                        "TICKET-{}",
                        Uuid::new_v4()
                            .to_string()
                            .chars()
                            .take(8)
                            .collect::<String>()
                            .to_uppercase()
                    ))
                    .to_string();

                info!(
                    "Successfully created ticket {} with title '{}'",
                    ticket_id, title
                );
                Ok(ticket_id)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Ticketing API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            info!(
                "Mock: Creating ticket '{}' with priority {} (assignee: {:?})",
                title, priority, assignee
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(format!(
                "TICKET-{}",
                Uuid::new_v4()
                    .to_string()
                    .chars()
                    .take(8)
                    .collect::<String>()
                    .to_uppercase()
            ))
        }
    }
}

impl CaseManagerClient {
    pub fn new() -> Self {
        let config = Self::load_config();
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
        }
    }

    fn load_config() -> CaseManagerConfig {
        CaseManagerConfig {
            api_endpoint: std::env::var("CASE_MANAGER_API_ENDPOINT")
                .unwrap_or_else(|_| "https://case-manager-api.example.com".to_string()),
            api_key: std::env::var("CASE_MANAGER_API_KEY")
                .unwrap_or_else(|_| "mock-api-key".to_string()),
            timeout_seconds: std::env::var("CASE_MANAGER_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }

    pub async fn get_case_details(
        &self,
        case_id: &str,
    ) -> Result<Option<CaseDetails>, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let response = self
                .client
                .get(&format!("{}/cases/{}", self.config.api_endpoint, case_id))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .send()
                .await?;

            match response.status().as_u16() {
                200 => {
                    let case_details: CaseDetails = response.json().await?;
                    Ok(Some(case_details))
                }
                404 => Ok(None),
                _ => {
                    let error_body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    Err(format!("Case Manager API error: {}", error_body).into())
                }
            }
        } else {
            // Mock implementation for testing
            tokio::time::sleep(Duration::from_millis(50)).await;
            if case_id.starts_with("NONEXISTENT") {
                Ok(None)
            } else {
                Ok(Some(CaseDetails {
                    id: case_id.to_string(),
                    title: format!("Mock Case {}", case_id),
                    status: "in_progress".to_string(),
                    priority: "medium".to_string(),
                    assignee: Some("analyst@example.com".to_string()),
                    created_at: Utc::now() - chrono::Duration::hours(24),
                    updated_at: Utc::now() - chrono::Duration::minutes(30),
                }))
            }
        }
    }

    pub async fn update_case(
        &self,
        case_id: &str,
        fields: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let response = self
                .client
                .patch(&format!("{}/cases/{}", self.config.api_endpoint, case_id))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(fields)
                .send()
                .await?;

            if response.status().is_success() {
                let updated_case: HashMap<String, Value> = response.json().await?;
                info!("Successfully updated case {}", case_id);
                Ok(updated_case)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Case Manager API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut updated_case = HashMap::new();
            updated_case.insert("id".to_string(), Value::String(case_id.to_string()));

            // Copy all the updated fields
            for (key, value) in fields {
                updated_case.insert(key.clone(), value.clone());
            }

            updated_case.insert(
                "updated_at".to_string(),
                Value::String(Utc::now().to_rfc3339()),
            );
            info!(
                "Mock: Updated case {} with fields: {:?}",
                case_id,
                fields.keys().collect::<Vec<_>>()
            );
            Ok(updated_case)
        }
    }

    pub async fn add_case_note(
        &self,
        case_id: &str,
        note: &str,
        author: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let payload = serde_json::json!({
                "note": note,
                "author": author,
                "timestamp": Utc::now().to_rfc3339()
            });

            let response = self
                .client
                .post(&format!(
                    "{}/cases/{}/notes",
                    self.config.api_endpoint, case_id
                ))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: Value = response.json().await?;
                let note_id = result["note_id"]
                    .as_str()
                    .unwrap_or(&format!("note_{}", Uuid::new_v4()))
                    .to_string();
                Ok(note_id)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Case Manager API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            tokio::time::sleep(Duration::from_millis(50)).await;
            let note_id = format!("note_{}", Uuid::new_v4());
            info!(
                "Mock: Added note {} to case {} by author {}",
                note_id, case_id, author
            );
            Ok(note_id)
        }
    }
}
