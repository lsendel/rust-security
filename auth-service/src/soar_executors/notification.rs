//! Notification Executors
//!
//! This module provides executors for various notification methods including
//! email, Slack, and generic webhook notifications.

use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};
use crate::soar_core::{StepAction, StepError, StepExecutor, WorkflowStep};
use async_trait::async_trait;
use lettre::{transport::smtp::authentication::Credentials, Message, SmtpTransport, Transport};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, error, info, instrument, warn};

/// Email configuration
#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub use_tls: bool,
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
                password: String::new(),
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

            SecurityLogger::log_event(
                &SecurityEvent::new(
                    SecurityEventType::AdminAction,
                    SecuritySeverity::Low,
                    "soar_executor".to_string(),
                    format!("Webhook notifications sent to {} endpoints", sent_count),
                )
                .with_actor("soar_system".to_string())
                .with_action("soar_execute".to_string())
                .with_target("soar_playbook".to_string())
                .with_outcome("success".to_string())
                .with_reason("Webhook notification step executed successfully".to_string())
                .with_detail("subject".to_string(), subject.clone())
                .with_detail("priority".to_string(), priority.clone())
                .with_detail("sent_count".to_string(), sent_count)
                .with_detail("failed_count".to_string(), failed_webhooks.len()),
            );

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

impl Default for SlackNotificationExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for WebhookNotificationExecutor {
    fn default() -> Self {
        Self::new()
    }
}
