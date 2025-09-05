//! Security Alert Handlers
//!
//! Implementations for different alert notification channels including
//! email, Slack, PagerDuty, and SIEM integration.

use crate::monitoring::security_alerts::{AlertError, AlertHandler, SecurityEvent};
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;

/// Email alert handler using SMTP
pub struct EmailAlertHandler {
    smtp_server: String,
    smtp_port: u16,
    username: String,
    password: String,
    from_address: String,
    to_addresses: Vec<String>,
}

impl EmailAlertHandler {
    pub fn new(
        smtp_server: String,
        smtp_port: u16,
        username: String,
        password: String,
        from_address: String,
        to_addresses: Vec<String>,
    ) -> Self {
        Self {
            smtp_server,
            smtp_port,
            username,
            password,
            from_address,
            to_addresses,
        }
    }

    fn format_email_subject(&self, event: &SecurityEvent) -> String {
        format!(
            "[SECURITY ALERT] {:?} - {:?}",
            event.severity, event.event_type
        )
    }

    fn format_email_body(&self, event: &SecurityEvent) -> String {
        format!(
            r#"Security Alert Details:

Event Type: {:?}
Severity: {:?}
Timestamp: {}
Source IP: {:?}
User ID: {:?}
Session ID: {:?}
User Agent: {:?}
Endpoint: {:?}
Message: {}

Metadata:
{:#?}

This is an automated security alert from the Rust Security Platform.
Please investigate this incident immediately.
"#,
            event.event_type,
            event.severity,
            chrono::DateTime::from_timestamp(event.timestamp as i64, 0)
                .unwrap_or_default(),
            event.source_ip,
            event.user_id,
            event.session_id,
            event.user_agent,
            event.endpoint,
            event.message,
            event.metadata
        )
    }
}

#[async_trait]
impl AlertHandler for EmailAlertHandler {
    async fn send_alert(&self, event: &SecurityEvent) -> Result<(), AlertError> {
        // Implementation would use lettre or similar SMTP library
        // For now, just log the alert
        tracing::info!(
            target: "email_alert",
            subject = %self.format_email_subject(event),
            body = %self.format_email_body(event),
            recipients = ?self.to_addresses,
            "Email alert would be sent"
        );
        Ok(())
    }

    fn get_name(&self) -> &str {
        "email"
    }
}

/// Slack alert handler using webhooks
pub struct SlackAlertHandler {
    webhook_url: String,
    channel: String,
    username: String,
}

impl SlackAlertHandler {
    pub fn new(webhook_url: String, channel: String, username: String) -> Self {
        Self {
            webhook_url,
            channel,
            username,
        }
    }

    fn format_slack_message(&self, event: &SecurityEvent) -> serde_json::Value {
        let color = match event.severity {
            crate::monitoring::security_alerts::AlertSeverity::Emergency => "danger",
            crate::monitoring::security_alerts::AlertSeverity::Critical => "danger",
            crate::monitoring::security_alerts::AlertSeverity::Warning => "warning",
            crate::monitoring::security_alerts::AlertSeverity::Info => "good",
        };

        let timestamp = chrono::DateTime::from_timestamp(event.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S UTC");

        json!({
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": ":warning:",
            "attachments": [{
                "color": color,
                "title": format!("Security Alert: {:?}", event.event_type),
                "fields": [
                    {
                        "title": "Severity",
                        "value": format!("{:?}", event.severity),
                        "short": true
                    },
                    {
                        "title": "Source IP",
                        "value": event.source_ip.map_or("N/A".to_string(), |ip| ip.to_string()),
                        "short": true
                    },
                    {
                        "title": "User ID",
                        "value": event.user_id.as_deref().unwrap_or("N/A"),
                        "short": true
                    },
                    {
                        "title": "Timestamp",
                        "value": timestamp.to_string(),
                        "short": true
                    },
                    {
                        "title": "Message",
                        "value": &event.message,
                        "short": false
                    }
                ],
                "footer": "Rust Security Platform",
                "ts": event.timestamp
            }]
        })
    }
}

#[async_trait]
impl AlertHandler for SlackAlertHandler {
    async fn send_alert(&self, event: &SecurityEvent) -> Result<(), AlertError> {
        let payload = self.format_slack_message(event);
        
        // Implementation would use reqwest to send to Slack webhook
        // For now, just log the alert
        tracing::info!(
            target: "slack_alert",
            webhook_url = %self.webhook_url,
            payload = %payload,
            "Slack alert would be sent"
        );
        Ok(())
    }

    fn get_name(&self) -> &str {
        "slack"
    }
}

/// PagerDuty alert handler for critical incidents
pub struct PagerDutyAlertHandler {
    integration_key: String,
    service_name: String,
}

impl PagerDutyAlertHandler {
    pub fn new(integration_key: String, service_name: String) -> Self {
        Self {
            integration_key,
            service_name,
        }
    }

    fn should_page(&self, event: &SecurityEvent) -> bool {
        matches!(
            event.severity,
            crate::monitoring::security_alerts::AlertSeverity::Critical |
            crate::monitoring::security_alerts::AlertSeverity::Emergency
        )
    }

    fn format_pagerduty_payload(&self, event: &SecurityEvent) -> serde_json::Value {
        json!({
            "routing_key": self.integration_key,
            "event_action": "trigger",
            "payload": {
                "summary": format!("{:?}: {}", event.event_type, event.message),
                "severity": match event.severity {
                    crate::monitoring::security_alerts::AlertSeverity::Emergency => "critical",
                    crate::monitoring::security_alerts::AlertSeverity::Critical => "critical",
                    crate::monitoring::security_alerts::AlertSeverity::Warning => "warning",
                    crate::monitoring::security_alerts::AlertSeverity::Info => "info",
                },
                "source": event.source_ip.map_or("unknown".to_string(), |ip| ip.to_string()),
                "component": self.service_name,
                "group": format!("{:?}", event.event_type),
                "class": "security",
                "custom_details": {
                    "event_type": format!("{:?}", event.event_type),
                    "user_id": event.user_id,
                    "session_id": event.session_id,
                    "user_agent": event.user_agent,
                    "endpoint": event.endpoint,
                    "metadata": event.metadata
                }
            }
        })
    }
}

#[async_trait]
impl AlertHandler for PagerDutyAlertHandler {
    async fn send_alert(&self, event: &SecurityEvent) -> Result<(), AlertError> {
        if !self.should_page(event) {
            return Ok(());
        }

        let payload = self.format_pagerduty_payload(event);
        
        // Implementation would use reqwest to send to PagerDuty Events API
        // For now, just log the alert
        tracing::info!(
            target: "pagerduty_alert",
            integration_key = %self.integration_key,
            payload = %payload,
            "PagerDuty alert would be sent"
        );
        Ok(())
    }

    fn get_name(&self) -> &str {
        "pagerduty"
    }
}

/// SIEM integration handler for security information and event management
pub struct SiemAlertHandler {
    siem_endpoint: String,
    api_key: String,
    organization_id: String,
}

impl SiemAlertHandler {
    pub fn new(siem_endpoint: String, api_key: String, organization_id: String) -> Self {
        Self {
            siem_endpoint,
            api_key,
            organization_id,
        }
    }

    fn format_siem_payload(&self, event: &SecurityEvent) -> serde_json::Value {
        json!({
            "timestamp": event.timestamp,
            "organization_id": self.organization_id,
            "event_type": "security_alert",
            "severity": format!("{:?}", event.severity).to_lowercase(),
            "category": format!("{:?}", event.event_type).to_lowercase(),
            "message": event.message,
            "source": {
                "ip": event.source_ip,
                "user_id": event.user_id,
                "session_id": event.session_id,
                "user_agent": event.user_agent
            },
            "destination": {
                "service": "rust-security-platform",
                "endpoint": event.endpoint
            },
            "metadata": event.metadata,
            "count": event.count,
            "tags": [
                "security",
                "authentication",
                "rust-security-platform"
            ]
        })
    }
}

#[async_trait]
impl AlertHandler for SiemAlertHandler {
    async fn send_alert(&self, event: &SecurityEvent) -> Result<(), AlertError> {
        let payload = self.format_siem_payload(event);
        
        // Implementation would use reqwest to send to SIEM endpoint
        // For now, just log the alert in structured format for collection
        tracing::info!(
            target: "siem_integration",
            siem_endpoint = %self.siem_endpoint,
            organization_id = %self.organization_id,
            event_data = %payload,
            "SIEM event would be sent"
        );
        Ok(())
    }

    fn get_name(&self) -> &str {
        "siem"
    }
}

/// Console/log alert handler for development and testing
pub struct ConsoleAlertHandler {
    include_metadata: bool,
}

impl ConsoleAlertHandler {
    pub fn new(include_metadata: bool) -> Self {
        Self { include_metadata }
    }
}

#[async_trait]
impl AlertHandler for ConsoleAlertHandler {
    async fn send_alert(&self, event: &SecurityEvent) -> Result<(), AlertError> {
        let timestamp = chrono::DateTime::from_timestamp(event.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S UTC");

        if self.include_metadata {
            tracing::warn!(
                target: "security_alert_console",
                event_type = ?event.event_type,
                severity = ?event.severity,
                timestamp = %timestamp,
                source_ip = ?event.source_ip,
                user_id = ?event.user_id,
                message = %event.message,
                metadata = ?event.metadata,
                "🚨 SECURITY ALERT: {} - {}",
                format!("{:?}", event.event_type),
                event.message
            );
        } else {
            tracing::warn!(
                "🚨 SECURITY ALERT [{:?}] {:?} from {:?}: {}",
                event.severity,
                event.event_type,
                event.source_ip.unwrap_or("unknown".parse().unwrap()),
                event.message
            );
        }

        Ok(())
    }

    fn get_name(&self) -> &str {
        "console"
    }
}

/// Factory for creating alert handlers from configuration
pub struct AlertHandlerFactory;

impl AlertHandlerFactory {
    pub fn create_handlers() -> Vec<Box<dyn AlertHandler + Send + Sync>> {
        let mut handlers: Vec<Box<dyn AlertHandler + Send + Sync>> = Vec::new();

        // Always add console handler for development
        handlers.push(Box::new(ConsoleAlertHandler::new(true)));

        // Add email handler if configured
        if let (Ok(smtp_server), Ok(username), Ok(password), Ok(from), Ok(to)) = (
            std::env::var("ALERT_SMTP_SERVER"),
            std::env::var("ALERT_SMTP_USERNAME"),
            std::env::var("ALERT_SMTP_PASSWORD"),
            std::env::var("ALERT_FROM_EMAIL"),
            std::env::var("ALERT_TO_EMAILS"),
        ) {
            let to_addresses: Vec<String> = to.split(',').map(|s| s.trim().to_string()).collect();
            let smtp_port = std::env::var("ALERT_SMTP_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse()
                .unwrap_or(587);

            handlers.push(Box::new(EmailAlertHandler::new(
                smtp_server,
                smtp_port,
                username,
                password,
                from,
                to_addresses,
            )));
        }

        // Add Slack handler if configured
        if let (Ok(webhook_url), Ok(channel)) = (
            std::env::var("ALERT_SLACK_WEBHOOK_URL"),
            std::env::var("ALERT_SLACK_CHANNEL"),
        ) {
            let username = std::env::var("ALERT_SLACK_USERNAME")
                .unwrap_or_else(|_| "Security Bot".to_string());

            handlers.push(Box::new(SlackAlertHandler::new(webhook_url, channel, username)));
        }

        // Add PagerDuty handler if configured
        if let (Ok(integration_key), Ok(service_name)) = (
            std::env::var("ALERT_PAGERDUTY_INTEGRATION_KEY"),
            std::env::var("ALERT_PAGERDUTY_SERVICE_NAME"),
        ) {
            handlers.push(Box::new(PagerDutyAlertHandler::new(integration_key, service_name)));
        }

        // Add SIEM handler if configured
        if let (Ok(siem_endpoint), Ok(api_key), Ok(org_id)) = (
            std::env::var("ALERT_SIEM_ENDPOINT"),
            std::env::var("ALERT_SIEM_API_KEY"),
            std::env::var("ALERT_SIEM_ORGANIZATION_ID"),
        ) {
            handlers.push(Box::new(SiemAlertHandler::new(siem_endpoint, api_key, org_id)));
        }

        handlers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::security_alerts::{SecurityEvent, SecurityEventType, AlertSeverity};
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_console_alert_handler() {
        let handler = ConsoleAlertHandler::new(true);
        
        let event = SecurityEvent {
            event_type: SecurityEventType::AuthenticationFailure,
            severity: AlertSeverity::Warning,
            timestamp: 1234567890,
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            user_id: Some("test_user".to_string()),
            session_id: None,
            user_agent: None,
            endpoint: None,
            message: "Test alert".to_string(),
            metadata: HashMap::new(),
            count: 1,
        };

        let result = handler.send_alert(&event).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_alert_handler_factory() {
        let handlers = AlertHandlerFactory::create_handlers();
        assert!(!handlers.is_empty());
        
        // Should always have at least the console handler
        assert!(handlers.iter().any(|h| h.get_name() == "console"));
    }
}