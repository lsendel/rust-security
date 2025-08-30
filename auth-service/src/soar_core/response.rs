//! Response automation engine for executing automated security responses
//!
//! This module provides automated response capabilities that can react to
//! security alerts and execute predefined response actions.

use super::types::*;
use crate::security_monitoring::{AlertSeverity, SecurityAlert, SecurityAlertType};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Response automation engine
pub struct ResponseAutomationEngine {
    /// Auto-response rules
    auto_response_rules: Arc<RwLock<Vec<AutoResponseRule>>>,

    /// Response execution history
    response_history: Arc<DashMap<String, ResponseExecution>>,

    /// Cooldown tracking
    cooldown_tracker: Arc<DashMap<String, DateTime<Utc>>>,

    /// Configuration
    config: AutoResponseConfig,

    /// Metrics
    metrics: Arc<tokio::sync::Mutex<ResponseMetrics>>,
}

impl ResponseAutomationEngine {
    /// Create a new response automation engine
    pub async fn new(config: AutoResponseConfig) -> Result<Self, ResponseError> {
        Ok(Self {
            auto_response_rules: Arc::new(RwLock::new(Vec::new())),
            response_history: Arc::new(DashMap::new()),
            cooldown_tracker: Arc::new(DashMap::new()),
            config,
            metrics: Arc::new(tokio::sync::Mutex::new(ResponseMetrics::default())),
        })
    }

    /// Start the response automation engine
    pub async fn start(&self) -> Result<(), ResponseError> {
        info!("Starting response automation engine");

        // Start cleanup task for old history
        let engine_clone = self.clone();
        tokio::spawn(async move {
            engine_clone.cleanup_old_history().await;
        });

        info!("Response automation engine started successfully");
        Ok(())
    }

    /// Stop the response automation engine
    pub async fn stop(&self) -> Result<(), ResponseError> {
        info!("Stopping response automation engine");
        Ok(())
    }

    /// Trigger automatic response for an alert
    pub async fn trigger_auto_response(
        &self,
        alert: SecurityAlert,
    ) -> Result<Option<String>, ResponseError> {
        debug!("Evaluating auto-response for alert: {}", alert.id);

        if !self.config.enabled {
            debug!("Auto-response is disabled");
            return Ok(None);
        }

        // Check if alert meets auto-response criteria
        if !self.should_auto_respond(&alert).await? {
            debug!("Alert does not meet auto-response criteria");
            return Ok(None);
        }

        // Find matching auto-response rules
        let matching_rules = self.find_matching_rules(&alert).await?;

        if matching_rules.is_empty() {
            debug!("No matching auto-response rules found");
            return Ok(None);
        }

        // Execute the highest priority rule
        let rule = &matching_rules[0];
        let execution_id = self.execute_auto_response_rule(rule, &alert).await?;

        // Update metrics
        {
            let mut metrics = self.metrics.lock().await;
            metrics.total_responses_triggered += 1;
        }

        Ok(Some(execution_id))
    }

    /// Add auto-response rule
    pub async fn add_auto_response_rule(
        &self,
        rule: AutoResponseRule,
    ) -> Result<(), ResponseError> {
        let mut rules = self.auto_response_rules.write().await;
        rules.push(rule);
        info!("Added new auto-response rule");
        Ok(())
    }

    /// Remove auto-response rule
    pub async fn remove_auto_response_rule(&self, rule_id: &str) -> Result<bool, ResponseError> {
        let mut rules = self.auto_response_rules.write().await;
        let initial_len = rules.len();
        rules.retain(|rule| rule.id != rule_id);
        Ok(rules.len() < initial_len)
    }

    /// Get response execution history
    pub async fn get_response_history(&self) -> Vec<ResponseExecution> {
        self.response_history
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get response metrics
    pub async fn get_metrics(&self) -> ResponseMetrics {
        self.metrics.lock().await.clone()
    }

    /// Check if alert should trigger auto-response
    async fn should_auto_respond(&self, alert: &SecurityAlert) -> Result<bool, ResponseError> {
        // Check severity threshold
        if alert.severity < self.config.severity_threshold {
            return Ok(false);
        }

        // Check allowed threat types
        if !self.config.allowed_threat_types.is_empty()
            && !self.config.allowed_threat_types.contains(&alert.alert_type)
        {
            return Ok(false);
        }

        // Check cooldown
        let cooldown_key = self.generate_cooldown_key(alert);
        if let Some(last_response) = self.cooldown_tracker.get(&cooldown_key) {
            let cooldown_duration = chrono::Duration::minutes(self.config.cooldown_minutes as i64);
            if Utc::now() - *last_response < cooldown_duration {
                debug!("Auto-response in cooldown period");
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Find matching auto-response rules for an alert
    async fn find_matching_rules(
        &self,
        alert: &SecurityAlert,
    ) -> Result<Vec<AutoResponseRule>, ResponseError> {
        let rules = self.auto_response_rules.read().await;
        let mut matching_rules = Vec::new();

        for rule in rules.iter() {
            if self.rule_matches_alert(rule, alert).await? {
                // Check execution limits
                if self.check_execution_limits(rule, alert).await? {
                    matching_rules.push(rule.clone());
                }
            }
        }

        // Sort by priority (higher priority first)
        matching_rules.sort_by(|a, b| b.confidence_threshold.cmp(&a.confidence_threshold));

        Ok(matching_rules)
    }

    /// Check if a rule matches an alert
    async fn rule_matches_alert(
        &self,
        rule: &AutoResponseRule,
        alert: &SecurityAlert,
    ) -> Result<bool, ResponseError> {
        for condition in &rule.conditions {
            if !self.evaluate_trigger_condition(condition, alert).await {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Evaluate a trigger condition against an alert
    async fn evaluate_trigger_condition(
        &self,
        condition: &TriggerCondition,
        alert: &SecurityAlert,
    ) -> bool {
        let field_value = self.get_alert_field_value(alert, &condition.field);

        match &condition.operator {
            ConditionOperator::Equals => {
                field_value.map(|v| serde_json::Value::String(v.to_string()))
                    == Some(condition.value.clone())
            }
            ConditionOperator::NotEquals => {
                field_value.map(|v| serde_json::Value::String(v.to_string()))
                    != Some(condition.value.clone())
            }
            ConditionOperator::Contains => {
                if let (Some(field_val), Some(search_val)) = (field_value, condition.value.as_str())
                {
                    field_val.contains(search_val)
                } else {
                    false
                }
            }
            ConditionOperator::GreaterThan => {
                if let (Some(field_val), Some(threshold)) = (
                    field_value.and_then(|v| v.parse::<f64>().ok()),
                    condition.value.as_f64(),
                ) {
                    field_val > threshold
                } else {
                    false
                }
            }
            ConditionOperator::In => {
                if let (Some(field_val), Some(values)) = (field_value, condition.value.as_array()) {
                    values.iter().any(|v| v.as_str() == Some(field_val))
                } else {
                    false
                }
            }
            _ => {
                warn!("Unsupported condition operator: {:?}", condition.operator);
                true
            }
        }
    }

    /// Get field value from alert
    fn get_alert_field_value(&self, alert: &SecurityAlert, field: &str) -> Option<String> {
        match field {
            "id" => Some(alert.id.clone()),
            "title" => Some(alert.title.clone()),
            "description" => Some(alert.description.clone()),
            "severity" => Some(format!("{:?}", alert.severity)),
            "alert_type" => Some(format!("{:?}", alert.alert_type)),
            "source_ip" => alert.source_ip.clone(),
            "destination_ip" => alert.destination_ip.clone(),
            "user_id" => alert.user_id.clone(),
            "source" => Some(alert.source.clone()),
            _ => {
                // Check metadata for custom fields
                alert
                    .metadata
                    .get(field)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            }
        }
    }

    /// Check execution limits for a rule
    async fn check_execution_limits(
        &self,
        rule: &AutoResponseRule,
        alert: &SecurityAlert,
    ) -> Result<bool, ResponseError> {
        let time_window = chrono::Duration::minutes(rule.time_window_minutes as i64);
        let window_start = Utc::now() - time_window;

        // Count executions in time window
        let execution_count = self
            .response_history
            .iter()
            .filter(|entry| {
                let execution = entry.value();
                execution.rule_id == rule.id && execution.executed_at >= window_start
            })
            .count();

        Ok(execution_count < rule.max_executions_per_window as usize)
    }

    /// Execute an auto-response rule
    async fn execute_auto_response_rule(
        &self,
        rule: &AutoResponseRule,
        alert: &SecurityAlert,
    ) -> Result<String, ResponseError> {
        let execution_id = Uuid::new_v4().to_string();

        info!(
            "Executing auto-response rule: {} for alert: {}",
            rule.name, alert.id
        );

        // Create execution record
        let execution = ResponseExecution {
            id: execution_id.clone(),
            rule_id: rule.id.clone(),
            workflow_instance_id: String::new(), // Will be updated when workflow starts
            executed_at: Utc::now(),
            input_data: serde_json::to_value(alert)
                .map_err(|e| ResponseError::SerializationError(e.to_string()))?,
            result: ExecutionResult::Pending,
        };

        self.response_history
            .insert(execution_id.clone(), execution);

        // Update cooldown tracker
        let cooldown_key = self.generate_cooldown_key(alert);
        self.cooldown_tracker.insert(cooldown_key, Utc::now());

        // Execute the response (this would typically trigger a workflow)
        match self.execute_response_actions(rule, alert).await {
            Ok(outputs) => {
                // Update execution result
                if let Some(mut execution) = self.response_history.get_mut(&execution_id) {
                    execution.result = ExecutionResult::Success { outputs };
                }

                // Update metrics
                {
                    let mut metrics = self.metrics.lock().await;
                    metrics.successful_responses += 1;
                }
            }
            Err(error) => {
                // Update execution result
                if let Some(mut execution) = self.response_history.get_mut(&execution_id) {
                    execution.result = ExecutionResult::Failure {
                        error: error.to_string(),
                        details: None,
                    };
                }

                // Update metrics
                {
                    let mut metrics = self.metrics.lock().await;
                    metrics.failed_responses += 1;
                }

                return Err(error);
            }
        }

        Ok(execution_id)
    }

    /// Execute response actions
    async fn execute_response_actions(
        &self,
        rule: &AutoResponseRule,
        alert: &SecurityAlert,
    ) -> Result<HashMap<String, serde_json::Value>, ResponseError> {
        let mut outputs = HashMap::new();

        // This is a simplified implementation
        // In a real system, this would trigger workflow execution

        debug!("Executing response actions for rule: {}", rule.name);

        // Simulate response actions based on alert type
        match alert.alert_type {
            SecurityAlertType::SuspiciousLogin => {
                outputs.insert(
                    "action_taken".to_string(),
                    serde_json::Value::String("User account locked".to_string()),
                );
                outputs.insert(
                    "duration_minutes".to_string(),
                    serde_json::Value::Number(30.into()),
                );
            }
            SecurityAlertType::MalwareDetected => {
                outputs.insert(
                    "action_taken".to_string(),
                    serde_json::Value::String("IP address blocked".to_string()),
                );
                outputs.insert(
                    "quarantine_applied".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
            SecurityAlertType::DataExfiltration => {
                outputs.insert(
                    "action_taken".to_string(),
                    serde_json::Value::String("Network access restricted".to_string()),
                );
                outputs.insert(
                    "incident_created".to_string(),
                    serde_json::Value::Bool(true),
                );
            }
            _ => {
                outputs.insert(
                    "action_taken".to_string(),
                    serde_json::Value::String("Alert escalated".to_string()),
                );
            }
        }

        outputs.insert(
            "execution_time".to_string(),
            serde_json::Value::String(Utc::now().to_rfc3339()),
        );
        outputs.insert(
            "rule_id".to_string(),
            serde_json::Value::String(rule.id.clone()),
        );

        Ok(outputs)
    }

    /// Generate cooldown key for an alert
    fn generate_cooldown_key(&self, alert: &SecurityAlert) -> String {
        format!(
            "{}_{:?}_{}",
            alert.source_ip.as_deref().unwrap_or("unknown"),
            alert.alert_type,
            alert.user_id.as_deref().unwrap_or("unknown")
        )
    }

    /// Clean up old response history
    async fn cleanup_old_history(&self) {
        let cleanup_interval = tokio::time::Duration::from_secs(3600); // 1 hour
        let mut interval = tokio::time::interval(cleanup_interval);

        loop {
            interval.tick().await;

            let cutoff_time = Utc::now() - chrono::Duration::days(30); // Keep 30 days of history

            // Remove old executions
            let mut removed_count = 0;
            self.response_history.retain(|_, execution| {
                if execution.executed_at < cutoff_time {
                    removed_count += 1;
                    false
                } else {
                    true
                }
            });

            // Clean up old cooldown entries
            let cooldown_cutoff = Utc::now() - chrono::Duration::hours(24);
            self.cooldown_tracker
                .retain(|_, timestamp| *timestamp > cooldown_cutoff);

            if removed_count > 0 {
                debug!("Cleaned up {} old response executions", removed_count);
            }
        }
    }
}

impl Clone for ResponseAutomationEngine {
    fn clone(&self) -> Self {
        Self {
            auto_response_rules: Arc::clone(&self.auto_response_rules),
            response_history: Arc::clone(&self.response_history),
            cooldown_tracker: Arc::clone(&self.cooldown_tracker),
            config: self.config.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

/// Response automation metrics
#[derive(Debug, Clone, Default)]
pub struct ResponseMetrics {
    pub total_responses_triggered: u64,
    pub successful_responses: u64,
    pub failed_responses: u64,
    pub average_response_time_ms: f64,
    pub responses_by_type: HashMap<String, u64>,
}

/// Response automation error types
#[derive(Debug, thiserror::Error)]
pub enum ResponseError {
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Rule evaluation error: {0}")]
    RuleEvaluationError(String),

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Cooldown violation: {0}")]
    CooldownViolation(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Response action trait for extensible response actions
#[async_trait::async_trait]
pub trait ResponseAction {
    async fn execute(
        &self,
        alert: &SecurityAlert,
        parameters: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, ResponseError>;

    fn get_action_type(&self) -> String;
}

// Missing type definitions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ExecutionResult {
    Pending,
    Success {
        outputs: std::collections::HashMap<String, serde_json::Value>,
    },
    Failure {
        error: String,
        details: Option<String>,
    },
    Timeout,
    Cancelled,
}
