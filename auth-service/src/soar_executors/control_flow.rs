//! Control Flow Executors
//!
//! This module provides executors for workflow control flow operations
//! including decision making and wait operations.

use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};
use crate::soar_core::{StepAction, StepError, StepExecutor, WorkflowStep};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{info, instrument};

/// Decision step executor for conditional workflow branching
pub struct DecisionExecutor;

impl DecisionExecutor {
    pub fn new() -> Self {
        Self
    }

    fn evaluate_condition(
        &self,
        condition: &str,
        context: &HashMap<String, Value>,
    ) -> Result<bool, StepError> {
        // Simple condition evaluation
        // In a production system, this would use a proper expression evaluator

        // Handle simple boolean conditions
        if let Some(value) = context.get(condition) {
            return Ok(value.as_bool().unwrap_or(false));
        }

        // Handle simple comparisons (key=value, key>value, etc.)
        if condition.contains('=') {
            let parts: Vec<&str> = condition.split('=').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let expected_value = parts[1].trim();

                if let Some(actual_value) = context.get(key) {
                    let actual_str = match actual_value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => actual_value.to_string(),
                    };
                    return Ok(actual_str == expected_value);
                }
            }
        }

        // Default to false for unknown conditions
        Ok(false)
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
        info!("Executing decision step: {}", step.name);

        // For decision steps, we evaluate conditions from the step inputs
        let condition = step
            .inputs
            .get("condition")
            .and_then(|v| v.as_str())
            .ok_or_else(|| StepError {
                code: "MISSING_CONDITION".to_string(),
                message: "Decision step requires a 'condition' input".to_string(),
                details: None,
                retryable: false,
            })?;

        let result = self.evaluate_condition(condition, context)?;

        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::AdminAction,
                SecuritySeverity::Low,
                "soar_executor".to_string(),
                format!("Decision step evaluated: {} = {}", condition, result),
            )
            .with_actor("soar_system".to_string())
            .with_action("soar_execute".to_string())
            .with_target("soar_playbook".to_string())
            .with_outcome("success".to_string())
            .with_reason("Decision step executed successfully".to_string())
            .with_detail("condition".to_string(), condition.to_string())
            .with_detail("result".to_string(), result),
        );

        let mut outputs = HashMap::new();
        outputs.insert("decision_result".to_string(), Value::Bool(result));
        outputs.insert(
            "condition".to_string(),
            Value::String(condition.to_string()),
        );

        // Add branch information
        if result {
            outputs.insert("branch".to_string(), Value::String("true".to_string()));
        } else {
            outputs.insert("branch".to_string(), Value::String("false".to_string()));
        }

        Ok(outputs)
    }

    fn get_step_type(&self) -> String {
        "decision".to_string()
    }
}

/// Wait step executor for introducing delays in workflows
pub struct WaitExecutor;

impl WaitExecutor {
    pub fn new() -> Self {
        Self
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
        // Get wait duration from step inputs
        let duration_seconds = step
            .inputs
            .get("duration_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(1); // Default to 1 second

        // Limit maximum wait time for security
        let max_wait_seconds = 3600; // 1 hour maximum
        let actual_duration = duration_seconds.min(max_wait_seconds);

        info!(
            "Executing wait step: {} seconds (requested: {})",
            actual_duration, duration_seconds
        );

        let start_time = std::time::Instant::now();

        // Perform the wait
        tokio::time::sleep(Duration::from_secs(actual_duration)).await;

        let elapsed = start_time.elapsed();

        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::AdminAction,
                SecuritySeverity::Low,
                "soar_executor".to_string(),
                format!("Wait step completed: {} seconds", actual_duration),
            )
            .with_actor("soar_system".to_string())
            .with_action("soar_execute".to_string())
            .with_target("soar_playbook".to_string())
            .with_outcome("success".to_string())
            .with_reason("Wait step executed successfully".to_string())
            .with_detail("duration_seconds".to_string(), actual_duration)
            .with_detail("elapsed_ms".to_string(), elapsed.as_millis() as u64),
        );

        let mut outputs = HashMap::new();
        outputs.insert(
            "duration_seconds".to_string(),
            Value::Number(actual_duration.into()),
        );
        outputs.insert(
            "elapsed_ms".to_string(),
            Value::Number((elapsed.as_millis() as u64).into()),
        );

        if duration_seconds > max_wait_seconds {
            outputs.insert(
                "warning".to_string(),
                Value::String(format!(
                    "Requested duration {} seconds was capped to {} seconds",
                    duration_seconds, max_wait_seconds
                )),
            );
        }

        Ok(outputs)
    }

    fn get_step_type(&self) -> String {
        "wait".to_string()
    }
}

impl Default for DecisionExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for WaitExecutor {
    fn default() -> Self {
        Self::new()
    }
}
