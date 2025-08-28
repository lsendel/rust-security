//! Case automation rules and actions
//!
//! This module handles automated case processing including rule evaluation,
//! action execution, and workflow integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::security_monitoring::AlertSeverity;
use crate::soar::case_types::{CaseStatus, SecurityCase};

/// Case automation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseAutomationRule {
    /// Rule ID
    pub id: String,

    /// Rule name
    pub name: String,

    /// Rule description
    pub description: String,

    /// Rule priority (higher = executed first)
    pub priority: u32,

    /// Rule status
    pub enabled: bool,

    /// Trigger conditions
    pub conditions: Vec<TriggerCondition>,

    /// Actions to execute
    pub actions: Vec<AutomationAction>,

    /// Rule metadata
    pub metadata: HashMap<String, serde_json::Value>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,

    /// Rule creator
    pub created_by: String,
}

/// Trigger condition for automation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCondition {
    /// Condition ID
    pub id: String,

    /// Field to evaluate
    pub field: String,

    /// Comparison operator
    pub operator: ComparisonOperator,

    /// Expected value
    pub value: serde_json::Value,

    /// Logical operator with next condition
    pub logical_operator: Option<LogicalOperator>,
}

/// Comparison operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    /// Equal to
    Equals,
    /// Not equal to
    NotEquals,
    /// Greater than
    GreaterThan,
    /// Greater than or equal
    GreaterThanOrEqual,
    /// Less than
    LessThan,
    /// Less than or equal
    LessThanOrEqual,
    /// Contains (for strings/arrays)
    Contains,
    /// Does not contain
    NotContains,
    /// Starts with
    StartsWith,
    /// Ends with
    EndsWith,
    /// Matches regex pattern
    Matches,
    /// In list
    In,
    /// Not in list
    NotIn,
    /// Is null/empty
    IsNull,
    /// Is not null/empty
    IsNotNull,
}

/// Logical operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogicalOperator {
    /// AND condition
    And,
    /// OR condition
    Or,
}

/// Automation action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationAction {
    /// Action ID
    pub id: String,

    /// Action type
    pub action_type: AutomationActionType,

    /// Action parameters
    pub parameters: HashMap<String, serde_json::Value>,

    /// Action timeout (seconds)
    pub timeout_seconds: Option<u64>,

    /// Retry configuration
    pub retry_config: Option<RetryConfig>,

    /// Action conditions (additional checks)
    pub conditions: Vec<TriggerCondition>,
}

/// Automation action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutomationActionType {
    /// Assign case to user/team
    AssignToUser,
    /// Assign to team
    AssignToTeam,
    /// Set case priority
    SetPriority,
    /// Add tag to case
    AddTag,
    /// Remove tag from case
    RemoveTag,
    /// Trigger workflow
    TriggerWorkflow,
    /// Send notification
    SendNotification,
    /// Escalate case
    EscalateCase,
    /// Collect evidence
    CollectEvidence,
    /// Update case status
    UpdateStatus,
    /// Create sub-case
    CreateSubCase,
    /// Merge with existing case
    MergeWithCase,
    /// Add comment
    AddComment,
    /// Set custom field
    SetCustomField,
    /// Execute webhook
    ExecuteWebhook,
    /// Custom action
    Custom(String),
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,

    /// Delay between retries (seconds)
    pub delay_seconds: u64,

    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,

    /// Maximum delay (seconds)
    pub max_delay_seconds: u64,
}

/// Rule evaluation context
#[derive(Debug, Clone)]
pub struct RuleContext {
    /// Case being evaluated
    pub case: SecurityCase,

    /// Additional context data
    pub context_data: HashMap<String, serde_json::Value>,

    /// Evaluation timestamp
    pub timestamp: DateTime<Utc>,

    /// Evaluating user
    pub user: String,
}

/// Rule evaluation result
#[derive(Debug, Clone)]
pub struct RuleEvaluationResult {
    /// Rule ID
    pub rule_id: String,

    /// Whether rule conditions matched
    pub matched: bool,

    /// Actions to execute
    pub actions: Vec<AutomationAction>,

    /// Evaluation details
    pub details: Vec<ConditionResult>,

    /// Evaluation timestamp
    pub evaluated_at: DateTime<Utc>,
}

/// Condition evaluation result
#[derive(Debug, Clone)]
pub struct ConditionResult {
    /// Condition ID
    pub condition_id: String,

    /// Whether condition passed
    pub passed: bool,

    /// Actual value found
    pub actual_value: serde_json::Value,

    /// Expected value
    pub expected_value: serde_json::Value,

    /// Evaluation message
    pub message: String,
}

/// Action execution result
#[derive(Debug, Clone)]
pub struct ActionExecutionResult {
    /// Action ID
    pub action_id: String,

    /// Execution success
    pub success: bool,

    /// Result data
    pub result_data: Option<serde_json::Value>,

    /// Error message (if failed)
    pub error_message: Option<String>,

    /// Execution duration (milliseconds)
    pub duration_ms: u64,

    /// Execution timestamp
    pub executed_at: DateTime<Utc>,
}

/// Automation engine
pub struct AutomationEngine {
    /// Active rules
    rules: Vec<CaseAutomationRule>,

    /// Rule execution history
    execution_history: Vec<RuleExecutionRecord>,
}

/// Rule execution record
#[derive(Debug, Clone)]
pub struct RuleExecutionRecord {
    /// Execution ID
    pub id: String,

    /// Rule ID
    pub rule_id: String,

    /// Case ID
    pub case_id: String,

    /// Execution result
    pub result: RuleEvaluationResult,

    /// Action results
    pub action_results: Vec<ActionExecutionResult>,

    /// Execution timestamp
    pub executed_at: DateTime<Utc>,
}

impl AutomationEngine {
    /// Create new automation engine
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            execution_history: Vec::new(),
        }
    }

    /// Add automation rule
    pub fn add_rule(&mut self, rule: CaseAutomationRule) {
        // Insert rule in priority order (higher priority first)
        let insert_pos = self
            .rules
            .iter()
            .position(|r| r.priority < rule.priority)
            .unwrap_or(self.rules.len());
        
        self.rules.insert(insert_pos, rule);
    }

    /// Remove automation rule
    pub fn remove_rule(&mut self, rule_id: &str) -> Option<CaseAutomationRule> {
        if let Some(pos) = self.rules.iter().position(|r| r.id == rule_id) {
            Some(self.rules.remove(pos))
        } else {
            None
        }
    }

    /// Evaluate rules for a case
    pub fn evaluate_rules(&self, context: &RuleContext) -> Vec<RuleEvaluationResult> {
        let mut results = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let result = self.evaluate_rule(rule, context);
            results.push(result);
        }

        results
    }

    /// Evaluate a single rule
    fn evaluate_rule(&self, rule: &CaseAutomationRule, context: &RuleContext) -> RuleEvaluationResult {
        let mut condition_results = Vec::new();
        let mut overall_match = true;

        for condition in &rule.conditions {
            let result = self.evaluate_condition(condition, context);
            let passed = operation_result.passed;
            condition_results.push(result);

            // Apply logical operators
            if let Some(logical_op) = &condition.logical_operator {
                match logical_op {
                    LogicalOperator::And => {
                        overall_match = overall_match && passed;
                    }
                    LogicalOperator::Or => {
                        overall_match = overall_match || passed;
                    }
                }
            } else {
                overall_match = overall_match && passed;
            }
        }

        let actions = if overall_match {
            rule.actions.clone()
        } else {
            Vec::new()
        };

        RuleEvaluationResult {
            rule_id: rule.id.clone(),
            matched: overall_match,
            actions,
            details: condition_results,
            evaluated_at: Utc::now(),
        }
    }

    /// Evaluate a single condition
    fn evaluate_condition(&self, condition: &TriggerCondition, context: &RuleContext) -> ConditionResult {
        let actual_value = self.extract_field_value(&condition.field, context);
        let expected_value = condition.value.clone();

        let passed = self.compare_values(&actual_value, &condition.operator, &expected_value);

        ConditionResult {
            condition_id: condition.id.clone(),
            passed,
            actual_value,
            expected_value,
            message: format!(
                "Field '{}' {} expected value",
                condition.field,
                if passed { "matches" } else { "does not match" }
            ),
        }
    }

    /// Extract field value from context
    fn extract_field_value(&self, field_path: &str, context: &RuleContext) -> serde_json::Value {
        // Handle nested field paths like "case.severity" or "context.alert_count"
        let parts: Vec<&str> = field_path.split('.').collect();
        
        match parts.get(0) {
            Some(&"case") => {
                self.extract_case_field(&parts[1..], &context.case)
            }
            Some(&"context") => {
                self.extract_context_field(&parts[1..], &context.context_data)
            }
            _ => serde_json::Value::Null,
        }
    }

    /// Extract field from case object
    fn extract_case_field(&self, field_path: &[&str], case: &SecurityCase) -> serde_json::Value {
        match field_path.get(0) {
            Some(&"severity") => serde_json::to_value(&case.severity).unwrap_or(serde_json::Value::Null),
            Some(&"status") => serde_json::to_value(&case.status).unwrap_or(serde_json::Value::Null),
            Some(&"assignee") => serde_json::to_value(&case.assignee).unwrap_or(serde_json::Value::Null),
            Some(&"tags") => serde_json::to_value(&case.tags).unwrap_or(serde_json::Value::Null),
            Some(&"age_hours") => serde_json::Value::Number(
                serde_json::Number::from_f64(case.age_hours()).unwrap_or(serde_json::Number::from(0))
            ),
            Some(&"evidence_count") => serde_json::Value::Number(
                serde_json::Number::from(case.evidence.len())
            ),
            Some(field) => {
                // Check custom fields
                case.custom_fields.get(*field).cloned().unwrap_or(serde_json::Value::Null)
            }
            None => serde_json::Value::Null,
        }
    }

    /// Extract field from context data
    fn extract_context_field(&self, field_path: &[&str], context_data: &HashMap<String, serde_json::Value>) -> serde_json::Value {
        if let Some(field_name) = field_path.get(0) {
            context_data.get(*field_name).cloned().unwrap_or(serde_json::Value::Null)
        } else {
            serde_json::Value::Null
        }
    }

    /// Compare values using operator
    fn compare_values(&self, actual: &serde_json::Value, operator: &ComparisonOperator, expected: &serde_json::Value) -> bool {
        match operator {
            ComparisonOperator::Equals => actual == expected,
            ComparisonOperator::NotEquals => actual != expected,
            ComparisonOperator::GreaterThan => {
                self.numeric_compare(actual, expected, |a, b| a > b)
            }
            ComparisonOperator::GreaterThanOrEqual => {
                self.numeric_compare(actual, expected, |a, b| a >= b)
            }
            ComparisonOperator::LessThan => {
                self.numeric_compare(actual, expected, |a, b| a < b)
            }
            ComparisonOperator::LessThanOrEqual => {
                self.numeric_compare(actual, expected, |a, b| a <= b)
            }
            ComparisonOperator::Contains => {
                self.string_contains(actual, expected)
            }
            ComparisonOperator::NotContains => {
                !self.string_contains(actual, expected)
            }
            ComparisonOperator::StartsWith => {
                self.string_starts_with(actual, expected)
            }
            ComparisonOperator::EndsWith => {
                self.string_ends_with(actual, expected)
            }
            ComparisonOperator::In => {
                if let serde_json::Value::Array(arr) = expected {
                    arr.contains(actual)
                } else {
                    false
                }
            }
            ComparisonOperator::NotIn => {
                if let serde_json::Value::Array(arr) = expected {
                    !arr.contains(actual)
                } else {
                    true
                }
            }
            ComparisonOperator::IsNull => {
                actual.is_null()
            }
            ComparisonOperator::IsNotNull => {
                !actual.is_null()
            }
            ComparisonOperator::Matches => {
                // TODO: Implement regex matching
                false
            }
        }
    }

    /// Numeric comparison helper
    fn numeric_compare<F>(&self, actual: &serde_json::Value, expected: &serde_json::Value, compare_fn: F) -> bool
    where
        F: Fn(f64, f64) -> bool,
    {
        match (actual.as_f64(), expected.as_f64()) {
            (Some(a), Some(b)) => compare_fn(a, b),
            _ => false,
        }
    }

    /// String contains helper
    fn string_contains(&self, actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
        match (actual.as_str(), expected.as_str()) {
            (Some(a), Some(b)) => a.contains(b),
            _ => false,
        }
    }

    /// String starts with helper
    fn string_starts_with(&self, actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
        match (actual.as_str(), expected.as_str()) {
            (Some(a), Some(b)) => a.starts_with(b),
            _ => false,
        }
    }

    /// String ends with helper
    fn string_ends_with(&self, actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
        match (actual.as_str(), expected.as_str()) {
            (Some(a), Some(b)) => a.ends_with(b),
            _ => false,
        }
    }
}

impl Default for AutomationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soar::case_types::*;
    use uuid::Uuid;

    #[test]
    fn test_automation_rule_evaluation() {
        let mut engine = AutomationEngine::new();

        // Create a rule that triggers on high severity cases
        let rule = CaseAutomationRule {
            id: Uuid::new_v4().to_string(),
            name: "High Severity Auto-Assignment".to_string(),
            description: "Auto-assign high severity cases".to_string(),
            priority: 100,
            enabled: true,
            conditions: vec![TriggerCondition {
                id: Uuid::new_v4().to_string(),
                field: "case.severity".to_string(),
                operator: ComparisonOperator::Equals,
                value: serde_json::to_value(AlertSeverity::High).unwrap(),
                logical_operator: None,
            }],
            actions: vec![AutomationAction {
                id: Uuid::new_v4().to_string(),
                action_type: AutomationActionType::AssignToUser,
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("user_id".to_string(), serde_json::Value::String("senior_analyst".to_string()));
                    params
                },
                timeout_seconds: Some(30),
                retry_config: None,
                conditions: vec![],
            }],
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "system".to_string(),
        };

        engine.add_rule(rule);

        // Create a high severity case
        let case = SecurityCase::new(
            "Test Case".to_string(),
            "Test Description".to_string(),
            AlertSeverity::High,
            vec![],
        );

        let context = RuleContext {
            case,
            context_data: HashMap::new(),
            timestamp: Utc::now(),
            user: "system".to_string(),
        };

        let results = engine.evaluate_rules(&context);
        assert_eq!(results.len(), 1);
        assert!(results[0].matched);
        assert_eq!(results[0].actions.len(), 1);
    }

    #[test]
    fn test_condition_evaluation() {
        let engine = AutomationEngine::new();

        let case = SecurityCase::new(
            "Test Case".to_string(),
            "Test Description".to_string(),
            AlertSeverity::Medium,
            vec![],
        );

        let context = RuleContext {
            case,
            context_data: HashMap::new(),
            timestamp: Utc::now(),
            user: "system".to_string(),
        };

        let condition = TriggerCondition {
            id: Uuid::new_v4().to_string(),
            field: "case.severity".to_string(),
            operator: ComparisonOperator::Equals,
            value: serde_json::to_value(AlertSeverity::Medium).unwrap(),
            logical_operator: None,
        };

        let result = engine.evaluate_condition(&condition, &context);
        assert!(operation_result.passed);
    }
}
