//! Case escalation policies and management
//!
//! This module handles case escalation based on time, severity, SLA breaches,
//! and other configurable triggers.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::security_monitoring::AlertSeverity;
use crate::soar::case_types::{CaseStatus, SecurityCase};

/// Case escalation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEscalationPolicy {
    /// Policy ID
    pub id: String,

    /// Policy name
    pub name: String,

    /// Policy description
    pub description: String,

    /// Policy priority
    pub priority: u32,

    /// Policy status
    pub enabled: bool,

    /// Escalation triggers
    pub triggers: Vec<EscalationTrigger>,

    /// Escalation levels
    pub escalation_levels: Vec<CaseEscalationLevel>,

    /// Maximum escalations
    pub max_escalations: u32,

    /// Cooldown period between escalations
    pub cooldown_minutes: u32,

    /// Policy metadata
    pub metadata: HashMap<String, serde_json::Value>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Escalation trigger conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationTrigger {
    /// Trigger ID
    pub id: String,

    /// Trigger name
    pub name: String,

    /// Trigger type
    pub trigger_type: EscalationTriggerType,

    /// Trigger conditions
    pub conditions: Vec<TriggerCondition>,

    /// Trigger weight (for prioritization)
    pub weight: f64,
}

/// Escalation trigger types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationTriggerType {
    /// Time-based escalation
    TimeBased(TimeBased),
    /// SLA breach escalation
    SlaBreach,
    /// Status-based escalation
    StatusBased,
    /// Severity-based escalation
    SeverityBased,
    /// Workload-based escalation
    WorkloadBased,
    /// Manual escalation
    Manual,
    /// Custom trigger
    Custom(String),
}

/// Time-based escalation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBased {
    /// Time threshold
    pub threshold_minutes: u32,

    /// Time reference point
    pub reference: TimeReference,

    /// Business hours only
    pub business_hours_only: bool,

    /// Timezone for calculation
    pub timezone: String,
}

/// Time reference points
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeReference {
    /// Case creation time
    CaseCreation,
    /// Last update time
    LastUpdate,
    /// Assignment time
    AssignmentTime,
    /// SLA deadline
    SlaDeadline,
    /// Custom reference
    Custom(String),
}

/// Trigger condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCondition {
    /// Condition ID
    pub id: String,

    /// Field to evaluate
    pub field: String,

    /// Comparison operator
    pub operator: String,

    /// Expected value
    pub value: serde_json::Value,

    /// Condition weight
    pub weight: f64,
}

/// Case escalation level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEscalationLevel {
    /// Level identifier
    pub level: u32,

    /// Level name
    pub name: String,

    /// Level description
    pub description: String,

    /// Time to escalate to this level (minutes)
    pub escalation_time_minutes: u32,

    /// Actions to take at this level
    pub actions: Vec<EscalationAction>,

    /// Notification settings
    pub notifications: Vec<EscalationNotification>,

    /// Auto-assignment rules
    pub auto_assignment: Option<EscalationAssignment>,

    /// Level metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Escalation action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationAction {
    /// Action ID
    pub id: String,

    /// Action type
    pub action_type: EscalationActionType,

    /// Action parameters
    pub parameters: HashMap<String, serde_json::Value>,

    /// Action timeout
    pub timeout_seconds: Option<u64>,

    /// Action retry configuration
    pub retry_config: Option<RetryConfig>,
}

/// Escalation action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationActionType {
    /// Reassign case
    Reassign,
    /// Change priority
    ChangePriority,
    /// Change severity
    ChangeSeverity,
    /// Add stakeholders
    AddStakeholders,
    /// Create incident
    CreateIncident,
    /// Trigger workflow
    TriggerWorkflow,
    /// Send alert
    SendAlert,
    /// Page on-call
    PageOnCall,
    /// Create ticket
    CreateTicket,
    /// Custom action
    Custom(String),
}

/// Retry configuration for actions
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

/// Escalation notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationNotification {
    /// Notification ID
    pub id: String,

    /// Notification type
    pub notification_type: NotificationType,

    /// Recipients
    pub recipients: Vec<NotificationRecipient>,

    /// Message template
    pub message_template: String,

    /// Notification channels
    pub channels: Vec<NotificationChannel>,

    /// Notification priority
    pub priority: NotificationPriority,
}

/// Notification types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    /// Escalation alert
    EscalationAlert,
    /// Status update
    StatusUpdate,
    /// Reminder
    Reminder,
    /// Emergency alert
    Emergency,
    /// Custom notification
    Custom(String),
}

/// Notification recipient
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecipient {
    /// Recipient ID
    pub id: String,

    /// Recipient type
    pub recipient_type: RecipientType,

    /// Notification preferences
    pub preferences: Option<RecipientPreferences>,
}

/// Recipient types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecipientType {
    /// Individual user
    User,
    /// Team
    Team,
    /// Role
    Role,
    /// Manager
    Manager,
    /// On-call person
    OnCall,
    /// Stakeholder group
    StakeholderGroup,
    /// External contact
    External,
}

/// Recipient preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientPreferences {
    /// Preferred channels
    pub preferred_channels: Vec<NotificationChannel>,

    /// Do not disturb hours
    pub dnd_hours: Option<DoNotDisturbHours>,

    /// Escalation delay (minutes)
    pub escalation_delay_minutes: u32,
}

/// Do not disturb hours
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoNotDisturbHours {
    /// Start time (24-hour format)
    pub start_time: String,

    /// End time (24-hour format)
    pub end_time: String,

    /// Days of week (0 = Sunday)
    pub days_of_week: Vec<u8>,

    /// Timezone
    pub timezone: String,
}

/// Notification channels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannel {
    /// Email
    Email,
    /// Slack
    Slack,
    /// Microsoft Teams
    Teams,
    /// SMS
    Sms,
    /// Phone call
    Phone,
    /// Push notification
    Push,
    /// Webhook
    Webhook,
    /// PagerDuty
    PagerDuty,
    /// Custom channel
    Custom(String),
}

/// Notification priority
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationPriority {
    /// Low priority
    Low,
    /// Normal priority
    Normal,
    /// High priority
    High,
    /// Critical priority
    Critical,
    /// Emergency priority
    Emergency,
}

/// Escalation assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationAssignment {
    /// Assignment type
    pub assignment_type: EscalationAssignmentType,

    /// Assignment parameters
    pub parameters: HashMap<String, serde_json::Value>,

    /// Assignment conditions
    pub conditions: Vec<TriggerCondition>,
}

/// Escalation assignment types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationAssignmentType {
    /// Assign to manager
    Manager,
    /// Assign to senior analyst
    SeniorAnalyst,
    /// Assign to team lead
    TeamLead,
    /// Assign to on-call
    OnCall,
    /// Assign to specific user
    SpecificUser(String),
    /// Assign to team
    Team(String),
    /// Custom assignment
    Custom(String),
}

/// Escalation state for a case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEscalationState {
    /// Case ID
    pub case_id: String,

    /// Current escalation level
    pub current_level: u32,

    /// Escalation policy ID
    pub policy_id: String,

    /// Escalation history
    pub escalation_history: Vec<EscalationEvent>,

    /// Next escalation time
    pub next_escalation_time: Option<DateTime<Utc>>,

    /// Escalation paused
    pub paused: bool,

    /// Pause reason
    pub pause_reason: Option<String>,

    /// Last updated
    pub last_updated: DateTime<Utc>,
}

/// Escalation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationEvent {
    /// Event ID
    pub id: String,

    /// Event type
    pub event_type: EscalationEventType,

    /// Escalation level
    pub level: u32,

    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    /// Event actor
    pub actor: String,

    /// Event description
    pub description: String,

    /// Event data
    pub data: Option<serde_json::Value>,
}

/// Escalation event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationEventType {
    /// Escalation triggered
    EscalationTriggered,
    /// Escalation executed
    EscalationExecuted,
    /// Escalation paused
    EscalationPaused,
    /// Escalation resumed
    EscalationResumed,
    /// Escalation cancelled
    EscalationCancelled,
    /// Escalation completed
    EscalationCompleted,
}

/// Escalation manager
pub struct EscalationManager {
    /// Escalation policies
    policies: HashMap<String, CaseEscalationPolicy>,

    /// Active escalations
    active_escalations: HashMap<String, CaseEscalationState>,

    /// Escalation history
    escalation_history: Vec<EscalationEvent>,
}

impl EscalationManager {
    /// Create new escalation manager
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            active_escalations: HashMap::new(),
            escalation_history: Vec::new(),
        }
    }

    /// Add escalation policy
    pub fn add_policy(&mut self, policy: CaseEscalationPolicy) {
        self.policies.insert(policy.id.clone(), policy);
    }

    /// Remove escalation policy
    pub fn remove_policy(&mut self, policy_id: &str) -> Option<CaseEscalationPolicy> {
        self.policies.remove(policy_id)
    }

    /// Start escalation for a case
    pub fn start_escalation(&mut self, case: &SecurityCase, policy_id: &str) -> Result<(), EscalationError> {
        if let Some(policy) = self.policies.get(policy_id) {
            if !policy.enabled {
                return Err(EscalationError::PolicyDisabled);
            }

            // Check if escalation already exists
            if self.active_escalations.contains_key(&case.id) {
                return Err(EscalationError::EscalationAlreadyActive);
            }

            // Create escalation state
            let escalation_state = CaseEscalationState {
                case_id: case.id.clone(),
                current_level: 0,
                policy_id: policy_id.to_string(),
                escalation_history: vec![],
                next_escalation_time: self.calculate_next_escalation_time(policy, 1),
                paused: false,
                pause_reason: None,
                last_updated: Utc::now(),
            };

            self.active_escalations.insert(case.id.clone(), escalation_state);

            // Record escalation start event
            let event = EscalationEvent {
                id: uuid::Uuid::new_v4().to_string(),
                event_type: EscalationEventType::EscalationTriggered,
                level: 0,
                timestamp: Utc::now(),
                actor: "system".to_string(),
                description: format!("Escalation started for case {} using policy {}", case.id, policy_id),
                data: None,
            };

            self.escalation_history.push(event);
            Ok(())
        } else {
            Err(EscalationError::PolicyNotFound)
        }
    }

    /// Process escalations (called periodically)
    pub fn process_escalations(&mut self) -> Vec<EscalationAction> {
        let mut actions_to_execute = Vec::new();
        let now = Utc::now();

        let mut escalations_to_update = Vec::new();

        for (case_id, escalation_state) in &self.active_escalations {
            if escalation_state.paused {
                continue;
            }

            if let Some(next_time) = escalation_state.next_escalation_time {
                if now >= next_time {
                    if let Some(policy) = self.policies.get(&escalation_state.policy_id) {
                        if let Some(level) = policy.escalation_levels.iter().find(|l| l.level == escalation_state.current_level + 1) {
                            // Execute escalation level
                            actions_to_execute.extend(level.actions.clone());

                            // Update escalation state
                            let mut updated_state = escalation_state.clone();
                            updated_state.current_level = level.level;
                            updated_state.next_escalation_time = self.calculate_next_escalation_time(policy, level.level + 1);
                            updated_state.last_updated = now;

                            // Add escalation event
                            let event = EscalationEvent {
                                id: uuid::Uuid::new_v4().to_string(),
                                event_type: EscalationEventType::EscalationExecuted,
                                level: level.level,
                                timestamp: now,
                                actor: "system".to_string(),
                                description: format!("Escalated case {} to level {}", case_id, level.level),
                                data: None,
                            };

                            updated_state.escalation_history.push(event.clone());
                            self.escalation_history.push(event);

                            escalations_to_update.push((case_id.clone(), updated_state));
                        }
                    }
                }
            }
        }

        // Update escalation states
        for (case_id, updated_state) in escalations_to_update {
            self.active_escalations.insert(case_id, updated_state);
        }

        actions_to_execute
    }

    /// Pause escalation for a case
    pub fn pause_escalation(&mut self, case_id: &str, reason: String) -> Result<(), EscalationError> {
        if let Some(escalation_state) = self.active_escalations.get_mut(case_id) {
            escalation_state.paused = true;
            escalation_state.pause_reason = Some(reason.clone());
            escalation_state.last_updated = Utc::now();

            // Record pause event
            let event = EscalationEvent {
                id: uuid::Uuid::new_v4().to_string(),
                event_type: EscalationEventType::EscalationPaused,
                level: escalation_state.current_level,
                timestamp: Utc::now(),
                actor: "system".to_string(),
                description: format!("Escalation paused for case {}: {}", case_id, reason),
                data: None,
            };

            escalation_state.escalation_history.push(event.clone());
            self.escalation_history.push(event);

            Ok(())
        } else {
            Err(EscalationError::EscalationNotFound)
        }
    }

    /// Resume escalation for a case
    pub fn resume_escalation(&mut self, case_id: &str) -> Result<(), EscalationError> {
        if let Some(escalation_state) = self.active_escalations.get_mut(case_id) {
            escalation_state.paused = false;
            escalation_state.pause_reason = None;
            escalation_state.last_updated = Utc::now();

            // Recalculate next escalation time
            if let Some(policy) = self.policies.get(&escalation_state.policy_id) {
                escalation_state.next_escalation_time = self.calculate_next_escalation_time(policy, escalation_state.current_level + 1);
            }

            // Record resume event
            let event = EscalationEvent {
                id: uuid::Uuid::new_v4().to_string(),
                event_type: EscalationEventType::EscalationResumed,
                level: escalation_state.current_level,
                timestamp: Utc::now(),
                actor: "system".to_string(),
                description: format!("Escalation resumed for case {}", case_id),
                data: None,
            };

            escalation_state.escalation_history.push(event.clone());
            self.escalation_history.push(event);

            Ok(())
        } else {
            Err(EscalationError::EscalationNotFound)
        }
    }

    /// Cancel escalation for a case
    pub fn cancel_escalation(&mut self, case_id: &str, reason: String) -> Result<(), EscalationError> {
        if let Some(mut escalation_state) = self.active_escalations.remove(case_id) {
            // Record cancellation event
            let event = EscalationEvent {
                id: uuid::Uuid::new_v4().to_string(),
                event_type: EscalationEventType::EscalationCancelled,
                level: escalation_state.current_level,
                timestamp: Utc::now(),
                actor: "system".to_string(),
                description: format!("Escalation cancelled for case {}: {}", case_id, reason),
                data: None,
            };

            escalation_state.escalation_history.push(event.clone());
            self.escalation_history.push(event);

            Ok(())
        } else {
            Err(EscalationError::EscalationNotFound)
        }
    }

    /// Calculate next escalation time
    fn calculate_next_escalation_time(&self, policy: &CaseEscalationPolicy, level: u32) -> Option<DateTime<Utc>> {
        if let Some(escalation_level) = policy.escalation_levels.iter().find(|l| l.level == level) {
            Some(Utc::now() + Duration::minutes(escalation_level.escalation_time_minutes as i64))
        } else {
            None
        }
    }

    /// Get escalation state for a case
    pub fn get_escalation_state(&self, case_id: &str) -> Option<&CaseEscalationState> {
        self.active_escalations.get(case_id)
    }

    /// List all active escalations
    pub fn list_active_escalations(&self) -> Vec<&CaseEscalationState> {
        self.active_escalations.values().collect()
    }
}

/// Escalation errors
#[derive(Debug, Clone)]
pub enum EscalationError {
    /// Policy not found
    PolicyNotFound,
    /// Policy is disabled
    PolicyDisabled,
    /// Escalation already active
    EscalationAlreadyActive,
    /// Escalation not found
    EscalationNotFound,
    /// Invalid escalation level
    InvalidLevel,
    /// Configuration error
    ConfigurationError(String),
}

impl std::fmt::Display for EscalationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EscalationError::PolicyNotFound => write!(f, "Escalation policy not found"),
            EscalationError::PolicyDisabled => write!(f, "Escalation policy is disabled"),
            EscalationError::EscalationAlreadyActive => write!(f, "Escalation already active for this case"),
            EscalationError::EscalationNotFound => write!(f, "Escalation not found for this case"),
            EscalationError::InvalidLevel => write!(f, "Invalid escalation level"),
            EscalationError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for EscalationError {}

impl Default for EscalationManager {
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
    fn test_escalation_manager() {
        let mut manager = EscalationManager::new();

        // Create escalation policy
        let policy = CaseEscalationPolicy {
            id: Uuid::new_v4().to_string(),
            name: "Standard Escalation".to_string(),
            description: "Standard escalation policy".to_string(),
            priority: 100,
            enabled: true,
            triggers: vec![],
            escalation_levels: vec![
                CaseEscalationLevel {
                    level: 1,
                    name: "Level 1".to_string(),
                    description: "First escalation level".to_string(),
                    escalation_time_minutes: 30,
                    actions: vec![],
                    notifications: vec![],
                    auto_assignment: None,
                    metadata: HashMap::new(),
                },
            ],
            max_escalations: 3,
            cooldown_minutes: 15,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let policy_id = policy.id.clone();
        manager.add_policy(policy);

        // Create test case
        let case = SecurityCase::new(
            "Test Case".to_string(),
            "Test Description".to_string(),
            AlertSeverity::High,
            vec![],
        );

        // Start escalation
        let result = manager.start_escalation(&case, &policy_id);
        assert!(operation_result.is_ok());

        // Check escalation state
        let state = manager.get_escalation_state(&case.id);
        assert!(state.is_some());
        assert_eq!(state.unwrap().current_level, 0);
    }
}
