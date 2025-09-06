//! Workflow Scheduler

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Workflow scheduler for time-based execution
pub struct WorkflowScheduler {
    /// Scheduled workflows
    scheduled_workflows: Arc<RwLock<HashMap<String, ScheduledWorkflow>>>,

    /// Execution queue
    execution_queue: Arc<RwLock<VecDeque<ScheduledWorkflow>>>,

    /// Scheduler configuration
    config: Arc<RwLock<SchedulerConfig>>,
}

impl WorkflowScheduler {
    /// Create a new workflow scheduler
    #[must_use]
    pub fn new() -> Self {
        Self {
            scheduled_workflows: Arc::new(RwLock::new(HashMap::new())),
            execution_queue: Arc::new(RwLock::new(VecDeque::new())),
            config: Arc::new(RwLock::new(SchedulerConfig::default())),
        }
    }

    /// Schedule a workflow for future execution
    pub async fn schedule_workflow(
        &self,
        workflow: super::types::WorkflowDefinition,
        execution_time: DateTime<Utc>,
        recurrence: Option<RecurrencePattern>,
    ) -> Result<String, String> {
        let schedule_id = uuid::Uuid::new_v4().to_string();
        let scheduled = ScheduledWorkflow {
            id: schedule_id.clone(),
            workflow,
            scheduled_time: execution_time,
            recurrence,
            status: ScheduleStatus::Active,
            created_at: Utc::now(),
            last_execution: None,
            next_execution: Some(execution_time),
        };

        self.scheduled_workflows
            .write()
            .await
            .insert(schedule_id.clone(), scheduled);

        Ok(schedule_id)
    }

    /// Get upcoming scheduled workflows
    pub async fn get_upcoming_workflows(&self, hours_ahead: i64) -> Vec<ScheduledWorkflow> {
        let now = Utc::now();
        let cutoff = now + Duration::hours(hours_ahead);

        let workflows = self.scheduled_workflows.read().await;
        workflows
            .values()
            .filter(|w| {
                w.status == ScheduleStatus::Active
                    && w.next_execution.is_some()
                    && w.next_execution.unwrap() <= cutoff
            })
            .cloned()
            .collect()
    }
}

impl Default for WorkflowScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheduled workflow
#[derive(Debug, Clone)]
pub struct ScheduledWorkflow {
    pub id: String,
    pub workflow: super::types::WorkflowDefinition,
    pub scheduled_time: DateTime<Utc>,
    pub recurrence: Option<RecurrencePattern>,
    pub status: ScheduleStatus,
    pub created_at: DateTime<Utc>,
    pub last_execution: Option<DateTime<Utc>>,
    pub next_execution: Option<DateTime<Utc>>,
}

/// Schedule status
#[derive(Debug, Clone, PartialEq)]
pub enum ScheduleStatus {
    Active,
    Paused,
    Completed,
    Cancelled,
}

/// Recurrence pattern for scheduled workflows
#[derive(Debug, Clone)]
pub enum RecurrencePattern {
    Daily { at_time: (u32, u32) }, // (hour, minute)
    Weekly { day: Weekday, at_time: (u32, u32) },
    Monthly { day: u32, at_time: (u32, u32) },
    Custom { cron_expression: String },
}

/// Days of the week
#[derive(Debug, Clone)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

/// Scheduler configuration
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Maximum concurrent scheduled executions
    pub max_concurrent_executions: usize,

    /// Look-ahead window for scheduling (hours)
    pub look_ahead_hours: i64,

    /// Retry configuration for failed schedules
    pub retry_config: SchedulerRetryConfig,

    /// Notification settings
    pub notifications: SchedulerNotifications,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_executions: 10,
            look_ahead_hours: 24,
            retry_config: SchedulerRetryConfig::default(),
            notifications: SchedulerNotifications::default(),
        }
    }
}

/// Scheduler retry configuration
#[derive(Debug, Clone)]
pub struct SchedulerRetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,

    /// Initial delay between retries
    pub initial_delay_seconds: u64,

    /// Maximum delay between retries
    pub max_delay_seconds: u64,

    /// Backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for SchedulerRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_seconds: 60,
            max_delay_seconds: 3600,
            backoff_multiplier: 2.0,
        }
    }
}

/// Scheduler notification settings
#[derive(Debug, Clone)]
pub struct SchedulerNotifications {
    /// Enable execution notifications
    pub execution_notifications: bool,

    /// Enable failure notifications
    pub failure_notifications: bool,

    /// Notification recipients
    pub recipients: Vec<String>,

    /// Notification channels
    pub channels: Vec<NotificationChannel>,
}

impl Default for SchedulerNotifications {
    fn default() -> Self {
        Self {
            execution_notifications: true,
            failure_notifications: true,
            recipients: vec![],
            channels: vec![NotificationChannel::Log],
        }
    }
}

/// Notification channels
#[derive(Debug, Clone)]
pub enum NotificationChannel {
    Log,
    Email,
    Slack,
    Webhook { url: String },
}
