//! Workflow Execution Components

use super::types::{WorkflowDefinition, WorkflowInstance, WorkflowStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;

/// Priority queue for workflow execution requests
pub struct PriorityQueue<T> {
    items: VecDeque<PriorityItem<T>>,
}

impl<T> PriorityQueue<T> {
    /// Create a new priority queue
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: VecDeque::new(),
        }
    }

    /// Push an item onto the queue with priority
    pub fn push(&mut self, item: PriorityItem<T>) {
        // Simple implementation - in a real system, you'd want a more efficient priority queue
        self.items.push_back(item);
        // Sort by priority (higher priority first)
        self.items
            .make_contiguous()
            .sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Pop the highest priority item from the queue
    pub fn pop(&mut self) -> Option<PriorityItem<T>> {
        self.items.pop_front()
    }

    /// Get the number of items in the queue
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if the queue is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl<T> Default for PriorityQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Item in the priority queue
#[derive(Debug, Clone)]
pub struct PriorityItem<T> {
    pub data: T,
    pub priority: super::types::Priority,
    pub queued_at: DateTime<Utc>,
}

/// Workflow execution request
#[derive(Debug, Clone)]
pub struct WorkflowExecutionRequest {
    pub instance_id: String,
    pub workflow: WorkflowDefinition,
    pub context: HashMap<String, Value>,
    pub priority: super::types::Priority,
    pub submitted_at: DateTime<Utc>,
}

/// Execution context for workflow steps
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub workflow_id: String,
    pub step_id: String,
    pub instance_id: String,
    pub inputs: HashMap<String, Value>,
    pub outputs: HashMap<String, Value>,
    pub metadata: ExecutionMetadata,
    pub security_context: super::security::SecurityContext,
}

/// Execution metadata
#[derive(Debug, Clone)]
pub struct ExecutionMetadata {
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
    pub retries: u32,
    pub attempt_number: u32,
    pub execution_node: String,
    pub resource_usage: super::metrics::ResourceUsage,
}

/// Execution trigger information
#[derive(Debug, Clone)]
pub struct ExecutionTrigger {
    pub trigger_type: TriggerType,
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub correlation_id: Option<String>,
}

/// Trigger types
#[derive(Debug, Clone)]
pub enum TriggerType {
    Manual,
    Scheduled,
    Event { event_type: String },
    Dependency { parent_step_id: String },
    Retry,
    Recovery,
}

/// Time constraints for workflow execution
#[derive(Debug, Clone)]
pub struct TimeConstraints {
    pub start_after: Option<DateTime<Utc>>,
    pub complete_before: Option<DateTime<Utc>>,
    pub execution_window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub timeout_minutes: Option<u32>,
}
