//! Metrics and Performance Tracking

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Workflow metrics tracking
#[derive(Debug, Clone, Default)]
pub struct WorkflowMetrics {
    pub total_executions: u64,
    pub successful_executions: u64,
    pub failed_executions: u64,
    pub cancelled_executions: u64,
    pub average_execution_time_ms: f64,
    pub step_metrics: HashMap<String, StepMetrics>,
    pub resource_usage: ResourceUsage,
    pub error_counts: HashMap<String, u64>,
    pub last_updated: DateTime<Utc>,
}

/// Step-specific metrics
#[derive(Debug, Clone, Default)]
pub struct StepMetrics {
    pub total_executions: u64,
    pub successful_executions: u64,
    pub failed_executions: u64,
    pub average_duration_ms: f64,
    pub min_duration_ms: u64,
    pub max_duration_ms: u64,
    pub retry_count: u64,
}

/// Resource usage tracking
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    pub cpu_time_ms: u64,
    pub memory_peak_bytes: u64,
    pub memory_average_bytes: u64,
    pub disk_io_bytes: u64,
    pub network_io_bytes: u64,
    pub database_queries: u64,
    pub external_api_calls: u64,
}

/// Step timing information
#[derive(Debug, Clone, Default)]
pub struct StepTiming {
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
    pub wait_time_ms: u64,
    pub execution_node: String,
}

/// Performance tracker for workflow execution
#[derive(Debug, Clone, Default)]
pub struct PerformanceTracker {
    pub step_timings: HashMap<String, StepTiming>,
    pub resource_snapshots: Vec<ResourceSnapshot>,
    pub bottlenecks: Vec<Bottleneck>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Resource usage snapshot
#[derive(Debug, Clone)]
pub struct ResourceSnapshot {
    pub timestamp: DateTime<Utc>,
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub disk_io_ops: u64,
    pub network_io_bytes: u64,
}

/// Bottleneck identification
#[derive(Debug, Clone)]
pub struct Bottleneck {
    pub step_id: String,
    pub description: String,
    pub duration_ms: u64,
    pub impact_score: f64,
    pub detected_at: DateTime<Utc>,
}

impl WorkflowMetrics {
    /// Record a successful execution
    pub fn record_success(&mut self, duration_ms: u64) {
        self.total_executions += 1;
        self.successful_executions += 1;

        // Update average execution time using incremental average formula
        let total = self.successful_executions as f64;
        let current_avg = self.average_execution_time_ms;
        self.average_execution_time_ms =
            ((current_avg * (total - 1.0)) + duration_ms as f64) / total;

        self.last_updated = Utc::now();
    }

    /// Record a failed execution
    pub fn record_failure(&mut self, error_type: &str) {
        self.total_executions += 1;
        self.failed_executions += 1;

        *self.error_counts.entry(error_type.to_string()).or_insert(0) += 1;
        self.last_updated = Utc::now();
    }

    /// Record a cancelled execution
    pub fn record_cancellation(&mut self) {
        self.total_executions += 1;
        self.cancelled_executions += 1;
        self.last_updated = Utc::now();
    }

    /// Record step metrics
    pub fn record_step_metrics(&mut self, step_id: &str, metrics: StepMetrics) {
        self.step_metrics.insert(step_id.to_string(), metrics);
    }

    /// Get success rate as a percentage
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_executions == 0 {
            100.0 // Default to 100% if no executions
        } else {
            (self.successful_executions as f64 / self.total_executions as f64) * 100.0
        }
    }

    /// Get failure rate as a percentage
    #[must_use]
    pub fn failure_rate(&self) -> f64 {
        if self.total_executions == 0 {
            0.0 // Default to 0% if no executions
        } else {
            (self.failed_executions as f64 / self.total_executions as f64) * 100.0
        }
    }
}
