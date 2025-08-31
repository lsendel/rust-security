//! Metrics collection and monitoring for the SOAR system
//!
//! This module provides comprehensive metrics collection for monitoring
//! SOAR system performance, workflow execution, and operational health.

use super::types::*;
use crate::infrastructure::security::security_monitoring::{AlertSeverity, SecurityAlert, SecurityAlertType};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// SOAR metrics collector
pub struct SoarMetrics {
    /// Workflow execution metrics
    workflow_metrics: Arc<DashMap<String, WorkflowMetrics>>,

    /// Alert processing metrics
    alert_metrics: Arc<Mutex<AlertMetrics>>,

    /// Case management metrics
    case_metrics: Arc<Mutex<CaseMetrics>>,

    /// Overall system metrics
    system_metrics: Arc<Mutex<SystemMetrics>>,

    /// Integration metrics
    integration_metrics: Arc<DashMap<String, IntegrationMetrics>>,

    /// Performance metrics
    performance_metrics: Arc<Mutex<PerformanceMetrics>>,
}

impl SoarMetrics {
    /// Create a new metrics collector
    pub async fn new() -> Result<Self, MetricsError> {
        Ok(Self {
            workflow_metrics: Arc::new(DashMap::new()),
            alert_metrics: Arc::new(Mutex::new(AlertMetrics::default())),
            case_metrics: Arc::new(Mutex::new(CaseMetrics::default())),
            system_metrics: Arc::new(Mutex::new(SystemMetrics::default())),
            integration_metrics: Arc::new(DashMap::new()),
            performance_metrics: Arc::new(Mutex::new(PerformanceMetrics::default())),
        })
    }

    /// Start metrics collection
    pub async fn start(&self) -> Result<(), MetricsError> {
        info!("Starting SOAR metrics collection");

        // Start periodic metrics collection
        let metrics_clone = self.clone();
        tokio::spawn(async move {
            metrics_clone.collect_system_metrics().await;
        });

        Ok(())
    }

    /// Stop metrics collection
    pub async fn stop(&self) -> Result<(), MetricsError> {
        info!("Stopping SOAR metrics collection");
        Ok(())
    }

    /// Record workflow execution
    pub async fn record_workflow_execution(
        &self,
        playbook_id: &str,
        execution_time_ms: u64,
        success: bool,
    ) -> Result<(), MetricsError> {
        let mut metrics = self
            .workflow_metrics
            .entry(playbook_id.to_string())
            .or_insert_with(|| WorkflowMetrics {
                playbook_id: playbook_id.to_string(),
                total_executions: 0,
                successful_executions: 0,
                failed_executions: 0,
                avg_execution_time_ms: 0.0,
                last_execution: None,
                success_rate: 0.0,
            });

        metrics.total_executions += 1;
        metrics.last_execution = Some(Utc::now());

        if success {
            metrics.successful_executions += 1;
        } else {
            metrics.failed_executions += 1;
        }

        // Update average execution time
        let total_time = metrics.avg_execution_time_ms * (metrics.total_executions - 1) as f64;
        metrics.avg_execution_time_ms =
            (total_time + execution_time_ms as f64) / metrics.total_executions as f64;

        // Update success rate
        metrics.success_rate =
            (metrics.successful_executions as f64 / metrics.total_executions as f64) * 100.0;

        Ok(())
    }

    /// Record alert processing
    pub async fn record_alert_processed(&self, alert: &SecurityAlert) -> Result<(), MetricsError> {
        let mut metrics = self.alert_metrics.lock().await;

        metrics.total_alerts += 1;

        // Update alerts by severity
        *metrics
            .alerts_by_severity
            .entry(alert.severity.clone())
            .or_insert(0) += 1;

        // Update alerts by type
        *metrics
            .alerts_by_type
            .entry(alert.alert_type.clone())
            .or_insert(0) += 1;

        Ok(())
    }

    /// Record alert correlation
    pub async fn record_alert_correlation(&self) -> Result<(), MetricsError> {
        let mut metrics = self.alert_metrics.lock().await;
        metrics.correlated_alerts += 1;
        Ok(())
    }

    /// Record auto-response
    pub async fn record_auto_response(&self) -> Result<(), MetricsError> {
        let mut metrics = self.alert_metrics.lock().await;
        metrics.auto_responded_alerts += 1;
        Ok(())
    }

    /// Record case creation
    pub async fn record_case_created(&self, severity: AlertSeverity) -> Result<(), MetricsError> {
        let mut metrics = self.case_metrics.lock().await;

        metrics.total_cases += 1;
        *metrics.cases_by_severity.entry(severity).or_insert(0) += 1;
        *metrics.cases_by_status.entry(CaseStatus::New).or_insert(0) += 1;

        Ok(())
    }

    /// Record case status change
    pub async fn record_case_status_change(
        &self,
        old_status: CaseStatus,
        new_status: CaseStatus,
    ) -> Result<(), MetricsError> {
        let mut metrics = self.case_metrics.lock().await;

        // Decrease old status count
        if let Some(count) = metrics.cases_by_status.get_mut(&old_status) {
            if *count > 0 {
                *count -= 1;
            }
        }

        // Increase new status count
        *metrics.cases_by_status.entry(new_status).or_insert(0) += 1;

        Ok(())
    }

    /// Record case response time
    pub async fn record_case_response_time(
        &self,
        response_time_minutes: f64,
    ) -> Result<(), MetricsError> {
        let mut metrics = self.case_metrics.lock().await;

        // Update average response time
        let total_cases_with_response = metrics.total_cases.max(1);
        let total_time =
            metrics.avg_time_to_response_minutes * (total_cases_with_response - 1) as f64;
        metrics.avg_time_to_response_minutes =
            (total_time + response_time_minutes) / total_cases_with_response as f64;

        Ok(())
    }

    /// Record case resolution time
    pub async fn record_case_resolution_time(
        &self,
        resolution_time_hours: f64,
    ) -> Result<(), MetricsError> {
        let mut metrics = self.case_metrics.lock().await;

        // Update average resolution time
        let resolved_cases = metrics
            .cases_by_status
            .get(&CaseStatus::Resolved)
            .unwrap_or(&0)
            + 1;
        let total_time = metrics.avg_time_to_resolution_hours * (resolved_cases - 1) as f64;
        metrics.avg_time_to_resolution_hours =
            (total_time + resolution_time_hours) / resolved_cases as f64;

        Ok(())
    }

    /// Record SLA breach
    pub async fn record_sla_breach(&self) -> Result<(), MetricsError> {
        let mut metrics = self.case_metrics.lock().await;

        // Calculate SLA breach rate
        let total_cases = metrics.total_cases.max(1);
        let breaches = (metrics.sla_breach_rate * total_cases as f64 / 100.0) + 1.0;
        metrics.sla_breach_rate = (breaches / total_cases as f64) * 100.0;

        Ok(())
    }

    /// Update integration metrics
    pub async fn update_integration_metrics(
        &self,
        integration_id: &str,
        metrics: IntegrationMetrics,
    ) -> Result<(), MetricsError> {
        self.integration_metrics
            .insert(integration_id.to_string(), metrics);
        Ok(())
    }

    /// Get workflow metrics
    pub async fn get_workflow_metrics(&self, playbook_id: &str) -> Option<WorkflowMetrics> {
        self.workflow_metrics
            .get(playbook_id)
            .map(|entry| entry.value().clone())
    }

    /// Get all workflow metrics
    pub async fn get_all_workflow_metrics(&self) -> HashMap<String, WorkflowMetrics> {
        self.workflow_metrics
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get alert metrics
    pub async fn get_alert_metrics(&self) -> AlertMetrics {
        self.alert_metrics.lock().await.clone()
    }

    /// Get case metrics
    pub async fn get_case_metrics(&self) -> CaseMetrics {
        self.case_metrics.lock().await.clone()
    }

    /// Get system metrics
    pub async fn get_system_metrics(&self) -> SystemMetrics {
        self.system_metrics.lock().await.clone()
    }

    /// Get integration metrics
    pub async fn get_integration_metrics(
        &self,
        integration_id: &str,
    ) -> Option<IntegrationMetrics> {
        self.integration_metrics
            .get(integration_id)
            .map(|entry| entry.value().clone())
    }

    /// Get performance metrics
    pub async fn get_performance_metrics(&self) -> PerformanceMetrics {
        self.performance_metrics.lock().await.clone()
    }

    /// Get comprehensive metrics summary
    pub async fn get_metrics_summary(&self) -> MetricsSummary {
        let workflow_metrics = self.get_all_workflow_metrics().await;
        let alert_metrics = self.get_alert_metrics().await;
        let case_metrics = self.get_case_metrics().await;
        let system_metrics = self.get_system_metrics().await;
        let performance_metrics = self.get_performance_metrics().await;

        MetricsSummary {
            timestamp: Utc::now(),
            workflow_metrics,
            alert_metrics,
            case_metrics,
            system_metrics,
            performance_metrics,
            integration_count: self.integration_metrics.len(),
        }
    }

    /// Collect system metrics periodically
    async fn collect_system_metrics(&self) {
        let collection_interval = tokio::time::Duration::from_secs(60); // 1 minute
        let mut interval = tokio::time::interval(collection_interval);

        loop {
            interval.tick().await;

            if let Err(e) = self.update_system_metrics().await {
                error!("Failed to update system metrics: {}", e);
            }
        }
    }

    /// Update system metrics
    async fn update_system_metrics(&self) -> Result<(), MetricsError> {
        let mut metrics = self.system_metrics.lock().await;

        // Update uptime (simplified - would use actual system uptime)
        metrics.uptime_seconds += 60;

        // Update active workflows count
        metrics.active_workflows = self.workflow_metrics.len() as u64;

        // Update integration health
        let healthy_integrations = self
            .integration_metrics
            .iter()
            .filter(|entry| {
                entry.value().error_rate < 5.0 // Less than 5% error rate
            })
            .count() as u64;

        metrics.healthy_integrations = healthy_integrations;
        metrics.total_integrations = self.integration_metrics.len() as u64;

        // Simulate resource usage (in real implementation, would collect actual metrics)
        metrics.memory_usage_mb = 512.0 + (rand::random::<f64>() * 100.0);
        metrics.cpu_usage_percent = 10.0 + (rand::random::<f64>() * 20.0);

        Ok(())
    }

    /// Record performance metric
    pub async fn record_performance_metric(
        &self,
        operation: &str,
        duration_ms: u64,
        success: bool,
    ) -> Result<(), MetricsError> {
        let mut metrics = self.performance_metrics.lock().await;

        let operation_metrics = metrics
            .operations
            .entry(operation.to_string())
            .or_insert_with(|| OperationMetrics {
                operation_name: operation.to_string(),
                total_operations: 0,
                successful_operations: 0,
                failed_operations: 0,
                avg_duration_ms: 0.0,
                min_duration_ms: u64::MAX,
                max_duration_ms: 0,
                p95_duration_ms: 0.0,
                last_operation: None,
            });

        operation_metrics.total_operations += 1;
        operation_metrics.last_operation = Some(Utc::now());

        if success {
            operation_metrics.successful_operations += 1;
        } else {
            operation_metrics.failed_operations += 1;
        }

        // Update duration metrics
        operation_metrics.min_duration_ms = operation_metrics.min_duration_ms.min(duration_ms);
        operation_metrics.max_duration_ms = operation_metrics.max_duration_ms.max(duration_ms);

        // Update average duration
        let total_time =
            operation_metrics.avg_duration_ms * (operation_metrics.total_operations - 1) as f64;
        operation_metrics.avg_duration_ms =
            (total_time + duration_ms as f64) / operation_metrics.total_operations as f64;

        Ok(())
    }
}

impl Clone for SoarMetrics {
    fn clone(&self) -> Self {
        Self {
            workflow_metrics: Arc::clone(&self.workflow_metrics),
            alert_metrics: Arc::clone(&self.alert_metrics),
            case_metrics: Arc::clone(&self.case_metrics),
            system_metrics: Arc::clone(&self.system_metrics),
            integration_metrics: Arc::clone(&self.integration_metrics),
            performance_metrics: Arc::clone(&self.performance_metrics),
        }
    }
}

/// Performance metrics for operations
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    pub operations: HashMap<String, OperationMetrics>,
}

/// Metrics for individual operations
#[derive(Debug, Clone)]
pub struct OperationMetrics {
    pub operation_name: String,
    pub total_operations: u64,
    pub successful_operations: u64,
    pub failed_operations: u64,
    pub avg_duration_ms: f64,
    pub min_duration_ms: u64,
    pub max_duration_ms: u64,
    pub p95_duration_ms: f64,
    pub last_operation: Option<DateTime<Utc>>,
}

/// Comprehensive metrics summary
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub timestamp: DateTime<Utc>,
    pub workflow_metrics: HashMap<String, WorkflowMetrics>,
    pub alert_metrics: AlertMetrics,
    pub case_metrics: CaseMetrics,
    pub system_metrics: SystemMetrics,
    pub performance_metrics: PerformanceMetrics,
    pub integration_count: usize,
}

/// Metrics error types
#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    #[error("Collection error: {0}")]
    CollectionError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Calculation error: {0}")]
    CalculationError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Default implementations for metrics types
impl Default for AlertMetrics {
    fn default() -> Self {
        Self {
            total_alerts: 0,
            alerts_by_severity: HashMap::new(),
            alerts_by_type: HashMap::new(),
            correlated_alerts: 0,
            auto_responded_alerts: 0,
            avg_processing_time_ms: 0.0,
        }
    }
}

impl Default for CaseMetrics {
    fn default() -> Self {
        Self {
            total_cases: 0,
            cases_by_status: HashMap::new(),
            cases_by_severity: HashMap::new(),
            avg_time_to_response_minutes: 0.0,
            avg_time_to_resolution_hours: 0.0,
            sla_breach_rate: 0.0,
        }
    }
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            uptime_seconds: 0,
            active_workflows: 0,
            active_cases: 0,
            healthy_integrations: 0,
            total_integrations: 0,
            memory_usage_mb: 0.0,
            cpu_usage_percent: 0.0,
        }
    }
}

// Missing type definitions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertMetrics {
    pub total_alerts: u64,
    pub alerts_by_severity: HashMap<String, u64>,
    pub alerts_by_type: HashMap<String, u64>,
    pub correlated_alerts: u64,
    pub auto_responded_alerts: u64,
    pub avg_processing_time_ms: f64,
}
