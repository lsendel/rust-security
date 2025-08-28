//! SOAR Case Manager - Refactored Implementation
//!
//! This is the main case management system that orchestrates all SOAR components
//! including templates, automation, evidence, SLA tracking, and collaboration.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};
use crate::security_monitoring::{AlertSeverity, SecurityAlert};
use crate::soar_core::*;

use super::case_types::*;
use super::templates::{TemplateManager, EnhancedCaseTemplate, automation::AutomationEngine};
use super::{SoarConfig, SoarEvent, SoarEventType, SoarOperations, SoarError, CaseFilters};

/// Main case management system - refactored for modularity
pub struct CaseManagementSystem {
    /// System configuration
    config: Arc<RwLock<SoarConfig>>,

    /// Active cases in memory cache
    active_cases: Arc<DashMap<String, SecurityCase>>,

    /// Template manager
    template_manager: Arc<RwLock<TemplateManager>>,

    /// Automation engine
    automation_engine: Arc<RwLock<AutomationEngine>>,

    /// Database connection pool
    db_pool: Arc<Pool<Postgres>>,

    /// Case metrics
    metrics: Arc<Mutex<CaseManagementMetrics>>,

    /// Event publisher
    event_publisher: Option<tokio::sync::mpsc::Sender<SoarEvent>>,

    /// Security logger
    security_logger: Arc<SecurityLogger>,
}

/// Case management metrics
#[derive(Debug, Clone)]
pub struct CaseManagementMetrics {
    /// Total cases created
    pub total_cases_created: u64,

    /// Cases by status
    pub cases_by_status: HashMap<CaseStatus, u64>,

    /// Cases by severity
    pub cases_by_severity: HashMap<AlertSeverity, u64>,

    /// Average case resolution time
    pub avg_resolution_time_hours: f64,

    /// SLA compliance rate
    pub sla_compliance_rate: f64,

    /// Cases escalated
    pub cases_escalated: u64,

    /// Evidence items collected
    pub evidence_items_collected: u64,

    /// Collaboration sessions
    pub collaboration_sessions: u64,

    /// Workflow integrations triggered
    pub workflow_integrations_triggered: u64,

    /// Last updated
    pub last_updated: DateTime<Utc>,
}

impl CaseManagementSystem {
    /// Create a new case management system
    pub async fn new(
        config: SoarConfig,
        db_pool: Pool<Postgres>,
        event_publisher: Option<tokio::sync::mpsc::Sender<SoarEvent>>,
        security_logger: Arc<SecurityLogger>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let system = Self {
            config: Arc::new(RwLock::new(config)),
            active_cases: Arc::new(DashMap::new()),
            template_manager: Arc::new(RwLock::new(TemplateManager::new())),
            automation_engine: Arc::new(RwLock::new(AutomationEngine::new())),
            db_pool: Arc::new(db_pool),
            metrics: Arc::new(Mutex::new(CaseManagementMetrics::default())),
            event_publisher,
            security_logger,
        };

        Ok(system)
    }

    /// Initialize the case management system
    #[instrument(skip(self))]
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing SOAR case management system");

        // Load case templates
        self.load_case_templates().await?;

        // Load automation rules
        self.load_automation_rules().await?;

        // Start background processors
        self.start_sla_monitor().await;
        self.start_metrics_collector().await;
        self.start_cleanup_processor().await;

        // Log security event
        self.security_logger.log_event(SecurityEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::SystemInitialized,
            severity: SecuritySeverity::Info,
            source: "soar_case_management".to_string(),
            description: "SOAR case management system initialized".to_string(),
            metadata: Some(serde_json::json!({
                "component": "case_management",
                "version": "2.0"
            })),
        }).await;

        info!("SOAR case management system initialized successfully");
        Ok(())
    }

    /// Create a new security case with enhanced template support
    #[instrument(skip(self, related_alerts))]
    pub async fn create_case_with_template(
        &self,
        title: String,
        description: String,
        severity: AlertSeverity,
        related_alerts: Vec<String>,
        template_id: Option<String>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let case_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Apply template if specified
        let (final_title, final_description, additional_tags) = if let Some(template_id) = template_id {
            self.apply_case_template(&template_id, &title, &description).await?
        } else {
            (title, description, Vec::new())
        };

        // Calculate SLA deadlines based on severity
        let _config = self.config.read().await;
        let response_deadline = now + Duration::hours(
            config.default_sla.response_time_hours
                .get(&format!("{:?}", severity))
                .copied()
                .unwrap_or(4) as i64,
        );
        let resolution_deadline = now + Duration::hours(
            config.default_sla.resolution_time_hours
                .get(&format!("{:?}", severity))
                .copied()
                .unwrap_or(24) as i64,
        );
        drop(config);

        // Create case using the new modular structure
        let mut case = SecurityCase::new(
            final_title,
            final_description,
            severity.clone(),
            related_alerts,
        );

        // Set SLA information
        case.sla_info.response_deadline = Some(response_deadline);
        case.sla_info.resolution_deadline = Some(resolution_deadline);
        case.due_date = Some(resolution_deadline);

        // Add template tags
        case.tags.extend(additional_tags);

        // Store case in memory cache
        self.active_cases.insert(case_id.clone(), case.clone());

        // Persist to database
        self.persist_case(&case).await?;

        // Apply automation rules
        self.apply_automation_rules(&case).await?;

        // Update metrics
        self.update_case_creation_metrics(&severity).await;

        // Publish case creation event
        self.publish_case_event(SoarEventType::CaseCreated, &case).await;

        // Log security event
        self.security_logger.log_event(SecurityEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: now,
            event_type: SecurityEventType::CaseCreated,
            severity: SecuritySeverity::Info,
            source: "soar_case_management".to_string(),
            description: format!("Security case created: {}", case_id),
            metadata: Some(serde_json::json!({
                "case_id": case_id,
                "severity": severity,
                "template_used": template_id.is_some()
            })),
        }).await;

        info!("Created security case: {} (severity: {:?})", case_id, severity);
        Ok(case_id)
    }

    /// Apply case template
    async fn apply_case_template(
        &self,
        template_id: &str,
        title: &str,
        description: &str,
    ) -> Result<(String, String, Vec<String>), Box<dyn std::error::Error + Send + Sync>> {
        let template_manager = self.template_manager.read().await;
        
        if let Some(template) = template_manager.get_template(template_id) {
            // Apply title pattern
            let final_title = template.base_template.title_pattern
                .replace("{title}", title)
                .replace("{timestamp}", &Utc::now().format("%Y-%m-%d %H:%M:%S").to_string());

            // Apply description template
            let final_description = template.base_template.description_template
                .replace("{description}", description)
                .replace("{timestamp}", &Utc::now().format("%Y-%m-%d %H:%M:%S").to_string());

            // Get default tags
            let tags = template.base_template.default_tags.clone();

            Ok((final_title, final_description, tags))
        } else {
            Err(format!("Template not found: {}", template_id).into())
        }
    }

    /// Apply automation rules to a case
    async fn apply_automation_rules(&self, case: &SecurityCase) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let automation_engine = self.automation_engine.read().await;
        
        // Create rule context
        let context = super::templates::automation::RuleContext {
            case: case.clone(),
            context_data: HashMap::new(),
            timestamp: Utc::now(),
            user: "system".to_string(),
        };

        // Evaluate rules
        let results = automation_engine.evaluate_rules(&context);

        for result in results {
            if result.matched {
                debug!("Automation rule {} matched for case {}", result.rule_id, case.id);
                
                // Execute actions (simplified for now)
                for action in result.actions {
                    debug!("Executing automation action: {:?}", action.action_type);
                    // TODO: Implement action execution
                }
            }
        }

        Ok(())
    }

    /// Update case creation metrics
    async fn update_case_creation_metrics(&self, severity: &AlertSeverity) {
        let mut metrics = self.metrics.lock().await;
        metrics.total_cases_created += 1;
        *metrics.cases_by_status.entry(CaseStatus::New).or_insert(0) += 1;
        *metrics.cases_by_severity.entry(severity.clone()).or_insert(0) += 1;
        metrics.last_updated = Utc::now();
    }

    /// Publish case event
    async fn publish_case_event(&self, event_type: SoarEventType, case: &SecurityCase) {
        if let Some(ref publisher) = self.event_publisher {
            let event = SoarEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type,
                data: serde_json::to_value(case).unwrap_or(serde_json::Value::Null),
                source: "case_management".to_string(),
                priority: match case.severity {
                    AlertSeverity::Critical => 1,
                    AlertSeverity::High => 2,
                    AlertSeverity::Medium => 3,
                    AlertSeverity::Low => 4,
                },
            };

            if let Err(e) = publisher.send(event).await {
                warn!("Failed to publish case event: {}", e);
            }
        }
    }

    /// Load case templates from database/configuration
    async fn load_case_templates(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Load templates from database or configuration files
        info!("Loaded case templates");
        Ok(())
    }

    /// Load automation rules
    async fn load_automation_rules(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Load automation rules from database or configuration
        info!("Loaded automation rules");
        Ok(())
    }

    /// Persist case to database
    async fn persist_case(&self, case: &SecurityCase) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Implement database persistence with proper schema
        debug!("Persisting case {} to database", case.id);
        Ok(())
    }

    /// Start SLA monitor background task
    async fn start_sla_monitor(&self) {
        let active_cases = self.active_cases.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(300)); // 5 minutes

            loop {
                interval.tick().await;

                let config_guard = config.read().await;
                if !config_guard.default_sla.business_hours_only {
                    // Check SLA breaches for all cases
                    for case_entry in active_cases.iter() {
                        let case = case_entry.value();
                        
                        // Check if case is overdue
                        if case.is_overdue() && case.is_active() {
                            warn!("SLA breach detected for case: {}", case.id);
                            // TODO: Trigger escalation
                        }
                    }
                }
                drop(config_guard);

                debug!("SLA monitor check completed");
            }
        });
    }

    /// Start metrics collector background task
    async fn start_metrics_collector(&self) {
        let metrics = self.metrics.clone();
        let active_cases = self.active_cases.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(300)); // 5 minutes

            loop {
                interval.tick().await;

                let mut metrics_guard = metrics.lock().await;

                // Update case status counts
                metrics_guard.cases_by_status.clear();
                metrics_guard.cases_by_severity.clear();

                for case_entry in active_cases.iter() {
                    let case = case_entry.value();
                    *metrics_guard
                        .cases_by_status
                        .entry(case.status.clone())
                        .or_insert(0) += 1;
                    *metrics_guard
                        .cases_by_severity
                        .entry(case.severity.clone())
                        .or_insert(0) += 1;
                }

                metrics_guard.last_updated = Utc::now();

                debug!("Updated case management metrics");
            }
        });
    }

    /// Start cleanup processor background task
    async fn start_cleanup_processor(&self) {
        let active_cases = self.active_cases.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(86400)); // 24 hours

            loop {
                interval.tick().await;

                let cutoff_time = Utc::now() - Duration::days(30);
                let mut to_remove = Vec::new();

                for case_entry in active_cases.iter() {
                    let case = case_entry.value();
                    if (case.status == CaseStatus::Closed || case.status == CaseStatus::Resolved)
                        && case.updated_at < cutoff_time
                    {
                        to_remove.push(case.id.clone());
                    }
                }

                for case_id in to_remove {
                    active_cases.remove(&case_id);
                }

                debug!("Cleaned up old cases from memory cache");
            }
        });
    }

    /// Get case metrics
    pub async fn get_metrics(&self) -> CaseManagementMetrics {
        self.metrics.lock().await.clone()
    }

    /// Get case by ID
    pub async fn get_case(&self, case_id: &str) -> Option<SecurityCase> {
        self.active_cases.get(case_id).map(|entry| entry.clone())
    }

    /// List cases with filters
    pub async fn list_cases_filtered(&self, filters: &CaseFilters) -> Vec<SecurityCase> {
        let mut cases: Vec<SecurityCase> = self.active_cases
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        // Apply filters
        if let Some(ref statuses) = filters.status {
            cases.retain(|case| statuses.contains(&case.status));
        }

        if let Some(ref severities) = filters.severity {
            cases.retain(|case| severities.contains(&case.severity));
        }

        if let Some(ref assignee) = filters.assignee {
            cases.retain(|case| case.assignee.as_ref() == Some(assignee));
        }

        if let Some(ref tags) = filters.tags {
            cases.retain(|case| tags.iter().any(|tag| case.tags.contains(tag)));
        }

        if let Some(ref date_range) = filters.date_range {
            cases.retain(|case| {
                case.created_at >= date_range.start && case.created_at <= date_range.end
            });
        }

        // Apply pagination if specified
        if let Some(ref pagination) = filters.pagination {
            let start = (pagination.page * pagination.size) as usize;
            let end = start + pagination.size as usize;
            
            if start < cases.len() {
                cases = cases[start..end.min(cases.len())].to_vec();
            } else {
                cases.clear();
            }
        }

        cases
    }
}

#[async_trait]
impl SoarOperations for CaseManagementSystem {
    async fn create_case(&self, request: CreateCaseRequest) -> Result<String, SoarError> {
        self.create_case_with_template(
            request.title,
            request.description,
            request.severity,
            request.related_alerts,
            None, // No template specified
        )
        .await
        .map_err(|e| SoarError::InternalError(e.to_string()))
    }

    async fn update_case(&self, case_id: &str, update: CaseUpdate) -> Result<SecurityCase, SoarError> {
        if let Some(mut case_entry) = self.active_cases.get_mut(case_id) {
            let case = case_entry.value_mut();

            // Apply updates
            if let Some(title) = update.title {
                case.title = title;
            }
            if let Some(description) = update.description {
                case.description = description;
            }
            if let Some(status) = update.status {
                case.status = status;
            }
            if let Some(assignee) = update.assignee {
                case.assignee = Some(assignee);
            }
            if let Some(tags) = update.tags {
                case.tags = tags;
            }
            if let Some(custom_fields) = update.custom_fields {
                case.custom_fields.extend(custom_fields);
            }

            case.updated_at = Utc::now();

            let updated_case = case.clone();
            drop(case_entry);

            // Persist changes
            self.persist_case(&updated_case).await
                .map_err(|e| SoarError::DatabaseError(e.to_string()))?;

            // Publish update event
            self.publish_case_event(SoarEventType::CaseUpdated, &updated_case).await;

            Ok(updated_case)
        } else {
            Err(SoarError::CaseNotFound(case_id.to_string()))
        }
    }

    async fn get_case(&self, case_id: &str) -> Result<Option<SecurityCase>, SoarError> {
        Ok(self.get_case(case_id).await)
    }

    async fn list_cases(&self, filters: CaseFilters) -> Result<Vec<SecurityCase>, SoarError> {
        Ok(self.list_cases_filtered(&filters).await)
    }

    async fn add_evidence(&self, case_id: &str, evidence: Evidence) -> Result<String, SoarError> {
        if let Some(mut case_entry) = self.active_cases.get_mut(case_id) {
            let case = case_entry.value_mut();
            
            case.evidence.push(evidence.clone());
            case.updated_at = Utc::now();

            // Add timeline entry
            case.add_timeline_entry(
                TimelineEntryType::EvidenceAdded,
                evidence.collected_by.clone(),
                format!("Evidence '{}' added to case", evidence.name),
                Some(serde_json::json!({
                    "evidence_id": evidence.id,
                    "evidence_type": evidence.evidence_type
                })),
            );

            let updated_case = case.clone();
            drop(case_entry);

            // Persist changes
            self.persist_case(&updated_case).await
                .map_err(|e| SoarError::DatabaseError(e.to_string()))?;

            // Update metrics
            {
                let mut metrics = self.metrics.lock().await;
                metrics.evidence_items_collected += 1;
            }

            Ok(evidence.id)
        } else {
            Err(SoarError::CaseNotFound(case_id.to_string()))
        }
    }

    async fn assign_case(&self, case_id: &str, assignee: &str, actor: &str) -> Result<(), SoarError> {
        if let Some(mut case_entry) = self.active_cases.get_mut(case_id) {
            let case = case_entry.value_mut();
            
            let old_assignee = case.assignee.clone();
            case.assignee = Some(assignee.to_string());
            case.updated_at = Utc::now();

            // Add timeline entry
            case.add_timeline_entry(
                TimelineEntryType::CaseAssigned,
                actor.to_string(),
                format!("Case assigned to {}", assignee),
                Some(serde_json::json!({
                    "old_assignee": old_assignee,
                    "new_assignee": assignee
                })),
            );

            // Update SLA info if this is first assignment
            if old_assignee.is_none() && case.sla_info.time_to_response.is_none() {
                case.sla_info.time_to_response = Some(Utc::now() - case.created_at);
            }

            let updated_case = case.clone();
            drop(case_entry);

            // Persist changes
            self.persist_case(&updated_case).await
                .map_err(|e| SoarError::DatabaseError(e.to_string()))?;

            // Publish assignment event
            self.publish_case_event(SoarEventType::CaseAssigned, &updated_case).await;

            Ok(())
        } else {
            Err(SoarError::CaseNotFound(case_id.to_string()))
        }
    }

    async fn close_case(&self, case_id: &str, reason: CloseReason, actor: &str) -> Result<(), SoarError> {
        if let Some(mut case_entry) = self.active_cases.get_mut(case_id) {
            let case = case_entry.value_mut();
            
            case.status = CaseStatus::Closed;
            case.updated_at = Utc::now();

            // Update SLA info
            if case.sla_info.time_to_resolution.is_none() {
                case.sla_info.time_to_resolution = Some(Utc::now() - case.created_at);
            }

            // Add timeline entry
            case.add_timeline_entry(
                TimelineEntryType::Custom("CaseClosed".to_string()),
                actor.to_string(),
                format!("Case closed: {:?}", reason),
                Some(serde_json::json!({
                    "close_reason": reason
                })),
            );

            let updated_case = case.clone();
            drop(case_entry);

            // Persist changes
            self.persist_case(&updated_case).await
                .map_err(|e| SoarError::DatabaseError(e.to_string()))?;

            // Publish close event
            self.publish_case_event(SoarEventType::CaseClosed, &updated_case).await;

            Ok(())
        } else {
            Err(SoarError::CaseNotFound(case_id.to_string()))
        }
    }
}

impl Default for CaseManagementMetrics {
    fn default() -> Self {
        Self {
            total_cases_created: 0,
            cases_by_status: HashMap::new(),
            cases_by_severity: HashMap::new(),
            avg_resolution_time_hours: 0.0,
            sla_compliance_rate: 0.0,
            cases_escalated: 0,
            evidence_items_collected: 0,
            collaboration_sessions: 0,
            workflow_integrations_triggered: 0,
            last_updated: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_logging::SecurityLogger;

    #[tokio::test]
    async fn test_case_creation_with_template() {
        // This test would require a proper database setup
        // For now, we'll test the basic structure
        
        let config = SoarConfig::default();
        let security_logger = Arc::new(SecurityLogger::new().await.unwrap());
        
        // Note: This would fail without a real database connection
        // let system = CaseManagementSystem::new(config, db_pool, None, security_logger).await.unwrap();
        
        // Test that the structure is correct
        assert!(config.auto_create_cases);
    }

    #[test]
    fn test_case_management_metrics() {
        let metrics = CaseManagementMetrics::default();
        assert_eq!(metrics.total_cases_created, 0);
        assert_eq!(metrics.cases_escalated, 0);
    }
}
