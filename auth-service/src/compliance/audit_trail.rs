//! Audit Trail Implementation for Compliance
//!
//! Comprehensive audit trail system for tracking all security-relevant events
//! across compliance frameworks (SOC 2, HIPAA, PCI DSS).

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// Audit event types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditEventType {
    Authentication,
    Authorization,
    DataAccess,
    DataModification,
    ConfigurationChange,
    SystemAccess,
    PrivilegedOperation,
    PolicyViolation,
    SecurityIncident,
    ComplianceCheck,
}

/// Audit event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: u64,
    pub event_type: AuditEventType,
    pub actor: String, // User ID or system identifier
    pub resource: String, // What was accessed/modified
    pub action: String, // What action was performed
    pub outcome: AuditOutcome,
    pub ip_address: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub metadata: HashMap<String, String>,
    pub compliance_frameworks: Vec<ComplianceFramework>,
}

/// Outcome of audited operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Success,
    Failure,
    Partial,
    Denied,
}

/// Audit trail manager
pub struct AuditTrailManager {
    // In a real implementation, this would connect to a secure database
    events: std::sync::Arc<std::sync::RwLock<Vec<AuditEvent>>>,
}

impl AuditTrailManager {
    /// Create new audit trail manager
    pub fn new() -> Self {
        Self {
            events: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }

    /// Log an audit event
    pub async fn log_event(&self, mut event: AuditEvent) -> ComplianceResult<()> {
        // Ensure event has unique ID
        if event.id.is_empty() {
            event.id = format!("audit_{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default());
        }

        // Set timestamp if not provided
        if event.timestamp == 0 {
            event.timestamp = chrono::Utc::now().timestamp() as u64;
        }

        debug!("Logging audit event: {}", event.id);

        // Store event (in production, this would be a secure database)
        let mut events = self.events.write().unwrap();
        events.push(event.clone());

        // Log for immediate visibility
        info!(
            "Audit Event: {} - {} performed {} on {} with outcome {:?}",
            event.event_type,
            event.actor,
            event.action,
            event.resource,
            event.outcome
        );

        Ok(())
    }

    /// Query audit events by criteria
    pub async fn query_events(
        &self,
        criteria: AuditQueryCriteria,
    ) -> ComplianceResult<Vec<AuditEvent>> {
        let events = self.events.read().unwrap();
        let mut filtered_events = Vec::new();

        for event in events.iter() {
            if self.matches_criteria(event, &criteria) {
                filtered_events.push(event.clone());
            }
        }

        // Sort by timestamp (newest first)
        filtered_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply limit
        if let Some(limit) = criteria.limit {
            filtered_events.truncate(limit);
        }

        Ok(filtered_events)
    }

    /// Check if event matches query criteria
    fn matches_criteria(&self, event: &AuditEvent, criteria: &AuditQueryCriteria) -> bool {
        // Time range filter
        if let Some(start) = criteria.start_time {
            if event.timestamp < start {
                return false;
            }
        }
        if let Some(end) = criteria.end_time {
            if event.timestamp > end {
                return false;
            }
        }

        // Event type filter
        if let Some(ref event_types) = criteria.event_types {
            if !event_types.contains(&event.event_type) {
                return false;
            }
        }

        // Actor filter
        if let Some(ref actor) = criteria.actor {
            if event.actor != *actor {
                return false;
            }
        }

        // Resource filter
        if let Some(ref resource) = criteria.resource {
            if !event.resource.contains(resource) {
                return false;
            }
        }

        // Outcome filter
        if let Some(ref outcomes) = criteria.outcomes {
            if !outcomes.contains(&event.outcome) {
                return false;
            }
        }

        // Compliance framework filter
        if let Some(ref frameworks) = criteria.compliance_frameworks {
            if !event.compliance_frameworks.iter().any(|f| frameworks.contains(f)) {
                return false;
            }
        }

        true
    }

    /// Generate audit report for compliance
    pub async fn generate_audit_report(
        &self,
        framework: ComplianceFramework,
        start_time: u64,
        end_time: u64,
    ) -> ComplianceResult<AuditReport> {
        let criteria = AuditQueryCriteria {
            start_time: Some(start_time),
            end_time: Some(end_time),
            compliance_frameworks: Some(vec![framework]),
            ..Default::default()
        };

        let events = self.query_events(criteria).await?;
        
        let mut report = AuditReport {
            id: format!("audit_report_{}_{}", framework, chrono::Utc::now().timestamp()),
            framework,
            report_period_start: start_time,
            report_period_end: end_time,
            total_events: events.len(),
            events_by_type: HashMap::new(),
            events_by_outcome: HashMap::new(),
            security_events: 0,
            failed_events: 0,
            critical_events: Vec::new(),
            compliance_summary: String::new(),
        };

        // Analyze events
        for event in &events {
            // Count by type
            *report.events_by_type.entry(event.event_type.clone()).or_insert(0) += 1;
            
            // Count by outcome
            *report.events_by_outcome.entry(event.outcome.clone()).or_insert(0) += 1;

            // Count security events
            if matches!(event.event_type, AuditEventType::SecurityIncident | AuditEventType::PolicyViolation) {
                report.security_events += 1;
            }

            // Count failed events
            if event.outcome == AuditOutcome::Failure || event.outcome == AuditOutcome::Denied {
                report.failed_events += 1;
            }

            // Identify critical events
            if self.is_critical_event(event) {
                report.critical_events.push(event.clone());
            }
        }

        // Generate compliance summary
        report.compliance_summary = self.generate_compliance_summary(&report, framework);

        info!("Generated audit report for {} covering {} events", framework, report.total_events);
        
        Ok(report)
    }

    /// Check if an event is considered critical
    fn is_critical_event(&self, event: &AuditEvent) -> bool {
        match event.event_type {
            AuditEventType::SecurityIncident => true,
            AuditEventType::PolicyViolation => true,
            AuditEventType::PrivilegedOperation if event.outcome == AuditOutcome::Failure => true,
            AuditEventType::DataAccess if event.outcome == AuditOutcome::Denied => true,
            _ => false,
        }
    }

    /// Generate compliance summary text
    fn generate_compliance_summary(&self, report: &AuditReport, framework: ComplianceFramework) -> String {
        let failure_rate = if report.total_events > 0 {
            (report.failed_events as f64 / report.total_events as f64) * 100.0
        } else {
            0.0
        };

        format!(
            "Audit report for {} compliance covering {} total events. \
            Security events: {}, Failed events: {} ({:.1}% failure rate), \
            Critical events requiring attention: {}. \
            {} framework requirements appear to be {}.",
            framework,
            report.total_events,
            report.security_events,
            report.failed_events,
            failure_rate,
            report.critical_events.len(),
            framework,
            if report.critical_events.is_empty() && failure_rate < 5.0 {
                "adequately implemented"
            } else {
                "requiring attention"
            }
        )
    }
}

/// Audit query criteria
#[derive(Debug, Default)]
pub struct AuditQueryCriteria {
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub event_types: Option<Vec<AuditEventType>>,
    pub actor: Option<String>,
    pub resource: Option<String>,
    pub outcomes: Option<Vec<AuditOutcome>>,
    pub compliance_frameworks: Option<Vec<ComplianceFramework>>,
    pub limit: Option<usize>,
}

/// Audit report structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub id: String,
    pub framework: ComplianceFramework,
    pub report_period_start: u64,
    pub report_period_end: u64,
    pub total_events: usize,
    pub events_by_type: HashMap<AuditEventType, u32>,
    pub events_by_outcome: HashMap<AuditOutcome, u32>,
    pub security_events: u32,
    pub failed_events: u32,
    pub critical_events: Vec<AuditEvent>,
    pub compliance_summary: String,
}

/// Global audit trail manager
static AUDIT_MANAGER: std::sync::OnceLock<AuditTrailManager> = std::sync::OnceLock::new();

/// Initialize audit trail system
pub fn initialize_audit_trail() {
    let manager = AuditTrailManager::new();
    let _ = AUDIT_MANAGER.set(manager);
    info!("Audit trail system initialized");
}

/// Get global audit trail manager
pub fn get_audit_manager() -> &'static AuditTrailManager {
    AUDIT_MANAGER.get_or_init(|| {
        initialize_audit_trail();
        AuditTrailManager::new()
    })
}

/// Convenience function to log authentication events
pub async fn log_authentication_event(
    user_id: &str,
    action: &str,
    outcome: AuditOutcome,
    ip_address: Option<std::net::IpAddr>,
    user_agent: Option<String>,
) -> ComplianceResult<()> {
    let event = AuditEvent {
        id: String::new(), // Will be generated
        timestamp: 0, // Will be set automatically
        event_type: AuditEventType::Authentication,
        actor: user_id.to_string(),
        resource: "authentication_system".to_string(),
        action: action.to_string(),
        outcome,
        ip_address,
        user_agent,
        session_id: None,
        metadata: HashMap::new(),
        compliance_frameworks: vec![
            ComplianceFramework::SOC2,
            ComplianceFramework::HIPAA,
            ComplianceFramework::PciDss,
        ],
    };

    get_audit_manager().log_event(event).await
}

/// Convenience function to log data access events
pub async fn log_data_access_event(
    user_id: &str,
    resource: &str,
    action: &str,
    outcome: AuditOutcome,
    compliance_frameworks: Vec<ComplianceFramework>,
) -> ComplianceResult<()> {
    let event = AuditEvent {
        id: String::new(),
        timestamp: 0,
        event_type: AuditEventType::DataAccess,
        actor: user_id.to_string(),
        resource: resource.to_string(),
        action: action.to_string(),
        outcome,
        ip_address: None,
        user_agent: None,
        session_id: None,
        metadata: HashMap::new(),
        compliance_frameworks,
    };

    get_audit_manager().log_event(event).await
}

/// Convenience function to log security incidents
pub async fn log_security_incident(
    incident_type: &str,
    description: &str,
    actor: &str,
    severity: ViolationSeverity,
) -> ComplianceResult<()> {
    let mut metadata = HashMap::new();
    metadata.insert("incident_type".to_string(), incident_type.to_string());
    metadata.insert("description".to_string(), description.to_string());
    metadata.insert("severity".to_string(), format!("{:?}", severity));

    let event = AuditEvent {
        id: String::new(),
        timestamp: 0,
        event_type: AuditEventType::SecurityIncident,
        actor: actor.to_string(),
        resource: "security_system".to_string(),
        action: "incident_detected".to_string(),
        outcome: AuditOutcome::Success, // Successfully detected
        ip_address: None,
        user_agent: None,
        session_id: None,
        metadata,
        compliance_frameworks: vec![
            ComplianceFramework::SOC2,
            ComplianceFramework::HIPAA,
            ComplianceFramework::PciDss,
        ],
    };

    get_audit_manager().log_event(event).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_event_logging() {
        let manager = AuditTrailManager::new();

        let event = AuditEvent {
            id: "test_event".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            event_type: AuditEventType::Authentication,
            actor: "test_user".to_string(),
            resource: "login_endpoint".to_string(),
            action: "login_attempt".to_string(),
            outcome: AuditOutcome::Success,
            ip_address: Some("192.168.1.1".parse().unwrap()),
            user_agent: Some("test_agent".to_string()),
            session_id: Some("session_123".to_string()),
            metadata: HashMap::new(),
            compliance_frameworks: vec![ComplianceFramework::SOC2],
        };

        let result = manager.log_event(event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_audit_event_query() {
        let manager = AuditTrailManager::new();

        // Log a test event
        let event = AuditEvent {
            id: "query_test".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            event_type: AuditEventType::DataAccess,
            actor: "test_user".to_string(),
            resource: "user_data".to_string(),
            action: "read".to_string(),
            outcome: AuditOutcome::Success,
            ip_address: None,
            user_agent: None,
            session_id: None,
            metadata: HashMap::new(),
            compliance_frameworks: vec![ComplianceFramework::SOC2],
        };

        let _ = manager.log_event(event).await;

        // Query for the event
        let criteria = AuditQueryCriteria {
            actor: Some("test_user".to_string()),
            limit: Some(10),
            ..Default::default()
        };

        let results = manager.query_events(criteria).await.unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].actor, "test_user");
    }

    #[tokio::test]
    async fn test_audit_report_generation() {
        let manager = AuditTrailManager::new();
        
        let now = chrono::Utc::now().timestamp() as u64;
        let start_time = now - 3600; // 1 hour ago
        
        let report = manager.generate_audit_report(
            ComplianceFramework::SOC2,
            start_time,
            now,
        ).await;

        assert!(report.is_ok());
        let report = report.unwrap();
        assert_eq!(report.framework, ComplianceFramework::SOC2);
        assert!(report.compliance_summary.contains("SOC 2"));
    }
}