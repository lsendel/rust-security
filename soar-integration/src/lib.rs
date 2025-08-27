//! Security Orchestration, Automation, and Response (SOAR) Integration Module
//!
//! This crate provides comprehensive SOAR capabilities for security incident management,
//! automated response workflows, and integration with external security tools.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum SoarError {
    #[error("Case not found: {id}")]
    CaseNotFound { id: Uuid },
    
    #[error("Workflow execution failed: {reason}")]
    WorkflowFailed { reason: String },
    
    #[error("Integration error: {service}")]
    IntegrationError { service: String },
    
    #[error("Database error")]
    DatabaseError(#[from] anyhow::Error),
    
    #[error("Template error: {reason}")]
    TemplateError { reason: String },
    
    #[error("Notification failed: {channel}")]
    NotificationFailed { channel: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub assigned_to: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentStatus {
    Open,
    InProgress,
    Resolved,
    Closed,
    FalsePositive,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_creation() {
        let incident = SecurityIncident {
            id: Uuid::new_v4(),
            title: "Suspicious login activity".to_string(),
            description: "Multiple failed login attempts detected".to_string(),
            severity: IncidentSeverity::Medium,
            status: IncidentStatus::Open,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            assigned_to: None,
            tags: vec!["authentication".to_string(), "brute-force".to_string()],
            metadata: HashMap::new(),
        };
        
        assert_eq!(incident.status, IncidentStatus::Open);
        assert_eq!(incident.severity, IncidentSeverity::Medium);
    }
}
