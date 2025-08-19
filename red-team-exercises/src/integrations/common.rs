use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EventSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityAlert {
    pub title: String,
    pub description: String,
    pub severity: EventSeverity,
    pub timestamp: DateTime<Utc>,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IntegrationMetadata {
    pub integration_name: String,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IntegrationResult {
    pub metadata: IntegrationMetadata,
    pub raw_output: String,
}
