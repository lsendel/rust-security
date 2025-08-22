//! SOAR Workflow Definitions
//! 
//! Workflow definition structures and validation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub steps: Vec<WorkflowStep>,
    pub triggers: Vec<WorkflowTrigger>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: String,
    pub name: String,
    pub action: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub conditions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTrigger {
    pub event_type: String,
    pub conditions: HashMap<String, serde_json::Value>,
}

impl WorkflowDefinition {
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("Workflow ID cannot be empty".to_string());
        }
        if self.steps.is_empty() {
            return Err("Workflow must have at least one step".to_string());
        }
        Ok(())
    }
}
