//! SOAR Workflow Engine
//! 
//! Workflow execution engine for automated security responses

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEngine {
    pub id: Uuid,
    pub name: String,
    pub active_workflows: HashMap<Uuid, WorkflowInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInstance {
    pub id: Uuid,
    pub workflow_id: String,
    pub status: WorkflowStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowStatus {
    Pending,
    Running,
    Completed,
    Failed(String),
}

impl WorkflowEngine {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            active_workflows: HashMap::new(),
        }
    }
}
