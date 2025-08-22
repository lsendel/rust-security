//! SOAR Executor Registry
//! 
//! Registry for managing workflow executors and their capabilities

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorRegistry {
    pub executors: HashMap<String, ExecutorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorInfo {
    pub name: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub status: ExecutorStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutorStatus {
    Available,
    Busy,
    Offline,
    Error(String),
}

impl ExecutorRegistry {
    pub fn new() -> Self {
        Self {
            executors: HashMap::new(),
        }
    }
    
    pub fn register_executor(&mut self, id: String, info: ExecutorInfo) {
        self.executors.insert(id, info);
    }
    
    pub fn get_available_executors(&self) -> Vec<&ExecutorInfo> {
        self.executors
            .values()
            .filter(|info| matches!(info.status, ExecutorStatus::Available))
            .collect()
    }
}

impl Default for ExecutorRegistry {
    fn default() -> Self {
        Self::new()
    }
}
