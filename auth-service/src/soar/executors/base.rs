//! SOAR Base Executor
//! 
//! Base traits and structures for SOAR executors

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub action: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub context: ExecutionContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub workflow_id: String,
    pub step_id: String,
    pub variables: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResponse {
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

#[async_trait]
pub trait BaseExecutor: Send + Sync {
    async fn execute(&self, request: ExecutionRequest) -> Result<ExecutionResponse, String>;
    fn get_capabilities(&self) -> Vec<String>;
    fn get_name(&self) -> String;
    fn get_version(&self) -> String;
}

pub struct DefaultExecutor {
    pub name: String,
    pub version: String,
}

impl DefaultExecutor {
    pub fn new(name: String, version: String) -> Self {
        Self { name, version }
    }
}

#[async_trait]
impl BaseExecutor for DefaultExecutor {
    async fn execute(&self, _request: ExecutionRequest) -> Result<ExecutionResponse, String> {
        Ok(ExecutionResponse {
            success: true,
            result: Some(serde_json::json!({"status": "completed"})),
            error: None,
            metadata: HashMap::new(),
        })
    }
    
    fn get_capabilities(&self) -> Vec<String> {
        vec!["basic_execution".to_string()]
    }
    
    fn get_name(&self) -> String {
        self.name.clone()
    }
    
    fn get_version(&self) -> String {
        self.version.clone()
    }
}
