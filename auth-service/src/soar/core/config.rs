//! SOAR Core Configuration
//! 
//! Configuration management for SOAR components

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarConfig {
    pub engine_name: String,
    pub max_concurrent_workflows: usize,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
}

impl Default for SoarConfig {
    fn default() -> Self {
        Self {
            engine_name: "rust-security-soar".to_string(),
            max_concurrent_workflows: 10,
            timeout_seconds: 300,
            retry_attempts: 3,
        }
    }
}
