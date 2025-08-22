//! SOAR Core Engine
//! 
//! Core orchestration engine for Security Orchestration, Automation and Response

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarEngine {
    pub name: String,
    pub version: String,
    pub status: EngineStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EngineStatus {
    Running,
    Stopped,
    Error(String),
}

impl SoarEngine {
    pub fn new(name: String, version: String) -> Self {
        Self {
            name,
            version,
            status: EngineStatus::Stopped,
        }
    }
    
    pub fn start(&mut self) -> Result<(), String> {
        self.status = EngineStatus::Running;
        Ok(())
    }
    
    pub fn stop(&mut self) {
        self.status = EngineStatus::Stopped;
    }
}
