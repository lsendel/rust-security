//! Red Team Tools Module
//!
//! Contains automated tools for security testing and attack execution

use anyhow::Result;
use std::collections::HashMap;
use tracing::info;

pub mod attack_simulator;
pub mod coverage_analyzer;
pub mod performance_monitor;

pub use attack_simulator::AttackSimulator;
pub use coverage_analyzer::CoverageAnalyzer;
pub use performance_monitor::PerformanceMonitor;

/// Tool registry for managing red team tools
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn RedTeamTool>>,
}

/// Trait for all red team tools
pub trait RedTeamTool {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    async fn execute(&self, target: &str, config: &ToolConfig) -> Result<ToolResult>;
}

/// Configuration for red team tools
#[derive(Debug, Clone)]
pub struct ToolConfig {
    pub intensity: String,
    pub duration_seconds: u64,
    pub concurrent_threads: u32,
    pub custom_params: HashMap<String, String>,
}

/// Result from tool execution
#[derive(Debug)]
pub struct ToolResult {
    pub tool_name: String,
    pub success: bool,
    pub metrics: HashMap<String, f64>,
    pub findings: Vec<String>,
    pub raw_data: serde_json::Value,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self { tools: HashMap::new() }
    }

    pub fn register_tool(&mut self, tool: Box<dyn RedTeamTool>) {
        let name = tool.name().to_string();
        self.tools.insert(name, tool);
    }

    pub async fn execute_tool(
        &self,
        tool_name: &str,
        target: &str,
        config: &ToolConfig,
    ) -> Result<ToolResult> {
        if let Some(tool) = self.tools.get(tool_name) {
            info!("Executing tool: {}", tool_name);
            tool.execute(target, config).await
        } else {
            Err(anyhow::anyhow!("Tool not found: {}", tool_name))
        }
    }

    pub fn list_tools(&self) -> Vec<&str> {
        self.tools.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            intensity: "medium".to_string(),
            duration_seconds: 300,
            concurrent_threads: 5,
            custom_params: HashMap::new(),
        }
    }
}
