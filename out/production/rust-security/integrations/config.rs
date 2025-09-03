use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct IntegrationConfig {
    #[serde(default)]
    pub siem: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub vulnerability_scanners: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub threat_intelligence: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub security_orchestration: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub compliance_reporting: Option<HashMap<String, serde_json::Value>>,
}
