use crate::soar_core::{Integration, IntegrationError, IntegrationHealth, IntegrationType, StepAction, HealthStatus};
use std::collections::HashMap;
use async_trait::async_trait;

pub struct MockIntegration {
    name: String,
    integration_type: IntegrationType,
}

impl MockIntegration {
    pub fn new(name: &str, integration_type: IntegrationType) -> Self {
        Self {
            name: name.to_string(),
            integration_type,
        }
    }
}

#[async_trait]
impl Integration for MockIntegration {
    async fn execute_action(
        &self,
        action: &StepAction,
        _context: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, IntegrationError> {
        println!("Executing action {:?} on integration {}", action, self.name);
        Ok(HashMap::new())
    }

    async fn health_check(&self) -> Result<IntegrationHealth, IntegrationError> {
        Ok(IntegrationHealth {
            integration_name: self.name.clone(),
            status: HealthStatus::Healthy,
            last_check: chrono::Utc::now(),
            response_time_ms: 100,
            error_message: None,
            metrics: HashMap::new(),
        })
    }

    fn get_integration_type(&self) -> IntegrationType {
        self.integration_type.clone()
    }

    fn get_integration_name(&self) -> String {
        self.name.clone()
    }
}
