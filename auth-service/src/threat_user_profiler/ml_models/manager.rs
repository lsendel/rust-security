use crate::threat_user_profiler::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// ML model manager for behavioral analysis
pub struct MLModelManager {
    models: Arc<RwLock<HashMap<String, Box<dyn MLModel + Send + Sync>>>>,
}

/// Trait for ML models used in behavioral analysis
pub trait MLModel {
    fn predict(
        &self,
        features: &BehavioralFeatureVector,
    ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>>;
    fn train(
        &mut self,
        training_data: &[BehavioralFeatureVector],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn model_type(&self) -> String;
}

impl MLModelManager {
    pub fn new() -> Self {
        Self {
            models: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_model(&self, name: String, model: Box<dyn MLModel + Send + Sync>) {
        let mut models = self.models.write().await;
        models.insert(name, model);
    }

    pub async fn predict(
        &self,
        model_name: &str,
        features: &BehavioralFeatureVector,
    ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
        let models = self.models.read().await;
        if let Some(model) = models.get(model_name) {
            model.predict(features)
        } else {
            Err(format!("Model {} not found", model_name).into())
        }
    }
}
