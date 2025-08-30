use crate::threat_user_profiler::types::BehavioralFeatureVector;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// ML model manager for behavioral analysis
pub struct MLModelManager {
    models: Arc<RwLock<HashMap<String, Box<dyn MLModel + Send + Sync>>>>,
}

/// Trait for ML models used in behavioral analysis
pub trait MLModel {
    /// Predict anomaly score for given behavioral features
    ///
    /// # Errors
    /// Returns an error if:
    /// - Feature vector is invalid or incomplete
    /// - Model prediction fails
    /// - Model is not properly trained
    fn predict(
        &self,
        features: &BehavioralFeatureVector,
    ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>>;
    
    /// Train the model with behavioral feature data
    ///
    /// # Errors
    /// Returns an error if:
    /// - Training data is insufficient or invalid
    /// - Model training algorithm fails
    /// - Feature normalization fails
    fn train(
        &mut self,
        training_data: &[BehavioralFeatureVector],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn model_type(&self) -> String;
}

impl Default for MLModelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MLModelManager {
    #[must_use] pub fn new() -> Self {
        Self {
            models: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_model(&self, name: String, model: Box<dyn MLModel + Send + Sync>) {
        let mut models = self.models.write().await;
        models.insert(name, model);
    }

    /// Make a prediction using the specified model
    ///
    /// # Errors
    /// Returns an error if:
    /// - Model with the specified name is not found
    /// - Model prediction fails
    pub async fn predict(
        &self,
        model_name: &str,
        features: &BehavioralFeatureVector,
    ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
        let models = self.models.read().await;
        if let Some(model) = models.get(model_name) {
            model.predict(features)
        } else {
            Err(format!("Model {model_name} not found").into())
        }
    }
}
