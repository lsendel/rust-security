#[derive(Clone)]
pub struct NetworkFeatureExtractor;
impl NetworkFeatureExtractor {
    pub fn new() -> Self {
        Self
    }
    pub async fn extract_network_features(
        &self,
        _events: &[UserSecurityEvent],
        _historical: Option<&NetworkFeatures>,
    ) -> Result<NetworkFeatures, Box<dyn std::error::Error + Send + Sync>> {
        Ok(NetworkFeatures::default())
    }
    pub async fn update_network_features(
        &self,
        _events: &[UserSecurityEvent],
        existing: &NetworkFeatures,
    ) -> Result<NetworkFeatures, Box<dyn std::error::Error + Send + Sync>> {
        Ok(existing.clone())
    }
}
