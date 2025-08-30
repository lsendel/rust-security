use crate::threat_user_profiler::{NetworkFeatures, UserSecurityEvent};

#[derive(Clone)]
pub struct NetworkFeatureExtractor;
impl Default for NetworkFeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkFeatureExtractor {
    #[must_use]
    pub const fn new() -> Self {
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
