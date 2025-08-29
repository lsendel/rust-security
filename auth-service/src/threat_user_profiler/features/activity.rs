#[derive(Clone)]
pub struct ActivityFeatureExtractor {
    window_days: i64,
}
impl ActivityFeatureExtractor {
    pub fn new(window_days: i64) -> Self {
        Self { window_days }
    }
    pub async fn extract_activity_features(
        &self,
        _events: &[UserSecurityEvent],
        _historical: Option<&ActivityFeatures>,
    ) -> Result<ActivityFeatures, Box<dyn std::error::Error + Send + Sync>> {
        Ok(ActivityFeatures::default())
    }
    pub async fn update_activity_features(
        &self,
        _events: &[UserSecurityEvent],
        existing: &ActivityFeatures,
    ) -> Result<ActivityFeatures, Box<dyn std::error::Error + Send + Sync>> {
        Ok(existing.clone())
    }
}
