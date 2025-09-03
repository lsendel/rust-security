use crate::threat_user_profiler::{ActivityFeatures, UserSecurityEvent};

#[derive(Clone)]
pub struct ActivityFeatureExtractor {
    #[allow(dead_code)]
    window_days: i64,
}
impl ActivityFeatureExtractor {
    #[must_use]
    pub const fn new(window_days: i64) -> Self {
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
