use crate::threat_user_profiler::{LocationFeatures, UserSecurityEvent};

#[derive(Clone)]
pub struct LocationFeatureExtractor {
    clustering_radius: f64,
}

impl LocationFeatureExtractor {
    pub fn new(clustering_radius: f64) -> Self {
        Self { clustering_radius }
    }

    pub async fn extract_location_features(
        &self,
        _events: &[UserSecurityEvent],
        _historical: Option<&LocationFeatures>,
    ) -> Result<LocationFeatures, Box<dyn std::error::Error + Send + Sync>> {
        Ok(LocationFeatures::default())
    }

    pub async fn update_location_features(
        &self,
        _events: &[UserSecurityEvent],
        existing: &LocationFeatures,
    ) -> Result<LocationFeatures, Box<dyn std::error::Error + Send + Sync>> {
        Ok(existing.clone())
    }
}
