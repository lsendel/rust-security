#[derive(Clone)]
pub struct DeviceFeatureExtractor {
    sensitivity: f64,
}

impl DeviceFeatureExtractor {
    pub fn new(sensitivity: f64) -> Self {
        Self { sensitivity }
    }

    pub async fn extract_device_features(
        &self,
        _events: &[UserSecurityEvent],
        _historical: Option<&DeviceFeatures>,
    ) -> Result<DeviceFeatures, Box<dyn std::error::Error + Send + Sync>> {
        Ok(DeviceFeatures::default())
    }

    pub async fn update_device_features(
        &self,
        _events: &[UserSecurityEvent],
        existing: &DeviceFeatures,
    ) -> Result<DeviceFeatures, Box<dyn std::error::Error + Send + Sync>> {
        Ok(existing.clone())
    }
}
