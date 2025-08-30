pub struct AnomalyDetectionModel;
impl Default for AnomalyDetectionModel {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetectionModel {
    #[must_use] pub const fn new() -> Self {
        Self
    }
}
