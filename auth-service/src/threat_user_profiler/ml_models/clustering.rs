pub struct UserClusteringModel;
impl Default for UserClusteringModel {
    fn default() -> Self {
        Self::new()
    }
}

impl UserClusteringModel {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
