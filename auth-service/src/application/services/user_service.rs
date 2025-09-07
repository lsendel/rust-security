//! User Application Service

/// User application service for managing user operations
pub struct UserApplicationService;

impl UserApplicationService {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for UserApplicationService {
    fn default() -> Self {
        Self::new()
    }
}
