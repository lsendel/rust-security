//! Session Application Service

/// Session application service for managing session operations
pub struct SessionApplicationService;

impl SessionApplicationService {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for SessionApplicationService {
    fn default() -> Self {
        Self::new()
    }
}
