//! Authentication Application Service

/// Authentication application service for managing authentication operations
pub struct AuthenticationApplicationService;

impl AuthenticationApplicationService {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuthenticationApplicationService {
    fn default() -> Self {
        Self::new()
    }
}
