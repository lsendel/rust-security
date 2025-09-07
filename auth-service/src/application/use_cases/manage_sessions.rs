//! Manage Sessions Use Case

/// Use case for managing user sessions
pub struct ManageSessionsUseCase;

impl ManageSessionsUseCase {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for ManageSessionsUseCase {
    fn default() -> Self {
        Self::new()
    }
}
