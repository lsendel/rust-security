//! Authorize Access Use Case

/// Use case for authorizing access to resources
pub struct AuthorizeAccessUseCase;

impl AuthorizeAccessUseCase {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuthorizeAccessUseCase {
    fn default() -> Self {
        Self::new()
    }
}
