//! Register User Use Case

/// Use case for registering new users
pub struct RegisterUserUseCase;

impl RegisterUserUseCase {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for RegisterUserUseCase {
    fn default() -> Self {
        Self::new()
    }
}
