//! Repository Interfaces
//!
//! Defines the contracts for data access in the domain layer.

pub mod session_repository;
pub mod token_repository;
pub mod user_repository;

pub use session_repository::{SessionRepository, SessionRepositoryError};
pub use token_repository::{TokenRepository, TokenRepositoryError};
pub use user_repository::{RepositoryError, UserRepository};

// Type aliases for convenience
pub type DynUserRepository = Box<dyn UserRepository>;
pub type DynSessionRepository = Box<dyn SessionRepository>;
pub type DynTokenRepository = Box<dyn TokenRepository>;

// Re-export mock repositories for testing
#[cfg(test)]
pub use session_repository::tests::MockSessionRepository;
#[cfg(test)]
pub use token_repository::tests::MockTokenRepository;
#[cfg(test)]
pub use user_repository::tests::MockUserRepository;
