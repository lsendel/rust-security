//! Repository Interfaces
//!
//! Defines the contracts for data access in the domain layer.

pub mod session_repository;
pub mod token_repository;
pub mod user_repository;

pub use session_repository::{SessionRepository, SessionRepositoryError};
pub use token_repository::{TokenRepository, TokenRepositoryError};
pub use user_repository::{RepositoryError, UserRepository};

// Type aliases for convenience - use Arc to enable cloning
pub type DynUserRepository = std::sync::Arc<dyn UserRepository>;
pub type DynSessionRepository = std::sync::Arc<dyn SessionRepository>;
pub type DynTokenRepository = std::sync::Arc<dyn TokenRepository>;

// Mock repositories are available in crate::tests::mocks module
