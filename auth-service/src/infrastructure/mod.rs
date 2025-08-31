//! Infrastructure Layer
//!
//! Contains infrastructure implementations (database, cache, storage, external services).

pub mod database;
pub mod cache;
pub mod storage;

// Re-export main infrastructure components
pub use database::*;
pub use cache::*;
pub use storage::*;
