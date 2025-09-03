//! Database Infrastructure
//!
//! Database connection and repository implementations.

pub mod connection_pool;
// pub mod postgres; // Module file doesn't exist
// pub mod redis; // Temporarily disabled due to complex async trait implementation issues

// Re-export database implementations
#[cfg(feature = "postgres")]
pub use connection_pool::{ConnectionPoolConfig, DatabaseConnectionManager, OptimizedPgPool};
// #[cfg(feature = "postgres")]
// pub use postgres::*; // Module doesn't exist
