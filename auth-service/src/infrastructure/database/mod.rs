//! Database Infrastructure
//!
//! Database connection and repository implementations.

pub mod connection_pool;
#[cfg(feature = "postgres")]
pub mod postgres;
// pub mod redis; // Temporarily disabled due to complex async trait implementation issues

// Re-export database implementations
pub use connection_pool::{ConnectionPoolConfig, DatabaseConnectionManager, OptimizedPgPool};
#[cfg(feature = "postgres")]
pub use postgres::*;
