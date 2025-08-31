//! Database Infrastructure
//!
//! Database connection and repository implementations.

pub mod connection_pool;
pub mod postgres;
pub mod redis;

// Re-export database implementations
pub use connection_pool::{ConnectionPoolConfig, DatabaseConnectionManager, OptimizedPgPool};
pub use postgres::*;
pub use redis::*;
