//! Database Module
//!
//! This module handles database operations including connection pooling,
//! query execution, and data persistence.

pub mod connection;
pub mod queries;
pub mod migration;

// Re-export main types
pub use connection::DatabaseConnection;
pub use queries::QueryExecutor;
pub use migration::DatabaseMigration;
