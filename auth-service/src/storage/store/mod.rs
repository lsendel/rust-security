//! Generic Storage Module
//!
//! This module provides generic storage interfaces and implementations,
//! including SQL storage, optimized storage, and hybrid storage solutions.
//!
//! ## Features
//!
//! - **SQL Storage**: PostgreSQL and SQLite storage implementations
//! - **Optimized Storage**: Performance-optimized storage solutions
//! - **Hybrid Storage**: Combined storage strategies
//! - **Store Interface**: Generic storage trait for extensibility

pub mod hybrid;
pub mod optimized;
pub mod sql;

// Re-export main store types
pub use hybrid::HybridStore;
pub use optimized::OptimizedRedisStore;
pub use sql::SqlStore;
