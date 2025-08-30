//! Storage Layer Module
//!
//! This module provides a unified interface for all storage operations in the auth service,
//! including caching, session management, and persistent storage.
//!
//! ## Architecture
//!
//! The storage layer is organized into three main submodules:
//! - `cache`: High-performance caching implementations
//! - `session`: Session management and persistence
//! - `store`: Generic storage interfaces and implementations
//!
//! ## Features
//!
//! - **Caching**: Token caching, policy caching, intelligent caching
//! - **Sessions**: Session storage, management, and cleanup
//! - **Storage**: SQL storage, optimized storage, hybrid storage
//! - **Performance**: Optimized for high-throughput scenarios
//! - **Reliability**: Circuit breakers and backpressure handling

pub mod cache;
pub mod session;
pub mod store;

// Re-export commonly used types for convenience
pub use cache::{Cache, IntelligentCacheError};
pub use session::store::RedisSessionStore;
pub use store::hybrid::HybridStore;
