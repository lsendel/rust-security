//! Session Management Module
//!
//! This module provides comprehensive session management functionality,
//! including storage, cleanup, and secure session handling.
//!
//! ## Features
//!
//! - **Session Storage**: Redis and in-memory session storage
//! - **Session Management**: Session lifecycle management
//! - **Secure Sessions**: Encrypted and secure session handling
//! - **Cleanup**: Automatic expired session cleanup
//! - **Performance**: Optimized for high-throughput scenarios

pub mod cleanup;
pub mod manager;
pub mod secure;
pub mod store;

// Re-export main session types
pub use cleanup::SessionCleanupScheduler;
pub use manager::SessionManager;
pub use secure::SecureSessionManager;
pub use store::RedisSessionStore;
