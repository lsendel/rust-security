//! Storage Layer
//!
//! Contains storage implementations and repositories.

// Re-export existing storage functionality
pub use crate::infrastructure::*;

// Direct path exports for external test compatibility
pub mod session {
    pub mod store {
        pub use crate::infrastructure::storage::session::store::RedisSessionStore;
        pub use crate::infrastructure::storage::session::store::SessionStore;
    }
}
