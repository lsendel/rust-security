//! Application Layer
//!
//! Contains application bootstrap and configuration.

pub mod di;
pub mod router;

// Re-export the main components
pub use di::AppContainer;
pub use router::create_router;
