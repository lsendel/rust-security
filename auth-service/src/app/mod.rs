//! Application Layer
//!
//! Contains application bootstrap and configuration.

pub mod di;
pub mod router;
pub mod mvp_router;
pub mod mvp_config;

// Re-export the main components
pub use di::AppContainer;
pub use router::create_router;

// Re-export MVP components
pub use mvp_router::create_mvp_router;
pub use mvp_config::{AuthConfig, ConfigError};
