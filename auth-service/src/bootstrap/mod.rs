//! Application Bootstrap
//!
//! This module handles the initialization and startup of the application.
//! It coordinates the setup of all services, middleware, and infrastructure components.

pub mod app_builder;
pub mod config_loader;
pub mod service_initializer;

// Re-export main bootstrap functions
pub use app_builder::AppBuilder;
pub use config_loader::ConfigLoader;
pub use service_initializer::ServiceInitializer;
