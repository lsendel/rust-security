//! SOAR Core Engine
//!
//! Provides the main SOAR engine functionality and configuration management.

pub mod engine;
pub mod config;
pub mod types;

pub use engine::SoarEngine;
pub use config::SoarConfig;
pub use types::*;
