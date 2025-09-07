//! Application State
//!
//! This module manages the shared application state that is passed
//! between handlers and services throughout the application.

pub mod app_state;
pub mod state_factory;

// Re-export main types
pub use app_state::AppState;
pub use state_factory::AppStateFactory;
