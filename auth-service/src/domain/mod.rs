//! Domain Layer
//!
//! This module contains the core business logic and domain entities.
//! Following Domain-Driven Design principles, this layer is independent
//! of infrastructure and presentation concerns.

pub mod entities;
pub mod value_objects;
pub mod repositories;
pub mod services;

// Re-export commonly used domain types
pub use entities::*;
pub use value_objects::*;
pub use services::*;
