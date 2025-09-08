//! Domain Layer
//!
//! This module contains the core business logic and domain entities.
//! Following Domain-Driven Design principles, this layer is independent
//! of infrastructure and presentation concerns.

pub mod entities;
pub mod repositories;
pub mod services;
pub mod value_objects;

// Re-export commonly used domain types
pub use entities::*;
pub use services::*;
pub use value_objects::*;
