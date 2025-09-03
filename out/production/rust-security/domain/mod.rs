//! Domain Layer
//!
//! Contains domain entities, value objects, and repository interfaces.

pub mod entities;
pub mod repositories;
pub mod value_objects;

// Re-export main types for convenience
pub use entities::*;
pub use repositories::*;
pub use value_objects::*;
