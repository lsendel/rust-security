//! Value Objects
//!
//! Immutable value objects that represent domain concepts.

pub mod email;
pub mod password_hash;
pub mod user_id;
pub mod scope;

pub use email::Email;
pub use password_hash::PasswordHash;
pub use user_id::UserId;
pub use scope::Scope;
