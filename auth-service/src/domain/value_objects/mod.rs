//! Value Objects
//!
//! Immutable value objects that represent domain concepts.

pub mod email;
pub mod password_hash;
pub mod scope;
pub mod user_id;

pub use email::Email;
pub use password_hash::PasswordHash;
pub use scope::Scope;
pub use user_id::UserId;
