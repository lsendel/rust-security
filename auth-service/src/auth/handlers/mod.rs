//! Authentication handlers module
//!
//! Contains handler functions split by feature

#[cfg(feature = "user-auth")]
pub mod user;

#[cfg(feature = "oauth")]
pub mod oauth;