//! # Auth Core - Minimal OAuth 2.0 Server
//!
//! A lightweight, secure OAuth 2.0 server implementation in Rust.
//! Perfect for microservices, development, and simple production use cases.
//!
//! ## Quick Start
//!
//! ```rust
//! use auth_core::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     AuthServer::minimal()
//!         .with_client("demo", "demo-secret")
//!         .serve("0.0.0.0:8080")
//!         .await
//! }
//! ```
//!
//! ## Features
//!
//! - **OAuth 2.0 Client Credentials Flow**: Service-to-service authentication
//! - **JWT Tokens**: Stateless, secure token format
//! - **In-Memory Storage**: Perfect for development and simple deployments
//! - **Rate Limiting**: Basic protection against abuse
//! - **Health Checks**: Monitor your service status
//!
//! ## Progressive Enhancement
//!
//! Start with `auth-core` and upgrade to `auth-standard` or `auth-enterprise`
//! as your needs grow, without changing your API.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, future_incompatible)]

pub mod client;
pub mod error;
pub mod handler;
pub mod server;
pub mod store;
pub mod token;

pub use error::{AuthError, Result};

/// Convenient re-exports for common use cases
pub mod prelude {
    pub use crate::client::ClientConfig;
    pub use crate::error::{AuthError, Result};
    pub use crate::server::{AuthServer, ServerConfig};
    pub use crate::token::{TokenRequest, TokenResponse};
}

/// Current version of the auth-core crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::const_is_empty)]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
