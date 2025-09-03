//! API Module
//!
//! This module handles HTTP API operations including routing,
//! request/response processing, and API versioning.

pub mod handlers;
pub mod middleware;
pub mod versioning;

// Re-export main types
pub use handlers::ApiHandlers;
pub use middleware::ApiMiddleware;
pub use versioning::ApiVersionManager;
