#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, future_incompatible)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::future_not_send,
    clippy::items_after_statements,
    clippy::unnecessary_wraps,
    clippy::struct_excessive_bools,
    clippy::branches_sharing_code,
    clippy::trivially_copy_pass_by_ref,
    dead_code
)]
//! Common types and utilities for the rust-security workspace
//!
//! This crate provides shared types, error handling, and utility functions
//! that are used across multiple services in the rust-security project.

pub mod config;
pub mod constants;
pub mod crypto_utils;
pub mod errors;
pub mod optimized_pools;
pub mod redis_config;
pub mod secure_logging;
pub mod sharded_rate_limiter;
pub mod store;
pub mod types;
pub mod utils;

pub use config::{PlatformConfiguration, RateLimitConfig, SecurityConfig};
pub use constants::*;
pub use crypto_utils::*;
pub use errors::*;
use num_cpus as _;
pub use optimized_pools::{OptimizedRedisPool, PoolError, PoolStats};
pub use redis_config::*;
pub use secure_logging::{
    sanitize_for_logging, AuditLogger, SafeForLogging, SanitizedValue, SecureRequestLog,
};
pub use sharded_rate_limiter::{RateLimited, ShardedRateLimiter};
pub use store::*;
pub use types::{
    AlertSeverity, ApiResponse, AuthCodeRecord, HealthStatus, MetricPoint, RateLimitInfo,
    ScimGroup, ScimUser, SecurityAlert, ServiceStatus, StoreMetrics, TokenRecord, ValidationResult,
};
pub use utils::{current_timestamp, format_duration, generate_correlation_id, validate_url};

// Import once_cell to satisfy unused dependency warning
use once_cell as _;
