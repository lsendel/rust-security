//! Performance optimization utilities
//!
//! This module provides optimized implementations for common operations
//! to improve memory usage, reduce allocations, and enhance async performance.

pub mod async_utils;
pub mod smart_cache;
pub mod string_optimization;

pub use async_utils::{process_batch, execute_with_timeout, TimeoutError};
pub use smart_cache::{SmartCache, CacheMetrics};
pub use string_optimization::{SharedString, OptionalString, shared_string, format_error_message, OptimizedConfig};
