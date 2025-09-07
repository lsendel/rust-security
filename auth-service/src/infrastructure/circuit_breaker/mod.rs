//! Circuit Breaker Infrastructure
//!
//! This module provides circuit breaker functionality for resilience
//! against cascading failures in distributed systems.

pub mod circuit_breaker;
pub mod circuit_breaker_advanced;

// Re-export the main circuit breaker types
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError, CircuitBreakerStats,
    RetryBackoff, RetryConfig, TimeoutConfig,
};
pub use circuit_breaker_advanced::AdvancedCircuitBreaker;
