//! Workflow Configuration Types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Workflow configuration
#[derive(Debug, Clone)]
pub struct WorkflowConfig {
    /// Maximum concurrent workflows
    pub max_concurrent_workflows: usize,

    /// Default timeout for workflows
    pub default_timeout_minutes: u32,

    /// Maximum retry attempts
    pub max_retry_attempts: u32,

    /// Step execution timeout
    pub step_timeout_minutes: u32,

    /// Enable parallel execution
    pub parallel_execution_enabled: bool,

    /// Workflow persistence settings
    pub persistence_config: PersistenceConfig,

    /// Error handling settings
    pub error_handling: GlobalErrorHandling,
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            max_concurrent_workflows: 100,
            default_timeout_minutes: 60,
            max_retry_attempts: 3,
            step_timeout_minutes: 30,
            parallel_execution_enabled: true,
            persistence_config: PersistenceConfig::default(),
            error_handling: GlobalErrorHandling::default(),
        }
    }
}

/// Persistence configuration
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Enable workflow state persistence
    pub enabled: bool,

    /// Persistence backend
    pub backend: PersistenceBackend,

    /// Checkpoint frequency
    pub checkpoint_frequency: CheckpointFrequency,

    /// Retention policy
    pub retention_days: u32,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: PersistenceBackend::Database,
            checkpoint_frequency: CheckpointFrequency::EveryStep,
            retention_days: 30,
        }
    }
}

/// Persistence backend types
#[derive(Debug, Clone)]
pub enum PersistenceBackend {
    Database,
    FileSystem,
    Redis,
    Hybrid,
}

/// Checkpoint frequency
#[derive(Debug, Clone)]
pub enum CheckpointFrequency {
    EveryStep,
    Periodic { minutes: u32 },
    OnStateChange,
    Manual,
}

/// Global error handling configuration
#[derive(Debug, Clone)]
pub struct GlobalErrorHandling {
    /// Enable circuit breaker pattern
    pub circuit_breaker_enabled: bool,

    /// Circuit breaker configuration
    pub circuit_breaker_config: CircuitBreakerConfig,

    /// Enable automatic rollback on failure
    pub auto_rollback_enabled: bool,

    /// Maximum error rate before circuit opens
    pub error_rate_threshold: f64,

    /// Retry configuration
    pub retry_config: RetryConfig,
}

impl Default for GlobalErrorHandling {
    fn default() -> Self {
        Self {
            circuit_breaker_enabled: true,
            circuit_breaker_config: CircuitBreakerConfig::default(),
            auto_rollback_enabled: true,
            error_rate_threshold: 0.5,
            retry_config: RetryConfig::default(),
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failure threshold before opening
    pub failure_threshold: u32,

    /// Timeout before attempting to close
    pub timeout_seconds: u32,

    /// Expected volume threshold
    pub expected_volume_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            timeout_seconds: 60,
            expected_volume_threshold: 10,
        }
    }
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,

    /// Initial delay between retries
    pub initial_delay_ms: u64,

    /// Maximum delay between retries
    pub max_delay_ms: u64,

    /// Backoff multiplier
    pub backoff_multiplier: f64,

    /// Jitter for retry delays
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}
