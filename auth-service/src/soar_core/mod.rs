//! SOAR (Security Orchestration, Automation, and Response) Core Module
//!
//! This module provides a comprehensive SOAR system with the following capabilities:
//! - Workflow orchestration and automation
//! - Alert correlation and analysis
//! - Automated response execution
//! - Case management and tracking
//! - Integration framework for external tools
//! - Comprehensive metrics and monitoring
//!
//! ## Architecture
//!
//! The SOAR core is organized into focused modules:
//! - `types`: Core data structures and configuration
//! - `engine`: Main SOAR engine implementation
//! - `workflow`: Workflow orchestration and execution
//! - `correlation`: Alert correlation and pattern detection
//! - `response`: Automated response execution
//! - `integration`: External tool integration framework
//! - `metrics`: Performance and operational metrics
//!
//! ## Usage
//!
//! ```rust
//! use crate::soar_core::{SoarCore, SoarConfig};
//!
//! let config = SoarConfig::default();
//! let soar = SoarCore::new(config).await?;
//! soar.start().await?;
//! ```

// Module declarations
pub mod correlation;
pub mod engine;
pub mod integration;
pub mod metrics;
pub mod response;
pub mod types;
pub mod workflow;

// Re-export main types and interfaces
pub use engine::{HealthStatus, SoarCore, SoarError, SoarHealthStatus};
pub use types::*;

// Re-export commonly used items from submodules
pub use correlation::{
    AlertCorrelationEngine, CorrelationError, CorrelationMetrics, CorrelationResult,
};
pub use integration::{
    EdrIntegration, FirewallIntegration, HealthMetrics, Integration, IntegrationFramework,
    IntegrationManager, SiemIntegration,
};
pub use metrics::{MetricsError, MetricsSummary, PerformanceMetrics, SoarMetrics};
pub use response::{ResponseAutomationEngine, ResponseError, ResponseMetrics};
pub use workflow::{StepExecutor, WorkflowEngine, WorkflowEngineMetrics};

// Type aliases for convenience
pub type SoarEngine = SoarCore;
pub type ResponseAction = Box<dyn response::ResponseAction + Send + Sync>;
