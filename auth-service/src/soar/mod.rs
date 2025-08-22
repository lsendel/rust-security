//! SOAR (Security Orchestration, Automation and Response) Module
//!
//! This module provides comprehensive SOAR capabilities including:
//! - Case management and workflow orchestration
//! - Automated response execution
//! - Integration with external security tools
//! - Threat intelligence correlation

pub mod core;
pub mod case_management;
pub mod workflow;
pub mod executors;

// Re-export main types
pub use core::{SoarEngine, SoarConfig};
pub use case_management::{CaseManager, Case, CaseStatus};
pub use workflow::{WorkflowEngine, WorkflowDefinition};
pub use executors::{ExecutorRegistry, ResponseExecutor};

/// SOAR service version
pub const SOAR_VERSION: &str = env!("CARGO_PKG_VERSION");
