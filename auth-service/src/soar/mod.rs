//! SOAR (Security Orchestration, Automation and Response) Module
//!
//! This module provides comprehensive SOAR capabilities including:
//! - Case management and workflow orchestration
//! - Automated response execution
//! - Integration with external security tools
//! - Threat intelligence correlation

pub mod case_management;
pub mod core;
pub mod executors;
pub mod workflow;

// Re-export available types
pub use case_management::{CaseManager, Case, CaseStatus};
pub use core::*;

/// SOAR service version
pub const SOAR_VERSION: &str = env!("CARGO_PKG_VERSION");
