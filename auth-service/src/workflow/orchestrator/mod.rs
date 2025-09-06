//! Workflow Orchestration Module
//!
//! This module provides the workflow execution engine for security playbooks,
//! including step execution, dependency management, approval handling, and error recovery.

pub mod approval;
pub mod audit;
pub mod config;
pub mod core;
pub mod execution;
pub mod metrics;
pub mod scheduler;
pub mod security;
pub mod types;

pub use self::approval::ApprovalManager;
pub use self::config::WorkflowConfig;
pub use self::core::WorkflowOrchestrator;
pub use self::scheduler::WorkflowScheduler;
pub use self::types::*;
