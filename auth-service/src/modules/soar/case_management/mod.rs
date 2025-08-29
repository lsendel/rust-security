//! SOAR Case Management Module
//!
//! This module provides comprehensive case management capabilities.
//! It has been refactored from the monolithic soar_case_management.rs
//! into smaller, focused modules for better maintainability.

pub mod config;
pub mod errors;
pub mod handlers;
pub mod models;
pub mod persistence;
pub mod reporting;
pub mod workflows;

// Re-export main types for easy access
pub use config::CaseManagementConfig;
pub use errors::{ContextualError, ErrorCategory, ErrorContext, SoarError, SoarResult};
// pub use handlers::CaseManagementHandler; // TODO: Implement when needed
pub use models::{CasePriority, CaseStatus, SecurityCase};
pub use persistence::CaseRepository;
pub use reporting::CaseReportingService;
pub use workflows::CaseWorkflowEngine;

// Re-export the main system for backward compatibility
pub use handlers::CaseManagementSystem;
