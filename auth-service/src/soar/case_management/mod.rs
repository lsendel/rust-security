//! Case Management System
//!
//! Handles security incident cases, their lifecycle, and associated workflows.

pub mod manager;
pub mod types;
pub mod storage;
pub mod analytics;

pub use manager::{CaseManager, CaseManagerConfig, CaseUpdate, CaseFilter};
pub use types::{
    Case, CaseStatus, CasePriority, CaseSeverity, CaseCategory,
    EvidenceItem, EvidenceType, CaseActivity, ActivityType,
    CaseSla, CaseMetrics, CaseTemplate,
};
