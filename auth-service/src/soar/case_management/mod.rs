//! Case Management System
//!
//! Handles security incident cases, their lifecycle, and associated workflows.

pub mod analytics;
pub mod manager;
pub mod storage;
pub mod types;

pub use manager::{CaseManager, CaseManagerConfig, CaseUpdate, CaseFilter};
pub use types::{
    Case, CaseStatus, CasePriority, CaseSeverity, CaseCategory,
    EvidenceItem, EvidenceType, CaseActivity, ActivityType,
    CaseSla, CaseMetrics, CaseTemplate,
};
