//! Red Team Exercise Suite Library
//!
//! Comprehensive security testing framework for the Rust authentication service

pub mod attack_framework;
pub mod reporting;
pub mod scenarios;
pub mod tools;
pub mod validation;

pub use attack_framework::RedTeamFramework;
pub use reporting::RedTeamReporter;
pub use validation::SecurityControlValidator;

/// Re-export common types for convenience
pub use attack_framework::{AttackResult, AttackSession};
pub use reporting::{RedTeamReport, SecurityPosture};
pub use validation::{RiskLevel, ValidationResult};
