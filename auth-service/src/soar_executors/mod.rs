//! SOAR Step Executors Module
//!
//! This module provides concrete implementations of step executors for various
//! security operations including IP blocking, account management, notifications,
//! SIEM queries, and integration with external security tools.
//!
//! ## Architecture
//!
//! The SOAR executors are organized into focused modules:
//! - `registry`: Step executor registry and management
//! - `security`: Security action executors (IP blocking, account locking, etc.)
//! - `notification`: Notification executors (Email, Slack, Webhook)
//! - `query`: Query executors (SIEM, Database)
//! - `case_management`: Case and ticket management executors
//! - `script`: Script and HTTP request executors
//! - `control_flow`: Control flow executors (Decision, Wait)
//! - `clients`: External service client implementations
//!
//! ## Usage
//!
//! ```rust
//! use crate::soar_executors::{StepExecutorRegistry, StepExecutor};
//!
//! let registry = StepExecutorRegistry::new().await?;
//! let executor = registry.get_executor("ip_block").await?;
//! ```

// Re-export the StepExecutor trait from soar_core
pub use crate::soar_core::StepExecutor;

// Module declarations
pub mod case_management;
pub mod clients;
pub mod control_flow;
pub mod notification;
pub mod query;
pub mod registry;
pub mod script;
pub mod security;

// Re-export main types and interfaces
pub use registry::StepExecutorRegistry;

// Re-export commonly used executors
pub use case_management::{CaseUpdateExecutor, TicketCreateExecutor};
pub use control_flow::{DecisionExecutor, WaitExecutor};
pub use notification::{EmailNotificationExecutor, SlackNotificationExecutor, WebhookNotificationExecutor};
pub use query::{DatabaseQueryExecutor, SiemQueryExecutor};
pub use script::{HttpRequestExecutor, ScriptExecutor};
pub use security::{AccountLockExecutor, IpBlockExecutor, TokenRevokeExecutor};

// Re-export client implementations
pub use clients::{
    CaseManagerClient, FirewallClient, IdentityProviderClient, SiemClient, TicketingClient,
};

// Re-export configuration types
pub use clients::{
    CaseDetails, CaseManagerConfig, FirewallConfig, IdentityProviderConfig, SiemConfig,
    TicketingConfig,
};
