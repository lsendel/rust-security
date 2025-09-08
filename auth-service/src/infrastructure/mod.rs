//! Infrastructure Layer
//!
//! Contains infrastructure implementations (database, cache, storage, external services).

pub mod cache;
pub mod circuit_breaker;
pub mod config;
pub mod crypto;
#[cfg(feature = "postgres")]
pub mod database;
pub mod http;
pub mod monitoring;
pub mod rate_limiting;
pub mod security;
pub mod storage;

// Re-export main infrastructure components
pub use cache::*;
pub use circuit_breaker::*;
pub use config::*;
pub use crypto::*;
#[cfg(feature = "postgres")]
pub use database::*;
pub use http::*;
pub use crate::security::audit_logging::{SecurityAuditLogger, SecurityEvent, SecurityEventType, SecuritySeverity};
pub use rate_limiting::*;
pub use crate::security::threat_detection::threat_adapter::ThreatDetectionAdapter;
pub use crate::security::threat_detection::threat_response_orchestrator::ThreatResponseOrchestrator;
pub use storage::*;
