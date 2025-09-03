//! Data models and types for the policy service

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Authorization request structure
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    /// Unique identifier for this authorization request
    pub request_id: String,
    /// The principal (user/system) making the request
    pub principal: serde_json::Value,
    /// The action being performed (e.g., "Document::read")
    pub action: String,
    /// The resource being accessed
    pub resource: serde_json::Value,
    /// Additional context for the authorization decision
    pub context: serde_json::Value,
}

/// Authorization response structure
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeResponse {
    /// The authorization decision ("Allow" or "Deny")
    pub decision: String,
}

/// Application state containing Cedar policy service components
///
/// This struct holds the core components needed for Cedar policy evaluation:
/// - Authorizer: The Cedar policy evaluation engine
/// - PolicySet: The compiled set of authorization policies
/// - Entities: The entity store containing entity definitions and attributes
///
/// # Thread Safety
///
/// All fields implement appropriate thread safety:
/// - `Authorizer` is thread-safe and can be shared across requests
/// - `PolicySet` is immutable after compilation and thread-safe
/// - `Entities` is thread-safe for concurrent access
///
/// # Memory Usage
///
/// The AppState is typically wrapped in an `Arc` for sharing across multiple
/// HTTP request handlers. The memory footprint depends on:
/// - Number and complexity of policies in the PolicySet
/// - Number and size of entities in the Entities store
/// - Policy evaluation caches (maintained by the Authorizer)
///
/// # Performance Considerations
///
/// - Policy compilation happens once during startup
/// - Entity data is loaded once and cached
/// - The Authorizer maintains internal caches for performance
/// - All components are optimized for concurrent access
pub struct AppState {
    /// The Cedar policy evaluation engine
    pub authorizer: cedar_policy::Authorizer,
    /// The compiled set of authorization policies
    pub policies: cedar_policy::PolicySet,
    /// The entity store containing entity definitions and attributes
    pub entities: cedar_policy::Entities,
}

/// Policy conflict information
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PolicyConflict {
    /// ID of the policy involved in the conflict
    pub policy_id: String,
    /// ID of the conflicting policy
    pub conflicting_policy: String,
    /// Type of conflict detected
    pub conflict_type: String,
}
