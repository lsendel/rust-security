//! Data models for MVP policy service

use cedar_policy::{Authorizer, Entities, PolicySet};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Application state for MVP policy service
#[derive(Clone)]
pub struct AppState {
    pub authorizer: Authorizer,
    pub policies: PolicySet,
    pub entities: Entities,
}

/// Authorization request model for MVP
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    /// Unique request identifier for tracing
    #[schema(example = "req-12345")]
    pub request_id: String,

    /// Principal entity (who is making the request)
    pub principal: serde_json::Value,

    /// Action being performed
    #[schema(example = "read")]
    pub action: String,

    /// Resource being accessed
    pub resource: serde_json::Value,

    /// Request context (additional attributes)
    pub context: serde_json::Value,
}

/// Authorization response model for MVP
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeResponse {
    /// Authorization decision (Allow or Deny)
    #[schema(example = "Allow")]
    pub decision: String,
}

/// Policy conflict information for MVP
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyConflict {
    /// ID of the first policy in conflict
    #[schema(example = "policy-1")]
    pub policy_id: String,

    /// ID of the conflicting policy
    #[schema(example = "policy-2")]
    pub conflicting_policy: String,

    /// Type of conflict detected
    #[schema(example = "overlapping_conditions")]
    pub conflict_type: String,
}
