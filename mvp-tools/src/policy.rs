//! Policy validation module for MVP tools
//!
//! This module provides Cedar policy validation and authorization support
//! integrated into the MVP architecture.

use crate::validation::{SecurityContext, ValidationError};
use serde_json::Value;

/// Authorization request structure for MVP
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub request_id: String,
    pub principal: Value,
    pub action: String,
    pub resource: Value,
    pub context: Value,
}

/// Authorization response structure for MVP
#[derive(Debug, Clone)]
pub struct AuthorizationResponse {
    pub decision: String,
    pub request_id: String,
}

/// Policy validation result
#[derive(Debug)]
pub enum PolicyValidationResult {
    Allow { reason: String },
    Deny { reason: String },
    Error { error: String },
}

/// MVP Policy Engine - simplified version for essential policy validation
pub struct MvpPolicyEngine {
    policies: Vec<String>,
    entities: Vec<String>,
}

impl MvpPolicyEngine {
    /// Create a new MVP policy engine with default policies
    pub fn new() -> Self {
        Self {
            policies: Self::default_policies(),
            entities: Self::default_entities(),
        }
    }

    /// Default policies for MVP deployment
    fn default_policies() -> Vec<String> {
        vec![
            // Allow authenticated users to perform read operations
            "permit(principal, action == Action::\"read\", resource) when { principal has authenticated && principal.authenticated == true };".to_string(),

            // Allow admins to perform any action
            "permit(principal, action, resource) when { principal has role && principal.role == \"admin\" };".to_string(),

            // Allow users to access their own resources
            "permit(principal, action == Action::\"read\", resource) when { principal has authenticated && principal.authenticated == true && resource has owner && principal.id == resource.owner };".to_string(),

            // Deny access to sensitive resources without proper clearance
            "forbid(principal, action, resource) when { resource has sensitive && resource.sensitive == true && !(principal has clearance && principal.clearance == \"high\") };".to_string(),
        ]
    }

    /// Default entities for MVP deployment
    fn default_entities() -> Vec<String> {
        vec![
            r#"{"uid": {"type": "User", "id": "alice"}, "attrs": {"authenticated": true, "role": "user"}, "parents": []}"#.to_string(),
            r#"{"uid": {"type": "User", "id": "admin"}, "attrs": {"authenticated": true, "role": "admin"}, "parents": []}"#.to_string(),
            r#"{"uid": {"type": "Action", "id": "read"}, "attrs": {}, "parents": []}"#.to_string(),
            r#"{"uid": {"type": "Action", "id": "write"}, "attrs": {}, "parents": []}"#.to_string(),
            r#"{"uid": {"type": "Resource", "id": "public-doc"}, "attrs": {"sensitive": false}, "parents": []}"#.to_string(),
            r#"{"uid": {"type": "Resource", "id": "private-doc"}, "attrs": {"sensitive": true}, "parents": []}"#.to_string(),
        ]
    }

    /// Validate authorization request with enhanced security
    pub fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<AuthorizationResponse, ValidationError> {
        let _security_ctx = SecurityContext::new().with_request_id(request.request_id.clone());

        // Validate request components with enhanced security
        crate::validation::validate_request_id(&request.request_id)?;
        crate::validation::validate_action_string(&request.action)?;
        crate::validation::validate_entity_structure(&request.principal, "principal")?;
        crate::validation::validate_entity_structure(&request.resource, "resource")?;
        crate::validation::validate_json_structure(&request.context, "context")?;

        // For MVP, implement simplified policy evaluation
        let decision = self.evaluate_policies(request);

        // Log authorization decision
        println!(
            "AUTHORIZATION: {} | Action: {} | Decision: {} | Request: {}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            request.action,
            decision.get_decision(),
            request.request_id
        );

        Ok(AuthorizationResponse {
            decision: decision.get_decision().to_string(),
            request_id: request.request_id.clone(),
        })
    }

    /// Simplified policy evaluation for MVP
    fn evaluate_policies(&self, request: &AuthorizationRequest) -> PolicyValidationResult {
        // Extract principal information
        let principal_id = request
            .principal
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let principal_authenticated = request
            .principal
            .get("attrs")
            .and_then(|attrs| attrs.get("authenticated"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let principal_role = request
            .principal
            .get("attrs")
            .and_then(|attrs| attrs.get("role"))
            .and_then(|v| v.as_str())
            .unwrap_or("guest");

        // Extract resource information
        let resource_sensitive = request
            .resource
            .get("attrs")
            .and_then(|attrs| attrs.get("sensitive"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let resource_owner = request
            .resource
            .get("attrs")
            .and_then(|attrs| attrs.get("owner"))
            .and_then(|v| v.as_str());

        // MVP policy evaluation logic

        // Rule 1: Admin can do anything
        if principal_role == "admin" {
            return PolicyValidationResult::Allow {
                reason: "Admin role has full access".to_string(),
            };
        }

        // Rule 2: Authenticated users can read non-sensitive resources
        if principal_authenticated && request.action == "read" && !resource_sensitive {
            return PolicyValidationResult::Allow {
                reason: "Authenticated user reading non-sensitive resource".to_string(),
            };
        }

        // Rule 3: Users can access their own resources
        if principal_authenticated && request.action == "read" {
            if let Some(owner) = resource_owner {
                if owner == principal_id {
                    return PolicyValidationResult::Allow {
                        reason: "User accessing own resource".to_string(),
                    };
                }
            }
        }

        // Rule 4: Deny sensitive resources without proper clearance
        if resource_sensitive {
            let has_clearance = request
                .principal
                .get("attrs")
                .and_then(|attrs| attrs.get("clearance"))
                .and_then(|v| v.as_str())
                .map(|clearance| clearance == "high")
                .unwrap_or(false);

            if !has_clearance {
                return PolicyValidationResult::Deny {
                    reason: "Access to sensitive resource denied without proper clearance"
                        .to_string(),
                };
            }
        }

        // Default deny
        PolicyValidationResult::Deny {
            reason: "No matching policy found".to_string(),
        }
    }

    /// Add custom policy for runtime configuration
    pub fn add_policy(&mut self, policy: String) {
        self.policies.push(policy);
    }

    /// Add custom entity for runtime configuration
    pub fn add_entity(&mut self, entity: String) {
        self.entities.push(entity);
    }

    /// Get policy count for metrics
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Get entity count for metrics
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }
}

impl PolicyValidationResult {
    fn get_decision(&self) -> &str {
        match self {
            PolicyValidationResult::Allow { .. } => "Allow",
            PolicyValidationResult::Deny { .. } => "Deny",
            PolicyValidationResult::Error { .. } => "Error",
        }
    }
}

impl Default for MvpPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy conflict detection for MVP
pub fn detect_policy_conflicts(policies: &[String]) -> Vec<String> {
    let mut conflicts = Vec::new();

    // For MVP, implement basic conflict detection
    for (i, policy1) in policies.iter().enumerate() {
        for (j, policy2) in policies.iter().enumerate() {
            if i != j {
                // Simple conflict detection - check for opposing permit/forbid patterns
                if (policy1.contains("permit") && policy2.contains("forbid"))
                    || (policy1.contains("forbid") && policy2.contains("permit"))
                {
                    // Further analysis would be needed for real conflict detection
                    if policies_potentially_conflict(policy1, policy2) {
                        conflicts.push(format!(
                            "Potential conflict between policy {} and policy {}",
                            i + 1,
                            j + 1
                        ));
                    }
                }
            }
        }
    }

    conflicts
}

/// Basic conflict detection helper
fn policies_potentially_conflict(policy1: &str, policy2: &str) -> bool {
    // Very basic pattern matching for MVP
    // In a full implementation, this would parse the Cedar AST

    // Check if both policies might apply to similar resources/actions
    let policy1_words: std::collections::HashSet<_> = policy1.split_whitespace().collect();
    let policy2_words: std::collections::HashSet<_> = policy2.split_whitespace().collect();

    // If they share significant keywords, they might conflict
    let overlap: Vec<_> = policy1_words.intersection(&policy2_words).collect();
    overlap.len() > 5 // Arbitrary threshold for MVP
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_mvp_policy_engine_creation() {
        let engine = MvpPolicyEngine::new();
        assert!(engine.policy_count() > 0);
        assert!(engine.entity_count() > 0);
    }

    #[test]
    fn test_admin_access() {
        let engine = MvpPolicyEngine::new();
        let request = AuthorizationRequest {
            request_id: "test-1".to_string(),
            principal: json!({
                "type": "User",
                "id": "admin",
                "attrs": {
                    "authenticated": true,
                    "role": "admin"
                }
            }),
            action: "write".to_string(),
            resource: json!({
                "type": "Resource",
                "id": "sensitive-doc",
                "attrs": {
                    "sensitive": true
                }
            }),
            context: json!({}),
        };

        let result = engine.authorize(&request).unwrap();
        assert_eq!(result.decision, "Allow");
    }

    #[test]
    fn test_authenticated_user_read_access() {
        let engine = MvpPolicyEngine::new();
        let request = AuthorizationRequest {
            request_id: "test-2".to_string(),
            principal: json!({
                "type": "User",
                "id": "alice",
                "attrs": {
                    "authenticated": true,
                    "role": "user"
                }
            }),
            action: "read".to_string(),
            resource: json!({
                "type": "Resource",
                "id": "public-doc",
                "attrs": {
                    "sensitive": false
                }
            }),
            context: json!({}),
        };

        let result = engine.authorize(&request).unwrap();
        assert_eq!(result.decision, "Allow");
    }

    #[test]
    fn test_sensitive_resource_denial() {
        let engine = MvpPolicyEngine::new();
        let request = AuthorizationRequest {
            request_id: "test-3".to_string(),
            principal: json!({
                "type": "User",
                "id": "alice",
                "attrs": {
                    "authenticated": true,
                    "role": "user"
                    // No clearance
                }
            }),
            action: "read".to_string(),
            resource: json!({
                "type": "Resource",
                "id": "sensitive-doc",
                "attrs": {
                    "sensitive": true
                }
            }),
            context: json!({}),
        };

        let result = engine.authorize(&request).unwrap();
        assert_eq!(result.decision, "Deny");
    }

    #[test]
    fn test_policy_conflict_detection() {
        let policies = vec![
            "permit(principal, action, resource) when { resource.public == true };".to_string(),
            "forbid(principal, action, resource) when { resource.public == true };".to_string(),
        ];

        let conflicts = detect_policy_conflicts(&policies);
        assert!(!conflicts.is_empty());
    }
}
