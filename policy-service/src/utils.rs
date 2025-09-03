//! Utility functions for entity parsing and data extraction

use cedar_policy;

/// Parse entity from JSON value
pub fn parse_entity(
    v: &serde_json::Value,
) -> Result<cedar_policy::EntityUid, crate::errors::AuthorizationError> {
    // Clone is necessary here since EntityUid::from_json takes ownership
    cedar_policy::EntityUid::from_json(v.clone()).map_err(|e| {
        crate::errors::AuthorizationError::RequestFailed {
            reason: format!("Invalid entity format: {e}"),
        }
    })
}

/// Extract entity type from JSON value for metrics
pub fn extract_entity_type(v: &serde_json::Value) -> Option<String> {
    v.get("type")
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
}

/// Extract action type from action string
pub fn extract_action_type(action: &str) -> String {
    // Extract the action type from action format like "Document::read" or "read"
    // Use more efficient string handling to avoid unnecessary allocations
    if let Some(pos) = action.find("::") {
        // Skip the "::" and take the rest
        if pos + 2 < action.len() {
            action[pos + 2..].to_string()
        } else {
            action.to_string()
        }
    } else {
        action.to_string()
    }
}

/// Extract client_id from context JSON. Supports either {"client_id": "..."} or {"client": {"id": "..."}}
pub fn extract_client_id_from_context(ctx: &serde_json::Value) -> Option<String> {
    // Try direct client_id field first
    if let Some(client_id) = ctx.get("client_id").and_then(|v| v.as_str()) {
        let trimmed = client_id.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    // Try nested client.id field
    if let Some(client_obj) = ctx.get("client").and_then(|v| v.as_object()) {
        if let Some(client_id) = client_obj.get("id").and_then(|v| v.as_str()) {
            let trimmed = client_id.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    None
}
