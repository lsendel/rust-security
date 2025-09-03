//! Input validation and sanitization functions

use crate::errors::{AppError, AuthorizationError};

/// Validate input data for security and correctness
pub fn validate_authorization_input(
    body: &crate::models::AuthorizeRequest,
) -> Result<(), AuthorizationError> {
    // Validate action format and content
    let action = body.action.trim();
    if action.is_empty() {
        return Err(AuthorizationError::InvalidAction {
            action: "(empty)".to_string(),
        });
    }

    // Check for potentially dangerous characters in action
    if action.contains('\0') || action.chars().any(|c| c.is_control() && c != ' ') {
        return Err(AuthorizationError::InvalidAction {
            action: "contains control characters".to_string(),
        });
    }

    // Validate action format (should contain separator like "domain:action")
    if !action.contains(':') {
        return Err(AuthorizationError::InvalidAction {
            action: "missing domain separator (:)".to_string(),
        });
    }

    // Check action length limits
    if action.len() > 256 {
        return Err(AuthorizationError::InvalidAction {
            action: "action too long".to_string(),
        });
    }

    // Validate JSON structure depth and size
    validate_json_structure(&body.principal, "principal")?;
    validate_json_structure(&body.resource, "resource")?;
    validate_json_structure(&body.context, "context")?;

    Ok(())
}

/// Validate JSON structure for security
pub fn validate_json_structure(
    value: &serde_json::Value,
    field_name: &str,
) -> Result<(), AuthorizationError> {
    // Check for excessively nested structures (potential DoS)
    fn check_depth(
        value: &serde_json::Value,
        field_name: &str,
        current_depth: usize,
        max_depth: usize,
    ) -> Result<(), AuthorizationError> {
        if current_depth > max_depth {
            return Err(AuthorizationError::RequestFailed {
                reason: format!("{} JSON structure too deeply nested", field_name),
            });
        }

        match value {
            serde_json::Value::Object(obj) => {
                for (_key, val) in obj {
                    check_depth(val, field_name, current_depth + 1, max_depth)?;
                }
            }
            serde_json::Value::Array(arr) => {
                for val in arr {
                    check_depth(val, field_name, current_depth + 1, max_depth)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    check_depth(value, field_name, 0, 10)?; // Max depth of 10

    // Check approximate size (rough estimate)
    let json_str = serde_json::to_string(value).map_err(|e| AuthorizationError::RequestFailed {
        reason: format!("Failed to serialize {}: {}", field_name, e),
    })?;

    if json_str.len() > 1024 * 1024 {
        // 1MB limit
        return Err(AuthorizationError::RequestFailed {
            reason: format!("{} JSON payload too large", field_name),
        });
    }

    Ok(())
}
