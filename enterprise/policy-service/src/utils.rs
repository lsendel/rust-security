//! Utility functions for MVP policy service

use serde_json::Value;

/// Extract entity type from JSON value
pub fn extract_entity_type(entity: &Value) -> Option<String> {
    entity
        .as_object()?
        .get("type")?
        .as_str()
        .map(|s| s.to_string())
}

/// Extract action type from action string
pub fn extract_action_type(action: &str) -> String {
    // For MVP, simple action parsing
    if let Some(pos) = action.find("::") {
        action.get(pos + 2..).unwrap_or("unknown").to_string()
    } else {
        action.to_string()
    }
}

/// Extract client ID from context JSON
pub fn extract_client_id_from_context(context: &Value) -> Option<String> {
    context
        .as_object()?
        .get("client_id")?
        .as_str()
        .map(|s| s.to_string())
}

/// Parse entity from JSON value to Cedar EntityUid
pub fn parse_entity(entity: &Value) -> Result<cedar_policy::EntityUid, cedar_policy::ParseErrors> {
    cedar_policy::EntityUid::from_json(entity.clone())
}

/// Validate entity format for MVP
pub fn validate_entity_format(entity: &Value) -> bool {
    if let Some(obj) = entity.as_object() {
        obj.contains_key("type") && obj.contains_key("id")
    } else {
        false
    }
}

/// Extract IP address from various header formats
pub fn extract_client_ip(headers: &axum::http::HeaderMap) -> Option<String> {
    // Try X-Forwarded-For first
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // Take the first IP in the chain
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return Some(first_ip.trim().to_string());
            }
        }
    }
    
    // Try X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }
    
    // Try other common headers
    for header in ["cf-connecting-ip", "x-client-ip", "x-forwarded"] {
        if let Some(ip_header) = headers.get(header) {
            if let Ok(ip_str) = ip_header.to_str() {
                return Some(ip_str.to_string());
            }
        }
    }
    
    None
}

/// Sanitize string for logging (remove control characters)
pub fn sanitize_for_logging(input: &str) -> String {
    input
        .chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_entity_type() {
        let entity = json!({
            "type": "User",
            "id": "alice"
        });
        
        assert_eq!(extract_entity_type(&entity), Some("User".to_string()));
        
        let invalid_entity = json!({
            "id": "alice"
        });
        
        assert_eq!(extract_entity_type(&invalid_entity), None);
    }

    #[test]
    fn test_extract_action_type() {
        assert_eq!(extract_action_type("Document::read"), "read");
        assert_eq!(extract_action_type("read"), "read");
        assert_eq!(extract_action_type("User::update_profile"), "update_profile");
    }

    #[test]
    fn test_extract_client_id_from_context() {
        let context = json!({
            "client_id": "web-app-v1.2",
            "timestamp": "2024-01-15T10:30:00Z"
        });
        
        assert_eq!(
            extract_client_id_from_context(&context), 
            Some("web-app-v1.2".to_string())
        );
        
        let context_no_client = json!({
            "timestamp": "2024-01-15T10:30:00Z"
        });
        
        assert_eq!(extract_client_id_from_context(&context_no_client), None);
    }

    #[test]
    fn test_validate_entity_format() {
        let valid_entity = json!({
            "type": "User",
            "id": "alice"
        });
        
        assert!(validate_entity_format(&valid_entity));
        
        let invalid_entity = json!({
            "id": "alice"
        });
        
        assert!(!validate_entity_format(&invalid_entity));
    }

    #[test]
    fn test_sanitize_for_logging() {
        let input = "Hello\x00World\x01!";
        let sanitized = sanitize_for_logging(input);
        assert_eq!(sanitized, "Hello_World_!");
        
        let normal_input = "Hello World!";
        let sanitized_normal = sanitize_for_logging(normal_input);
        assert_eq!(sanitized_normal, "Hello World!");
    }
}