//! Enhanced security validation for MVP policy service

use crate::errors::{AppError, AuthorizationError};
use std::collections::HashMap;
use tracing::{warn, debug, error, info};
use url::Url;

/// Security configuration constants for MVP
const MAX_REQUEST_ID_LENGTH: usize = 128;
const MAX_ENTITY_ID_LENGTH: usize = 512;
const MAX_ACTION_LENGTH: usize = 256;
const MAX_JSON_DEPTH: usize = 10;
const MAX_JSON_SIZE: usize = 1024 * 1024; // 1MB
const MAX_CONTEXT_KEYS: usize = 50;

/// Enhanced error context for security incidents
#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub request_id: String,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub threat_level: ThreatLevel,
    pub violation_type: ViolationType,
}

#[derive(Debug, Clone)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    InvalidInput,
    SuspiciousPattern,
    PayloadTooLarge,
    StructureAbuse,
    InjectionAttempt,
}

impl SecurityContext {
    pub fn new(request_id: String) -> Self {
        Self {
            request_id,
            client_ip: None,
            user_agent: None,
            threat_level: ThreatLevel::Low,
            violation_type: ViolationType::InvalidInput,
        }
    }
    
    pub fn with_threat_level(mut self, level: ThreatLevel) -> Self {
        self.threat_level = level;
        self
    }
    
    pub fn with_violation_type(mut self, violation: ViolationType) -> Self {
        self.violation_type = violation;
        self
    }
    
    pub fn with_client_info(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.client_ip = ip;
        self.user_agent = user_agent;
        self
    }
    
    /// Log security incident with full context
    pub fn log_security_incident(&self, message: &str) {
        match self.threat_level {
            ThreatLevel::Critical | ThreatLevel::High => {
                error!(
                    request_id = %self.request_id,
                    client_ip = ?self.client_ip,
                    user_agent = ?self.user_agent,
                    threat_level = ?self.threat_level,
                    violation_type = ?self.violation_type,
                    message = %message,
                    "SECURITY INCIDENT: High-level threat detected"
                );
            }
            ThreatLevel::Medium => {
                warn!(
                    request_id = %self.request_id,
                    client_ip = ?self.client_ip,
                    threat_level = ?self.threat_level,
                    violation_type = ?self.violation_type,
                    message = %message,
                    "Security violation detected"
                );
            }
            ThreatLevel::Low => {
                info!(
                    request_id = %self.request_id,
                    violation_type = ?self.violation_type,
                    message = %message,
                    "Low-level security issue detected"
                );
            }
        }
    }
}

/// Validate input data for security and correctness with enhanced security context
pub fn validate_authorization_input(
    body: &crate::models::AuthorizeRequest,
) -> Result<(), AuthorizationError> {
    validate_authorization_input_with_context(body, None, None)
}

/// Enhanced validation with security context for MVP
pub fn validate_authorization_input_with_context(
    body: &crate::models::AuthorizeRequest,
    client_ip: Option<String>,
    user_agent: Option<String>,
) -> Result<(), AuthorizationError> {
    let mut security_ctx = SecurityContext::new(body.request_id.clone())
        .with_client_info(client_ip, user_agent);

    // Enhanced request ID validation
    if let Err(e) = validate_request_id(&body.request_id) {
        security_ctx = security_ctx.with_violation_type(ViolationType::InvalidInput);
        security_ctx.log_security_incident("Invalid request ID format");
        return Err(e);
    }
    
    // Enhanced action validation with threat detection
    let action = body.action.trim();
    if let Err(e) = validate_action_string(action) {
        // Check for high-risk injection patterns
        if action.to_lowercase().contains("script") || 
           action.to_lowercase().contains("eval") ||
           action.to_lowercase().contains("exec") {
            security_ctx = security_ctx
                .with_threat_level(ThreatLevel::High)
                .with_violation_type(ViolationType::InjectionAttempt);
        } else {
            security_ctx = security_ctx.with_violation_type(ViolationType::InvalidInput);
        }
        security_ctx.log_security_incident(&format!("Invalid action: {}", action));
        return Err(e);
    }

    // Enhanced entity validation
    if let Err(e) = validate_entity_structure(&body.principal, "principal") {
        security_ctx = security_ctx.with_violation_type(ViolationType::StructureAbuse);
        security_ctx.log_security_incident("Invalid principal structure");
        return Err(e);
    }
    
    if let Err(e) = validate_entity_structure(&body.resource, "resource") {
        security_ctx = security_ctx.with_violation_type(ViolationType::StructureAbuse);
        security_ctx.log_security_incident("Invalid resource structure");
        return Err(e);
    }
    
    // Enhanced context validation
    if let Err(e) = validate_context_structure(&body.context) {
        security_ctx = security_ctx.with_violation_type(ViolationType::StructureAbuse);
        security_ctx.log_security_incident("Invalid context structure");
        return Err(e);
    }

    // JSON structure validation with size monitoring
    for (field_name, field_value) in [
        ("principal", &body.principal),
        ("resource", &body.resource),
        ("context", &body.context),
    ] {
        if let Err(e) = validate_json_structure(field_value, field_name) {
            // Check if it's a payload size attack
            let json_str = serde_json::to_string(field_value).unwrap_or_default();
            if json_str.len() > MAX_JSON_SIZE / 2 {
                security_ctx = security_ctx
                    .with_threat_level(ThreatLevel::Medium)
                    .with_violation_type(ViolationType::PayloadTooLarge);
            } else {
                security_ctx = security_ctx.with_violation_type(ViolationType::StructureAbuse);
            }
            security_ctx.log_security_incident(&format!("Invalid {} structure", field_name));
            return Err(e);
        }
    }

    debug!(
        request_id = %body.request_id,
        action = %body.action,
        "Authorization input validation passed with security context"
    );

    Ok(())
}

/// Validate request ID format and security
fn validate_request_id(request_id: &str) -> Result<(), AuthorizationError> {
    if request_id.is_empty() {
        warn!("Empty request ID provided");
        return Err(AuthorizationError::RequestFailed {
            reason: "Request ID cannot be empty".to_string(),
        });
    }
    
    if request_id.len() > MAX_REQUEST_ID_LENGTH {
        warn!(request_id_len = request_id.len(), "Request ID too long");
        return Err(AuthorizationError::RequestFailed {
            reason: "Request ID too long".to_string(),
        });
    }
    
    // Check for control characters and potential injection attacks
    if request_id.chars().any(|c| c.is_control()) {
        warn!("Request ID contains control characters");
        return Err(AuthorizationError::RequestFailed {
            reason: "Request ID contains invalid characters".to_string(),
        });
    }
    
    Ok(())
}

/// Validate action string with enhanced security checks
fn validate_action_string(action: &str) -> Result<(), AuthorizationError> {
    if action.is_empty() {
        warn!("Empty action provided");
        return Err(AuthorizationError::InvalidAction {
            action: "(empty)".to_string(),
        });
    }

    // Check for potentially dangerous characters in action
    if action.contains('\0') || action.chars().any(|c| c.is_control() && c != ' ') {
        warn!(action = %action, "Action contains control characters");
        return Err(AuthorizationError::InvalidAction {
            action: "contains control characters".to_string(),
        });
    }

    // Check for potential injection patterns
    let suspicious_patterns = [
        "drop", "delete", "insert", "update", "select", "union", "exec", "script"
    ];
    let action_lower = action.to_lowercase();
    for pattern in &suspicious_patterns {
        if action_lower.contains(pattern) {
            warn!(action = %action, pattern = %pattern, "Suspicious pattern detected in action");
        }
    }

    // Check action length limits
    if action.len() > MAX_ACTION_LENGTH {
        warn!(action_len = action.len(), "Action too long");
        return Err(AuthorizationError::InvalidAction {
            action: "action too long".to_string(),
        });
    }

    // Validate UTF-8 encoding
    if !action.is_ascii() {
        // Allow Unicode but log for monitoring
        debug!(action = %action, "Non-ASCII action received");
    }

    Ok(())
}

/// Validate entity structure with enhanced security checks
fn validate_entity_structure(entity: &serde_json::Value, entity_type: &str) -> Result<(), AuthorizationError> {
    let obj = entity.as_object().ok_or_else(|| {
        warn!(entity_type = %entity_type, "Entity is not a JSON object");
        AuthorizationError::RequestFailed {
            reason: format!("{} must be a JSON object", entity_type),
        }
    })?;
    
    // Validate required fields
    let entity_id = obj.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
        warn!(entity_type = %entity_type, "Entity missing id field");
        AuthorizationError::RequestFailed {
            reason: format!("{} missing required 'id' field", entity_type),
        }
    })?;
    
    let type_field = obj.get("type").and_then(|v| v.as_str()).ok_or_else(|| {
        warn!(entity_type = %entity_type, "Entity missing type field");
        AuthorizationError::RequestFailed {
            reason: format!("{} missing required 'type' field", entity_type),
        }
    })?;
    
    // Validate ID length
    if entity_id.len() > MAX_ENTITY_ID_LENGTH {
        warn!(entity_type = %entity_type, id_len = entity_id.len(), "Entity ID too long");
        return Err(AuthorizationError::RequestFailed {
            reason: format!("{} ID too long", entity_type),
        });
    }
    
    // Check for control characters in ID
    if entity_id.chars().any(|c| c.is_control()) {
        warn!(entity_type = %entity_type, entity_id = %entity_id, "Entity ID contains control characters");
        return Err(AuthorizationError::RequestFailed {
            reason: format!("{} ID contains invalid characters", entity_type),
        });
    }
    
    // Validate type field
    if type_field.is_empty() || type_field.len() > 64 {
        warn!(entity_type = %entity_type, type_len = type_field.len(), "Invalid entity type length");
        return Err(AuthorizationError::RequestFailed {
            reason: format!("{} type invalid", entity_type),
        });
    }
    
    Ok(())
}

/// Validate context structure with enhanced security
fn validate_context_structure(context: &serde_json::Value) -> Result<(), AuthorizationError> {
    let obj = context.as_object().ok_or_else(|| {
        warn!("Context is not a JSON object");
        AuthorizationError::InvalidContext {
            reason: "Context must be a JSON object".to_string(),
        }
    })?;
    
    // Limit number of context keys to prevent DoS
    if obj.len() > MAX_CONTEXT_KEYS {
        warn!(context_keys = obj.len(), "Too many context keys");
        return Err(AuthorizationError::InvalidContext {
            reason: "Too many context keys".to_string(),
        });
    }
    
    // Validate each context key and value
    for (key, value) in obj {
        // Check key format
        if key.is_empty() || key.len() > 128 {
            warn!(key = %key, "Invalid context key length");
            return Err(AuthorizationError::InvalidContext {
                reason: "Invalid context key format".to_string(),
            });
        }
        
        if key.chars().any(|c| c.is_control()) {
            warn!(key = %key, "Context key contains control characters");
            return Err(AuthorizationError::InvalidContext {
                reason: "Context key contains invalid characters".to_string(),
            });
        }
        
        // Check value size if it's a string
        if let Some(str_value) = value.as_str() {
            if str_value.len() > 4096 {
                warn!(key = %key, value_len = str_value.len(), "Context value too long");
                return Err(AuthorizationError::InvalidContext {
                    reason: "Context value too long".to_string(),
                });
            }
        }
    }
    
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
            warn!(
                field_name = %field_name, 
                depth = current_depth, 
                "JSON structure too deeply nested"
            );
            return Err(AuthorizationError::RequestFailed {
                reason: format!("{} JSON structure too deeply nested", field_name),
            });
        }

        match value {
            serde_json::Value::Object(obj) => {
                // Limit object key count to prevent DoS
                if obj.len() > 1000 {
                    warn!(
                        field_name = %field_name, 
                        key_count = obj.len(), 
                        "JSON object has too many keys"
                    );
                    return Err(AuthorizationError::RequestFailed {
                        reason: format!("{} JSON object too large", field_name),
                    });
                }
                
                for (key, val) in obj {
                    // Validate key format
                    if key.len() > 256 {
                        warn!(field_name = %field_name, key_len = key.len(), "JSON key too long");
                        return Err(AuthorizationError::RequestFailed {
                            reason: format!("{} JSON key too long", field_name),
                        });
                    }
                    check_depth(val, field_name, current_depth + 1, max_depth)?;
                }
            }
            serde_json::Value::Array(arr) => {
                // Limit array size to prevent DoS
                if arr.len() > 1000 {
                    warn!(
                        field_name = %field_name, 
                        array_len = arr.len(), 
                        "JSON array too large"
                    );
                    return Err(AuthorizationError::RequestFailed {
                        reason: format!("{} JSON array too large", field_name),
                    });
                }
                
                for val in arr {
                    check_depth(val, field_name, current_depth + 1, max_depth)?;
                }
            }
            serde_json::Value::String(s) => {
                // Validate string length and content
                if s.len() > 16384 { // 16KB max per string
                    warn!(field_name = %field_name, str_len = s.len(), "JSON string too long");
                    return Err(AuthorizationError::RequestFailed {
                        reason: format!("{} JSON string too long", field_name),
                    });
                }
                
                // Check for suspicious patterns in strings
                if s.contains('\0') || s.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
                    warn!(field_name = %field_name, "JSON string contains control characters");
                    return Err(AuthorizationError::RequestFailed {
                        reason: format!("{} JSON string contains invalid characters", field_name),
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }

    check_depth(value, field_name, 0, MAX_JSON_DEPTH)?;

    // Check approximate size (more accurate estimate)
    let json_str = serde_json::to_string(value).map_err(|e| {
        warn!(field_name = %field_name, error = %e, "Failed to serialize JSON");
        AuthorizationError::RequestFailed {
            reason: format!("Failed to serialize {}: {}", field_name, e),
        }
    })?;

    if json_str.len() > MAX_JSON_SIZE {
        warn!(
            field_name = %field_name, 
            size = json_str.len(), 
            max_size = MAX_JSON_SIZE,
            "JSON payload too large"
        );
        return Err(AuthorizationError::RequestFailed {
            reason: format!("{} JSON payload too large", field_name),
        });
    }

    Ok(())
}

/// Additional security utilities for input sanitization
pub mod security_utils {
    use super::*;
    
    /// Sanitize string input by removing dangerous characters
    pub fn sanitize_string(input: &str) -> String {
        input
            .chars()
            .filter(|&c| !c.is_control() || c == ' ' || c == '\t' || c == '\n' || c == '\r')
            .collect()
    }
    
    /// Check if string contains potentially dangerous patterns
    pub fn contains_suspicious_patterns(input: &str) -> bool {
        let patterns = [
            "<script", "javascript:", "data:", "vbscript:", "onload=", "onerror=",
            "eval(", "setTimeout(", "setInterval(",
        ];
        
        let input_lower = input.to_lowercase();
        patterns.iter().any(|pattern| input_lower.contains(pattern))
    }
    
    /// Validate IPv4/IPv6 address format
    pub fn is_valid_ip_address(addr: &str) -> bool {
        addr.parse::<std::net::IpAddr>().is_ok()
    }
    
    /// Check if URL is safe (no dangerous schemes)
    pub fn is_safe_url(url: &str) -> bool {
        if let Ok(parsed) = Url::parse(url) {
            matches!(parsed.scheme(), "http" | "https" | "ftp" | "ftps")
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use crate::models::AuthorizeRequest;

    #[test]
    fn test_validate_request_id() {
        // Valid request ID
        assert!(validate_request_id("req-12345").is_ok());
        
        // Empty request ID
        assert!(validate_request_id("").is_err());
        
        // Too long request ID
        let long_id = "a".repeat(200);
        assert!(validate_request_id(&long_id).is_err());
        
        // Control characters
        assert!(validate_request_id("req\x00123").is_err());
    }

    #[test]
    fn test_validate_action_string() {
        // Valid actions
        assert!(validate_action_string("Document::read").is_ok());
        assert!(validate_action_string("read").is_ok());
        
        // Empty action
        assert!(validate_action_string("").is_err());
        
        // Control characters
        assert!(validate_action_string("read\x00").is_err());
        
        // Too long action
        let long_action = "a".repeat(300);
        assert!(validate_action_string(&long_action).is_err());
    }

    #[test]
    fn test_validate_entity_structure() {
        // Valid entity
        let entity = json!({
            "type": "User",
            "id": "alice"
        });
        assert!(validate_entity_structure(&entity, "principal").is_ok());
        
        // Missing type
        let entity = json!({
            "id": "alice"
        });
        assert!(validate_entity_structure(&entity, "principal").is_err());
        
        // Missing id
        let entity = json!({
            "type": "User"
        });
        assert!(validate_entity_structure(&entity, "principal").is_err());
        
        // Too long ID
        let entity = json!({
            "type": "User",
            "id": "a".repeat(600)
        });
        assert!(validate_entity_structure(&entity, "principal").is_err());
    }

    #[test]
    fn test_security_utils() {
        use security_utils::*;
        
        // Sanitize string
        let input = "Hello\x00World\x01!";
        let sanitized = sanitize_string(input);
        assert_eq!(sanitized, "HelloWorld!");
        
        // Suspicious patterns
        assert!(contains_suspicious_patterns("<script>alert('xss')</script>"));
        assert!(contains_suspicious_patterns("javascript:alert('xss')"));
        assert!(!contains_suspicious_patterns("normal text"));
        
        // IP validation
        assert!(is_valid_ip_address("192.168.1.1"));
        assert!(is_valid_ip_address("::1"));
        assert!(!is_valid_ip_address("not.an.ip"));
        
        // URL validation
        assert!(is_safe_url("https://example.com"));
        assert!(is_safe_url("http://example.com"));
        assert!(!is_safe_url("javascript:alert('xss')"));
        assert!(!is_safe_url("data:text/html,<script>alert('xss')</script>"));
    }
}