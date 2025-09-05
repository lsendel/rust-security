//! Enhanced security validation for MVP tools
//!
//! This module provides enterprise-grade input validation and security features
//! integrated into the MVP architecture for Auth-as-a-Service.

use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;

/// Security configuration constants for MVP
const MAX_REQUEST_ID_LENGTH: usize = 128;
const MAX_ENTITY_ID_LENGTH: usize = 512;
const MAX_ACTION_LENGTH: usize = 256;
const MAX_JSON_DEPTH: usize = 10;
const MAX_JSON_SIZE: usize = 1024 * 1024; // 1MB
const MAX_STRING_LENGTH: usize = 16384; // 16KB

/// Validation error types for MVP tools
#[derive(Debug)]
pub enum ValidationError {
    InvalidInput {
        field: String,
        reason: String,
    },
    SecurityViolation {
        threat_level: ThreatLevel,
        details: String,
    },
    PayloadTooLarge {
        field: String,
        size: usize,
        max_size: usize,
    },
    StructureAbuse {
        field: String,
        details: String,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidInput { field, reason } => {
                write!(f, "Invalid input in {}: {}", field, reason)
            }
            ValidationError::SecurityViolation {
                threat_level,
                details,
            } => {
                write!(f, "Security violation ({:?}): {}", threat_level, details)
            }
            ValidationError::PayloadTooLarge {
                field,
                size,
                max_size,
            } => {
                write!(
                    f,
                    "Payload too large in {}: {} bytes (max {})",
                    field, size, max_size
                )
            }
            ValidationError::StructureAbuse { field, details } => {
                write!(f, "Structure abuse in {}: {}", field, details)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Threat level classification for security incidents
#[derive(Debug, Clone)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Violation type classification
#[derive(Debug, Clone)]
pub enum ViolationType {
    InvalidInput,
    SuspiciousPattern,
    PayloadTooLarge,
    StructureAbuse,
    InjectionAttempt,
}

/// Security context for validation incidents
#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub request_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub threat_level: ThreatLevel,
    pub violation_type: ViolationType,
}

impl SecurityContext {
    pub fn new() -> Self {
        Self {
            request_id: None,
            client_ip: None,
            user_agent: None,
            threat_level: ThreatLevel::Low,
            violation_type: ViolationType::InvalidInput,
        }
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_client_info(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.client_ip = ip;
        self.user_agent = user_agent;
        self
    }

    pub fn with_threat_level(mut self, level: ThreatLevel) -> Self {
        self.threat_level = level;
        self
    }

    pub fn with_violation_type(mut self, violation: ViolationType) -> Self {
        self.violation_type = violation;
        self
    }

    /// Log security incident with full context
    pub fn log_security_incident(&self, message: &str) {
        match self.threat_level {
            ThreatLevel::Critical | ThreatLevel::High => {
                println!(
                    "SECURITY ALERT: {} | Request: {:?} | IP: {:?} | UA: {:?} | Threat: {:?} | Type: {:?}",
                    message, self.request_id, self.client_ip, self.user_agent,
                    self.threat_level, self.violation_type
                );
            }
            ThreatLevel::Medium => {
                println!(
                    "SECURITY WARNING: {} | Request: {:?} | IP: {:?} | Threat: {:?}",
                    message, self.request_id, self.client_ip, self.threat_level
                );
            }
            ThreatLevel::Low => {
                println!(
                    "SECURITY INFO: {} | Request: {:?} | Type: {:?}",
                    message, self.request_id, self.violation_type
                );
            }
        }
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Enhanced input validation for MVP
pub fn validate_input(input: &str) -> Result<(), Box<dyn std::error::Error>> {
    validate_string_input(input, "input", MAX_STRING_LENGTH)?;
    Ok(())
}

/// Validate string input with security checks
pub fn validate_string_input(
    input: &str,
    field_name: &str,
    max_length: usize,
) -> Result<(), ValidationError> {
    // Check length
    if input.len() > max_length {
        return Err(ValidationError::PayloadTooLarge {
            field: field_name.to_string(),
            size: input.len(),
            max_size: max_length,
        });
    }

    // Check for control characters
    if input
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(ValidationError::SecurityViolation {
            threat_level: ThreatLevel::Medium,
            details: format!("Control characters detected in {}", field_name),
        });
    }

    // Check for suspicious patterns
    if contains_suspicious_patterns(input) {
        return Err(ValidationError::SecurityViolation {
            threat_level: ThreatLevel::High,
            details: format!("Suspicious patterns detected in {}", field_name),
        });
    }

    Ok(())
}

/// Validate request ID format and security
pub fn validate_request_id(request_id: &str) -> Result<(), ValidationError> {
    if request_id.is_empty() {
        return Err(ValidationError::InvalidInput {
            field: "request_id".to_string(),
            reason: "Cannot be empty".to_string(),
        });
    }

    if request_id.len() > MAX_REQUEST_ID_LENGTH {
        return Err(ValidationError::PayloadTooLarge {
            field: "request_id".to_string(),
            size: request_id.len(),
            max_size: MAX_REQUEST_ID_LENGTH,
        });
    }

    // Check for control characters and potential injection attacks
    if request_id.chars().any(|c| c.is_control()) {
        return Err(ValidationError::SecurityViolation {
            threat_level: ThreatLevel::Medium,
            details: "Request ID contains control characters".to_string(),
        });
    }

    Ok(())
}

/// Validate action string with enhanced security checks
pub fn validate_action_string(action: &str) -> Result<(), ValidationError> {
    if action.is_empty() {
        return Err(ValidationError::InvalidInput {
            field: "action".to_string(),
            reason: "Cannot be empty".to_string(),
        });
    }

    // Check for potentially dangerous characters in action
    if action.contains('\0') || action.chars().any(|c| c.is_control() && c != ' ') {
        return Err(ValidationError::SecurityViolation {
            threat_level: ThreatLevel::High,
            details: "Action contains control characters".to_string(),
        });
    }

    // Check for potential injection patterns
    let suspicious_patterns = [
        "drop", "delete", "insert", "update", "select", "union", "exec", "script",
    ];
    let action_lower = action.to_lowercase();
    for pattern in &suspicious_patterns {
        if action_lower.contains(pattern) {
            println!(
                "WARNING: Suspicious pattern '{}' detected in action: {}",
                pattern, action
            );
        }
    }

    // Check action length limits
    if action.len() > MAX_ACTION_LENGTH {
        return Err(ValidationError::PayloadTooLarge {
            field: "action".to_string(),
            size: action.len(),
            max_size: MAX_ACTION_LENGTH,
        });
    }

    Ok(())
}

/// Validate JSON structure for security
pub fn validate_json_structure(value: &Value, field_name: &str) -> Result<(), ValidationError> {
    // Check for excessively nested structures (potential DoS)
    fn check_depth(
        value: &Value,
        field_name: &str,
        current_depth: usize,
        max_depth: usize,
    ) -> Result<(), ValidationError> {
        if current_depth > max_depth {
            return Err(ValidationError::StructureAbuse {
                field: field_name.to_string(),
                details: format!(
                    "JSON structure too deeply nested (depth: {})",
                    current_depth
                ),
            });
        }

        match value {
            Value::Object(obj) => {
                // Limit object key count to prevent DoS
                if obj.len() > 1000 {
                    return Err(ValidationError::StructureAbuse {
                        field: field_name.to_string(),
                        details: format!("JSON object has too many keys: {}", obj.len()),
                    });
                }

                for (key, val) in obj {
                    // Validate key format
                    if key.len() > 256 {
                        return Err(ValidationError::PayloadTooLarge {
                            field: field_name.to_string(),
                            size: key.len(),
                            max_size: 256,
                        });
                    }
                    check_depth(val, field_name, current_depth + 1, max_depth)?;
                }
            }
            Value::Array(arr) => {
                // Limit array size to prevent DoS
                if arr.len() > 1000 {
                    return Err(ValidationError::StructureAbuse {
                        field: field_name.to_string(),
                        details: format!("JSON array too large: {}", arr.len()),
                    });
                }

                for val in arr {
                    check_depth(val, field_name, current_depth + 1, max_depth)?;
                }
            }
            Value::String(s) => {
                // Validate string length and content
                if s.len() > MAX_STRING_LENGTH {
                    return Err(ValidationError::PayloadTooLarge {
                        field: field_name.to_string(),
                        size: s.len(),
                        max_size: MAX_STRING_LENGTH,
                    });
                }

                // Check for suspicious patterns in strings
                if s.contains('\0')
                    || s.chars()
                        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
                {
                    return Err(ValidationError::SecurityViolation {
                        threat_level: ThreatLevel::Medium,
                        details: format!(
                            "JSON string contains control characters in {}",
                            field_name
                        ),
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }

    check_depth(value, field_name, 0, MAX_JSON_DEPTH)?;

    // Check approximate size
    let json_str = serde_json::to_string(value).map_err(|e| ValidationError::InvalidInput {
        field: field_name.to_string(),
        reason: format!("Failed to serialize JSON: {}", e),
    })?;

    if json_str.len() > MAX_JSON_SIZE {
        return Err(ValidationError::PayloadTooLarge {
            field: field_name.to_string(),
            size: json_str.len(),
            max_size: MAX_JSON_SIZE,
        });
    }

    Ok(())
}

/// Validate entity structure (for authorization requests)
pub fn validate_entity_structure(entity: &Value, entity_type: &str) -> Result<(), ValidationError> {
    let obj = entity
        .as_object()
        .ok_or_else(|| ValidationError::InvalidInput {
            field: entity_type.to_string(),
            reason: "Must be a JSON object".to_string(),
        })?;

    // Validate required fields
    let entity_id =
        obj.get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::InvalidInput {
                field: entity_type.to_string(),
                reason: "Missing required 'id' field".to_string(),
            })?;

    let type_field =
        obj.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ValidationError::InvalidInput {
                field: entity_type.to_string(),
                reason: "Missing required 'type' field".to_string(),
            })?;

    // Validate ID length
    if entity_id.len() > MAX_ENTITY_ID_LENGTH {
        return Err(ValidationError::PayloadTooLarge {
            field: entity_type.to_string(),
            size: entity_id.len(),
            max_size: MAX_ENTITY_ID_LENGTH,
        });
    }

    // Check for control characters in ID
    if entity_id.chars().any(|c| c.is_control()) {
        return Err(ValidationError::SecurityViolation {
            threat_level: ThreatLevel::Medium,
            details: format!("Entity ID contains control characters in {}", entity_type),
        });
    }

    // Validate type field
    if type_field.is_empty() || type_field.len() > 64 {
        return Err(ValidationError::InvalidInput {
            field: entity_type.to_string(),
            reason: "Invalid entity type".to_string(),
        });
    }

    Ok(())
}

/// Security utilities for input sanitization
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
            "<script",
            "javascript:",
            "data:",
            "vbscript:",
            "onload=",
            "onerror=",
            "eval(",
            "setTimeout(",
            "setInterval(",
        ];

        let input_lower = input.to_lowercase();
        patterns.iter().any(|pattern| input_lower.contains(pattern))
    }

    /// Validate IPv4/IPv6 address format
    pub fn is_valid_ip_address(addr: &str) -> bool {
        addr.parse::<IpAddr>().is_ok()
    }

    /// Extract client IP from various header formats
    pub fn extract_client_ip(headers: &HashMap<String, String>) -> Option<String> {
        // Try X-Forwarded-For first
        if let Some(forwarded) = headers.get("x-forwarded-for") {
            if let Some(first_ip) = forwarded.split(',').next() {
                return Some(first_ip.trim().to_string());
            }
        }

        // Try X-Real-IP
        if let Some(real_ip) = headers.get("x-real-ip") {
            return Some(real_ip.clone());
        }

        // Try other common headers
        for header in ["cf-connecting-ip", "x-client-ip", "x-forwarded"] {
            if let Some(ip_header) = headers.get(header) {
                return Some(ip_header.clone());
            }
        }

        None
    }

    /// Sanitize string for logging (replace control characters)
    pub fn sanitize_for_logging(input: &str) -> String {
        input
            .chars()
            .map(|c| if c.is_control() { '_' } else { c })
            .collect()
    }
}

/// Re-export main validation function for backward compatibility
pub use security_utils::contains_suspicious_patterns;

/// Enhanced validation with security context
pub fn validate_with_security_context(
    input: &str,
    field_name: &str,
    security_ctx: &mut SecurityContext,
) -> Result<(), ValidationError> {
    match validate_string_input(input, field_name, MAX_STRING_LENGTH) {
        Ok(_) => Ok(()),
        Err(e) => {
            // Update security context based on error type
            match &e {
                ValidationError::SecurityViolation { threat_level, .. } => {
                    security_ctx.threat_level = threat_level.clone();
                    security_ctx.violation_type = ViolationType::SuspiciousPattern;
                }
                ValidationError::PayloadTooLarge { .. } => {
                    security_ctx.threat_level = ThreatLevel::Medium;
                    security_ctx.violation_type = ViolationType::PayloadTooLarge;
                }
                ValidationError::StructureAbuse { .. } => {
                    security_ctx.threat_level = ThreatLevel::Medium;
                    security_ctx.violation_type = ViolationType::StructureAbuse;
                }
                ValidationError::InvalidInput { .. } => {
                    security_ctx.violation_type = ViolationType::InvalidInput;
                }
            }

            security_ctx
                .log_security_incident(&format!("Validation failed for {}: {}", field_name, e));
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validate_input() {
        // Valid input
        assert!(validate_input("hello world").is_ok());

        // Empty input
        assert!(validate_input("").is_ok());

        // Input with control characters
        assert!(validate_string_input("hello\x00world", "test", 100).is_err());
    }

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
        assert!(validate_action_string("read").is_ok());
        assert!(validate_action_string("Document::read").is_ok());

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
    }

    #[test]
    fn test_security_utils() {
        use security_utils::*;

        // Sanitize string
        let input = "Hello\x00World\x01!";
        let sanitized = sanitize_string(input);
        assert_eq!(sanitized, "HelloWorld!");

        // Suspicious patterns
        assert!(contains_suspicious_patterns(
            "<script>alert('xss')</script>"
        ));
        assert!(contains_suspicious_patterns("javascript:alert('xss')"));
        assert!(!contains_suspicious_patterns("normal text"));

        // IP validation
        assert!(is_valid_ip_address("192.168.1.1"));
        assert!(is_valid_ip_address("::1"));
        assert!(!is_valid_ip_address("not.an.ip"));
    }

    #[test]
    fn test_security_context() {
        let ctx = SecurityContext::new()
            .with_request_id("test-123".to_string())
            .with_threat_level(ThreatLevel::Medium);

        // This should not panic and should log appropriately
        ctx.log_security_incident("Test security incident");
    }
}
