//! Common utility functions

use crate::ValidationResult;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::time::{Duration, SystemTime};
use url::Url;
use uuid::Uuid;

/// Generate a new correlation ID
pub fn generate_correlation_id() -> Uuid {
    Uuid::new_v4()
}

/// Get current timestamp as UTC
pub fn current_timestamp() -> DateTime<Utc> {
    Utc::now()
}

/// Calculate uptime in seconds from a start time
pub fn calculate_uptime(start_time: SystemTime) -> u64 {
    SystemTime::now()
        .duration_since(start_time)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Validate URL format
pub fn validate_url(url: &str) -> Result<Url> {
    Url::parse(url).map_err(|e| anyhow::anyhow!("Invalid URL: {}", e))
}

/// Validate that a URL uses HTTPS
pub fn validate_https_url(url: &str) -> ValidationResult {
    let mut result = ValidationResult {
        valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    match Url::parse(url) {
        Ok(parsed_url) => {
            if parsed_url.scheme() != "https" {
                result.valid = false;
                result.errors.push("URL must use HTTPS".to_string());
            }
        }
        Err(e) => {
            result.valid = false;
            result.errors.push(format!("Invalid URL format: {}", e));
        }
    }

    result
}

/// Sanitize string for logging (remove sensitive information)
pub fn sanitize_for_logging(input: &str) -> String {
    // Remove potential tokens, passwords, keys
    let sensitive_patterns = [
        r"(token|password|key|secret|credential)[:=]\s*\S+",
        r"Bearer\s+\S+",
        r"Basic\s+\S+",
    ];

    let mut sanitized = input.to_string();
    for pattern in &sensitive_patterns {
        if let Ok(regex) = regex::Regex::new(pattern) {
            sanitized = regex.replace_all(&sanitized, "$1=***").to_string();
        }
    }
    sanitized
}

/// Extract client IP from various header formats
pub fn extract_client_ip(headers: &std::collections::HashMap<String, String>) -> Option<String> {
    // Try various headers in order of preference
    let ip_headers = [
        "x-forwarded-for",
        "x-real-ip",
        "x-client-ip",
        "cf-connecting-ip",
        "x-cluster-client-ip",
    ];

    for header in &ip_headers {
        if let Some(value) = headers.get(&header.to_lowercase()) {
            // X-Forwarded-For can contain multiple IPs, take the first one
            let ip = value.split(',').next()?.trim();
            if !ip.is_empty() && ip != "unknown" {
                return Some(ip.to_string());
            }
        }
    }

    None
}

/// Format duration in human-readable format
pub fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    
    if total_seconds < 60 {
        format!("{}s", total_seconds)
    } else if total_seconds < 3600 {
        format!("{}m {}s", total_seconds / 60, total_seconds % 60)
    } else if total_seconds < 86400 {
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        format!("{}h {}m", hours, minutes)
    } else {
        let days = total_seconds / 86400;
        let hours = (total_seconds % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}

/// Validate email format (basic validation)
pub fn validate_email(email: &str) -> bool {
    email.contains('@') && email.len() > 3 && !email.starts_with('@') && !email.ends_with('@')
}

/// Generate a secure random string
pub fn generate_secure_random_string(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789";
    let mut rng = rand::thread_rng();
    
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_correlation_id() {
        let id1 = generate_correlation_id();
        let id2 = generate_correlation_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_validate_https_url() {
        let result = validate_https_url("https://example.com");
        assert!(result.valid);

        let result = validate_https_url("http://example.com");
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validate_email() {
        assert!(validate_email("test@example.com"));
        assert!(!validate_email("invalid-email"));
        assert!(!validate_email("@example.com"));
        assert!(!validate_email("test@"));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m");
    }
}