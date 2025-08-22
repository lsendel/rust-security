use regex::Regex;
use once_cell::sync::Lazy;
use validator::{ValidationError, ValidationErrors};
use std::collections::HashSet;

// Compile security-focused regexes once for performance
static SAFE_STRING_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9\-_\.\s@]+$").unwrap()
});

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
});

static URL_SAFE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$").unwrap()
});

static ALPHANUMERIC_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9]+$").unwrap()
});

// Dangerous patterns that could indicate injection attacks
static DANGEROUS_PATTERNS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        // JavaScript injection
        "javascript:", "data:", "vbscript:", "<script", "</script>",
        "eval(", "expression(", "import(", "require(",
        "setTimeout", "setInterval", "Function(",
        
        // SQL injection
        "union select", "drop table", "delete from", "insert into",
        "update set", "alter table", "create table", "exec(",
        "xp_", "sp_", "@@", "char(", "cast(",
        
        // Command injection
        "system(", "exec(", "shell_exec", "passthru",
        "$(", "`", "&&", "||", ";", "|",
        
        // Path traversal
        "../", "..\\", "%2e%2e", "%252e%252e",
        
        // LDAP injection
        "*(", "*)", "|(", "|)", "&(", "&)",
        
        // XPath injection
        "or 1=1", "and 1=1", "' or '", "\" or \"",
        
        // Template injection
        "{{", "}}", "${", "<%", "%>", "#{",
        
        // Protocol handlers
        "file:", "ftp:", "gopher:", "ldap:", "dict:",
    ]
});

/// Enhanced scope validation with comprehensive security checks
pub fn validate_scope(scope: &str) -> Result<(), ValidationError> {
    if scope.is_empty() {
        return Err(ValidationError::new("Scope cannot be empty"));
    }
    
    if scope.len() > super::MAX_SCOPE_LENGTH {
        return Err(ValidationError::new("Scope exceeds maximum length"));
    }
    
    // Check for dangerous patterns
    let scope_lower = scope.to_lowercase();
    for pattern in DANGEROUS_PATTERNS.iter() {
        if scope_lower.contains(pattern) {
            return Err(ValidationError::new("Invalid characters detected in scope"));
        }
    }
    
    // Validate scope format (space-separated tokens)
    for token in scope.split_whitespace() {
        if token.is_empty() {
            return Err(ValidationError::new("Empty scope token"));
        }
        
        if token.len() > 100 {
            return Err(ValidationError::new("Scope token too long"));
        }
        
        if !SAFE_STRING_REGEX.is_match(token) {
            return Err(ValidationError::new("Invalid scope token format"));
        }
    }
    
    // Check for duplicate scopes
    let tokens: Vec<&str> = scope.split_whitespace().collect();
    let unique_tokens: HashSet<&str> = tokens.iter().cloned().collect();
    if tokens.len() != unique_tokens.len() {
        return Err(ValidationError::new("Duplicate scopes not allowed"));
    }
    
    Ok(())
}

/// Enhanced redirect URI validation with comprehensive security checks
pub fn validate_redirect_uri(uri: &str) -> Result<(), ValidationError> {
    if uri.is_empty() {
        return Err(ValidationError::new("Redirect URI cannot be empty"));
    }
    
    if uri.len() > super::MAX_REDIRECT_URI_LENGTH {
        return Err(ValidationError::new("Redirect URI too long"));
    }
    
    // Check for dangerous patterns
    let uri_lower = uri.to_lowercase();
    for pattern in DANGEROUS_PATTERNS.iter() {
        if uri_lower.contains(pattern) {
            return Err(ValidationError::new("Invalid characters detected in URI"));
        }
    }
    
    // Parse and validate URL structure
    let parsed = url::Url::parse(uri)
        .map_err(|_| ValidationError::new("Invalid URL format"))?;
    
    // Security constraints on schemes
    match parsed.scheme() {
        "https" => {}, // Always allowed
        "http" => {
            // Only allow localhost for development
            if let Some(host) = parsed.host_str() {
                if !host.starts_with("localhost") && 
                   !host.starts_with("127.0.0.1") && 
                   !host.starts_with("::1") {
                    return Err(ValidationError::new("HTTP only allowed for localhost"));
                }
            }
        },
        // Allow custom app schemes but validate format
        scheme if scheme.len() >= 3 && scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') => {
            // Custom schemes must be at least 3 characters and alphanumeric
        },
        _ => return Err(ValidationError::new("Unsupported URI scheme")),
    }
    
    // Prevent open redirects by checking against allowlist
    if let Some(host) = parsed.host_str() {
        let allowed_hosts = std::env::var("ALLOWED_REDIRECT_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
            
        if !allowed_hosts.is_empty() && !allowed_hosts.contains(&host.to_lowercase()) {
            return Err(ValidationError::new("Host not in allowlist"));
        }
    }
    
    // Check for suspicious query parameters
    if let Some(query) = parsed.query() {
        let query_lower = query.to_lowercase();
        for pattern in DANGEROUS_PATTERNS.iter() {
            if query_lower.contains(pattern) {
                return Err(ValidationError::new("Invalid characters in query parameters"));
            }
        }
    }
    
    // Check for suspicious fragments
    if let Some(fragment) = parsed.fragment() {
        let fragment_lower = fragment.to_lowercase();
        for pattern in DANGEROUS_PATTERNS.iter() {
            if fragment_lower.contains(pattern) {
                return Err(ValidationError::new("Invalid characters in fragment"));
            }
        }
    }
    
    Ok(())
}

/// Validate client ID with security constraints
pub fn validate_client_id(client_id: &str) -> Result<(), ValidationError> {
    if client_id.is_empty() {
        return Err(ValidationError::new("Client ID cannot be empty"));
    }
    
    if client_id.len() > super::MAX_CLIENT_ID_LENGTH {
        return Err(ValidationError::new("Client ID too long"));
    }
    
    // Client IDs should be alphanumeric with limited special characters
    if !ALPHANUMERIC_REGEX.is_match(client_id) {
        return Err(ValidationError::new("Client ID contains invalid characters"));
    }
    
    // Check minimum length for security
    if client_id.len() < 8 {
        return Err(ValidationError::new("Client ID too short (minimum 8 characters)"));
    }
    
    Ok(())
}

/// Validate email with comprehensive checks
pub fn validate_email_secure(email: &str) -> Result<(), ValidationError> {
    if email.is_empty() {
        return Err(ValidationError::new("Email cannot be empty"));
    }
    
    if email.len() > super::MAX_EMAIL_LENGTH {
        return Err(ValidationError::new("Email too long"));
    }
    
    // Check for dangerous patterns
    let email_lower = email.to_lowercase();
    for pattern in DANGEROUS_PATTERNS.iter() {
        if email_lower.contains(pattern) {
            return Err(ValidationError::new("Invalid characters in email"));
        }
    }
    
    // Validate email format
    if !EMAIL_REGEX.is_match(email) {
        return Err(ValidationError::new("Invalid email format"));
    }
    
    // Additional security checks
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err(ValidationError::new("Invalid email format"));
    }
    
    let (local, domain) = (parts[0], parts[1]);
    
    // Validate local part
    if local.is_empty() || local.len() > 64 {
        return Err(ValidationError::new("Invalid email local part"));
    }
    
    // Validate domain part
    if domain.is_empty() || domain.len() > 253 {
        return Err(ValidationError::new("Invalid email domain"));
    }
    
    // Check for suspicious patterns in domain
    if domain.contains("..") || domain.starts_with('.') || domain.ends_with('.') {
        return Err(ValidationError::new("Invalid domain format"));
    }
    
    Ok(())
}

/// Validate username with security constraints
pub fn validate_username_secure(username: &str) -> Result<(), ValidationError> {
    if username.is_empty() {
        return Err(ValidationError::new("Username cannot be empty"));
    }
    
    if username.len() > super::MAX_USERNAME_LENGTH {
        return Err(ValidationError::new("Username too long"));
    }
    
    if username.len() < 3 {
        return Err(ValidationError::new("Username too short (minimum 3 characters)"));
    }
    
    // Check for dangerous patterns
    let username_lower = username.to_lowercase();
    for pattern in DANGEROUS_PATTERNS.iter() {
        if username_lower.contains(pattern) {
            return Err(ValidationError::new("Invalid characters in username"));
        }
    }
    
    // Username should only contain safe characters
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(ValidationError::new("Username contains invalid characters"));
    }
    
    // Additional security constraints
    if username.starts_with('.') || username.ends_with('.') {
        return Err(ValidationError::new("Username cannot start or end with period"));
    }
    
    if username.contains("..") {
        return Err(ValidationError::new("Username cannot contain consecutive periods"));
    }
    
    Ok(())
}

/// Validate password strength
pub fn validate_password_strength(password: &str) -> Result<(), ValidationError> {
    if password.is_empty() {
        return Err(ValidationError::new("Password cannot be empty"));
    }
    
    if password.len() < 8 {
        return Err(ValidationError::new("Password must be at least 8 characters"));
    }
    
    if password.len() > 128 {
        return Err(ValidationError::new("Password too long"));
    }
    
    // Check for character variety
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());
    
    let variety_count = [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    
    if variety_count < 3 {
        return Err(ValidationError::new(
            "Password must contain at least 3 of: lowercase, uppercase, digits, special characters"
        ));
    }
    
    // Check for common weak patterns
    let password_lower = password.to_lowercase();
    let weak_patterns = [
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "shadow"
    ];
    
    for pattern in &weak_patterns {
        if password_lower.contains(pattern) {
            return Err(ValidationError::new("Password contains common weak patterns"));
        }
    }
    
    Ok(())
}

/// Sanitize string input by removing dangerous characters
pub fn sanitize_string(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || " -_.@".contains(*c))
        .collect()
}

/// Validate and sanitize general text input
pub fn validate_text_input(input: &str, max_length: usize, field_name: &str) -> Result<String, ValidationError> {
    if input.is_empty() {
        return Err(ValidationError::new(&format!("{} cannot be empty", field_name)));
    }
    
    if input.len() > max_length {
        return Err(ValidationError::new(&format!("{} exceeds maximum length", field_name)));
    }
    
    // Check for dangerous patterns
    let input_lower = input.to_lowercase();
    for pattern in DANGEROUS_PATTERNS.iter() {
        if input_lower.contains(pattern) {
            return Err(ValidationError::new(&format!("Invalid characters in {}", field_name)));
        }
    }
    
    // Return sanitized version
    Ok(sanitize_string(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_validation() {
        // Valid scopes
        assert!(validate_scope("read write").is_ok());
        assert!(validate_scope("openid profile email").is_ok());
        
        // Invalid scopes
        assert!(validate_scope("").is_err());
        assert!(validate_scope("read <script>alert(1)</script>").is_err());
        assert!(validate_scope("read read").is_err()); // Duplicates
    }

    #[test]
    fn test_redirect_uri_validation() {
        // Valid URIs
        assert!(validate_redirect_uri("https://example.com/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:3000/callback").is_ok());
        assert!(validate_redirect_uri("myapp://callback").is_ok());
        
        // Invalid URIs
        assert!(validate_redirect_uri("").is_err());
        assert!(validate_redirect_uri("javascript:alert(1)").is_err());
        assert!(validate_redirect_uri("http://evil.com/callback").is_err());
    }

    #[test]
    fn test_email_validation() {
        // Valid emails
        assert!(validate_email_secure("user@example.com").is_ok());
        assert!(validate_email_secure("test.user+tag@domain.co.uk").is_ok());
        
        // Invalid emails
        assert!(validate_email_secure("").is_err());
        assert!(validate_email_secure("invalid-email").is_err());
        assert!(validate_email_secure("user@<script>alert(1)</script>").is_err());
    }

    #[test]
    fn test_password_strength() {
        // Strong passwords
        assert!(validate_password_strength("MyStr0ng!Pass").is_ok());
        assert!(validate_password_strength("C0mplex#P@ssw0rd").is_ok());
        
        // Weak passwords
        assert!(validate_password_strength("").is_err());
        assert!(validate_password_strength("weak").is_err());
        assert!(validate_password_strength("password123").is_err());
        assert!(validate_password_strength("12345678").is_err());
    }
}
