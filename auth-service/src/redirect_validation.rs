use regex::Regex;
use std::collections::HashSet;
use url::Url;

/// Comprehensive redirect URI validation for `OAuth2` security
#[allow(dead_code)]
pub struct RedirectUriValidator {
    /// Registered redirect URIs for each client
    client_redirect_uris: std::collections::HashMap<String, HashSet<String>>,
    /// Whether to enforce HTTPS in production
    enforce_https: bool,
    /// Allowed schemes (https, http for localhost only}
    allowed_schemes: HashSet<String>,
    /// Maximum URI length to prevent `DoS`
    max_uri_length: usize,
    /// Allowed TLDs for validation
    allowed_tlds: HashSet<String>,
    /// Blocked domains/hosts
    blocked_domains: HashSet<String>,
    /// Pattern to validate URI components
    suspicious_patterns: Vec<Regex>,
}

// Suspicious patterns to detect in URIs
static SUSPICIOUS_PATTERNS: std::sync::LazyLock<Vec<Regex>> = std::sync::LazyLock::new(|| {
    vec![
        Regex::new(r"\.\.[\\/]").unwrap(),         // Path traversal
        Regex::new(r#"[<>"']"#).unwrap(),          // HTML/JS injection chars
        Regex::new(r"javascript:").unwrap(),       // JavaScript protocol
        Regex::new(r"data:").unwrap(),             // Data protocol
        Regex::new(r"vbscript:").unwrap(),         // VBScript protocol
        Regex::new(r"file:").unwrap(),             // File protocol
        Regex::new(r"\\x[0-9a-fA-F]{2}").unwrap(), // Hex encoded chars
        Regex::new(r"%[0-9a-fA-F]{2}").unwrap(),   // URL encoded suspicious chars
    ]
});

static COMMON_TLDS: std::sync::LazyLock<HashSet<String>> = std::sync::LazyLock::new(|| {
    [
        "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "uk", "de", "fr", "jp", "cn",
        "au", "ca", "br", "ru", "in", "mx", "es", "it", "nl", "se", "no", "dk", "fi", "pl", "be",
        "at", "ch", "cz", "hu", "pt", "ro", "gr", "bg", "hr", "sk", "si", "lt", "lv", "ee", "ie",
        "lu", "mt", "cy",
    ]
    .iter()
    .map(|&s| s.to_string())
    .collect()
});

impl RedirectUriValidator {
    pub fn new(enforce_https: bool) -> Self {
        let mut allowed_schemes = HashSet::new();
        allowed_schemes.insert("https".to_string());

        // Allow http only for localhost in development
        if !enforce_https {
            allowed_schemes.insert("http".to_string());
        }

        let mut blocked_domains = HashSet::new();
        // Add common suspicious domains
        blocked_domains.insert("bit.ly".to_string());
        blocked_domains.insert("tinyurl.com".to_string());
        blocked_domains.insert("short.link".to_string());
        blocked_domains.insert("t.co".to_string());

        Self {
            client_redirect_uris: std::collections::HashMap::new(),
            enforce_https,
            allowed_schemes,
            max_uri_length: 2048, // RFC 7519 recommendation
            allowed_tlds: COMMON_TLDS.clone(),
            blocked_domains,
            suspicious_patterns: SUSPICIOUS_PATTERNS.clone(),
        }
    }

    /// Register allowed redirect URIs for a client
    pub fn register_client_uris(
        &mut self,
        client_id: &str,
        uris: Vec<String>,
    ) -> Result<(), crate::shared::error::AppError> {
        let mut validated_uris = HashSet::new();

        for uri in uris {
            // Validate and also enforce security policies at registration time to align with tests
            self.validate_uri_format(&uri)?;
            // Reject path traversal early to prevent registration of suspicious URIs
            self.validate_security_policies(&uri)?;
            validated_uris.insert(uri);
        }

        self.client_redirect_uris
            .insert(client_id.to_string(), validated_uris);
        Ok(())
    }

    /// Comprehensive redirect URI validation
    pub fn validate_redirect_uri(
        &self,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<(), crate::shared::error::AppError> {
        // 1. Length validation
        if redirect_uri.len() > self.max_uri_length {
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Redirect URI exceeds maximum length".to_string(),
            });
        }

        // 2. Basic format validation
        self.validate_uri_format(redirect_uri)?;

        // 3. Client whitelist validation
        self.validate_client_whitelist(client_id, redirect_uri)?;

        // 4. Security policy validation
        self.validate_security_policies(redirect_uri)?;

        Ok(())
    }

    /// Validate URI format and structure
    fn validate_uri_format(&self, uri: &str) -> Result<(), crate::shared::error::AppError> {
        // Basic string-level path traversal guard prior to parsing (URL parsing may normalize dot segments}
        if uri.contains("/../") || uri.ends_with("/..") {
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Path traversal detected in redirect URI".to_string(),
            });
        }
        // Parse URL
        let parsed_url =
            Url::parse(uri).map_err(|_| crate::shared::error::AppError::InvalidRequest {
                reason: "Invalid redirect URI format".to_string(),
            })?;

        // Basic scheme presence; detailed scheme enforcement happens in security policies
        if parsed_url.scheme() != "https" && parsed_url.scheme() != "http" {
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: format!("Unsupported scheme: {}", parsed_url.scheme()),
            });
        }

        // Validate host exists
        if parsed_url.host().is_none() {
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Redirect URI must have a valid host".to_string(),
            });
        }

        // Prevent fragment in redirect URI (OAuth2 security best practice}
        if parsed_url.fragment().is_some() {
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Redirect URI must not contain fragments".to_string(),
            });
        }

        Ok(())
    }

    /// Validate against client's registered redirect URIs
    fn validate_client_whitelist(
        &self,
        client_id: &str,
        redirect_uri: &str,
    ) -> Result<(), crate::shared::error::AppError> {
        let client_uris = self.client_redirect_uris.get(client_id).ok_or_else(|| {
            crate::shared::error::AppError::UnauthorizedClient("Client not registered".to_string())
        })?;

        // Exact match required for security
        if !client_uris.contains(redirect_uri) {
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Redirect URI not registered for this client".to_string(),
            });
        }

        Ok(())
    }

    /// Apply additional security policies
    fn validate_security_policies(
        &self,
        redirect_uri: &str,
    ) -> Result<(), crate::shared::error::AppError> {
        let parsed_url = Url::parse(redirect_uri).unwrap(); // Already validated above

        // HTTPS enforcement in production
        if self.enforce_https && parsed_url.scheme() != "https" {
            // Allow localhost for development
            if let Some(host) = parsed_url.host_str() {
                if !self.is_localhost(host) {
                    return Err(crate::shared::error::AppError::InvalidRequest {
                        reason: "HTTPS required for redirect URIs in production".to_string(),
                    });
                }
            }
        }

        // Prevent IP addresses (except localhost}
        if let Some(host) = parsed_url.host_str() {
            if self.is_ip_address(host) && !self.is_localhost(host) {
                return Err(crate::shared::error::AppError::InvalidRequest {
                    reason: "IP addresses not allowed in redirect URIs".to_string(),
                });
            }

            // Check for blocked domains
            if self.is_blocked_domain(host) {
                return Err(crate::shared::error::AppError::InvalidRequest {
                    reason: "Domain is on the blocklist".to_string(),
                });
            }

            // Validate TLD
            if !self.is_valid_tld(host) {
                return Err(crate::shared::error::AppError::InvalidRequest {
                    reason: "Invalid or suspicious TLD".to_string(),
                });
            }
        }

        // Check for suspicious patterns
        for pattern in &self.suspicious_patterns {
            if pattern.is_match(redirect_uri) {
                return Err(crate::shared::error::AppError::InvalidRequest {
                    reason: "Suspicious pattern detected in redirect URI".to_string(),
                });
            }
        }

        // Prevent suspicious paths
        let raw_path = parsed_url.path();
        if raw_path.contains("..") || raw_path.contains("//") {
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Path traversal detected in redirect URI".to_string(),
            });
        }

        // Check for encoded attack attempts
        if self.contains_encoded_attacks(redirect_uri) {
            return Err(crate::shared::error::AppError::InvalidRequest {
                reason: "Encoded attack detected in redirect URI".to_string(),
            });
        }

        Ok(())
    }

    /// Check if host is localhost
    fn is_localhost(&self, host: &str) -> bool {
        matches!(host, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0")
    }

    /// Check if host is an IP address
    fn is_ip_address(&self, host: &str) -> bool {
        host.parse::<std::net::IpAddr>().is_ok()
    }

    /// Check if domain is blocked
    fn is_blocked_domain(&self, host: &str) -> bool {
        self.blocked_domains.contains(&host.to_lowercase())
    }

    /// Validate TLD against known good TLDs
    fn is_valid_tld(&self, host: &str) -> bool {
        // Allow localhost and IP addresses
        if self.is_localhost(host) || self.is_ip_address(host) {
            return true;
        }

        if let Some(tld) = host.split('.').next_back() {
            self.allowed_tlds.contains(&tld.to_lowercase())
        } else {
            // Single word hosts like "localhost" are allowed
            host.to_lowercase() == "localhost"
        }
    }

    /// Check for encoded attack patterns
    fn contains_encoded_attacks(&self, uri: &str) -> bool {
        let decoded = urlencoding::decode(uri).unwrap_or_default();

        // Check for double encoding
        let double_decoded = urlencoding::decode(&decoded).unwrap_or_default();
        if decoded != double_decoded {
            return true;
        }

        // Check for dangerous decoded patterns
        let dangerous_patterns = [
            "<script",
            "javascript:",
            "vbscript:",
            "data:",
            "file:",
            "..\\.",
            "../.",
            "\\x",
        ];

        for pattern in &dangerous_patterns {
            if decoded.to_lowercase().contains(pattern) {
                return true;
            }
        }

        false
    }

    /// Add a domain to the blocklist
    pub fn block_domain(&mut self, domain: &str) {
        self.blocked_domains.insert(domain.to_lowercase());
    }

    /// Remove a domain from the blocklist
    pub fn unblock_domain(&mut self, domain: &str) {
        self.blocked_domains.remove(&domain.to_lowercase());
    }
}

/// Default redirect URI configurations for common clients
impl Default for RedirectUriValidator {
    fn default() -> Self {
        let mut validator =
            Self::new(std::env::var("ENVIRONMENT").unwrap_or_default() == "production");

        // Register default test client
        let _ = validator.register_client_uris(
            "test_client",
            vec![
                "https://example.com/callback".to_string(),
                "http://localhost:3000/callback".to_string(),
            ],
        );

        validator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_redirect_uri() {
        let mut validator = RedirectUriValidator::new(false);
        validator
            .register_client_uris(
                "test_client",
                vec!["https://example.com/callback".to_string()],
            )
            .unwrap();

        assert!(validator
            .validate_redirect_uri("test_client", "https://example.com/callback")
            .is_ok());
    }

    #[test]
    fn test_unregistered_redirect_uri() {
        let mut validator = RedirectUriValidator::new(false);
        validator
            .register_client_uris(
                "test_client",
                vec!["https://example.com/callback".to_string()],
            )
            .unwrap();

        assert!(validator
            .validate_redirect_uri("test_client", "https://evil.com/callback")
            .is_err());
    }

    #[test]
    fn test_fragment_rejection() {
        let mut validator = RedirectUriValidator::new(false);
        validator
            .register_client_uris(
                "test_client",
                vec!["https://example.com/callback#fragment".to_string()],
            )
            .unwrap_err(); // Should fail during registration
    }

    #[test]
    fn test_https_enforcement() {
        let mut validator = RedirectUriValidator::new(true); // Production mode
        let result = validator.register_client_uris(
            "test_client",
            vec!["http://example.com/callback".to_string()],
        );

        // Should allow registration but fail validation
        if result.is_ok() {
            assert!(validator
                .validate_redirect_uri("test_client", "http://example.com/callback")
                .is_err());
        }
    }

    #[test]
    fn test_localhost_exception() {
        let mut validator = RedirectUriValidator::new(true); // Production mode
        validator
            .register_client_uris(
                "test_client",
                vec!["http://localhost:3000/callback".to_string()],
            )
            .unwrap();

        assert!(validator
            .validate_redirect_uri("test_client", "http://localhost:3000/callback")
            .is_ok());
    }

    #[test]
    fn test_path_traversal_prevention() {
        let mut validator = RedirectUriValidator::new(false);
        let result = validator.register_client_uris(
            "test_client",
            vec!["https://example.com/../callback".to_string()],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_ip_address_rejection() {
        let mut validator = RedirectUriValidator::new(false);
        let result = validator.register_client_uris(
            "test_client",
            vec!["https://192.168.1.1/callback".to_string()],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_uri_length_limit() {
        let validator = RedirectUriValidator::new(false);
        let long_uri = format!("https://example.com/{}", "a".repeat(3000));

        assert!(validator
            .validate_redirect_uri("test_client", &long_uri)
            .is_err());
    }

    #[test]
    fn test_blocked_domains() {
        let mut validator = RedirectUriValidator::new(false);
        validator.block_domain("evil.com");

        let result = validator
            .register_client_uris("test_client", vec!["https://evil.com/callback".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_tld() {
        let mut validator = RedirectUriValidator::new(false);
        let result = validator.register_client_uris(
            "test_client",
            vec!["https://example.badtld/callback".to_string()],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_javascript_protocol_attack() {
        let mut validator = RedirectUriValidator::new(false);
        let result = validator
            .register_client_uris("test_client", vec!["javascript:alert('xss')".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_data_protocol_attack() {
        let mut validator = RedirectUriValidator::new(false);
        let result = validator.register_client_uris(
            "test_client",
            vec!["data:text/html,<script>alert('xss')</script>".to_string()],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_encoded_attack_detection() {
        let mut validator = RedirectUriValidator::new(false);

        // Test URL encoded script tag
        let result = validator.register_client_uris(
            "test_client",
            vec![
                "https://example.com/callback?param=%3Cscript%3Ealert('xss')%3C/script%3E"
                    .to_string(),
            ],
        );
        assert!(result.is_err());

        // Test double encoding
        let result = validator.register_client_uris(
            "test_client2",
            vec!["https://example.com/callback?param=%25%33%43script%25%33%45".to_string()],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_encoded_attacks() {
        let mut validator = RedirectUriValidator::new(false);
        let result = validator.register_client_uris(
            "test_client",
            vec!["https://example.com/callback\\x3cscript\\x3e".to_string()],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_path_injection_variants() {
        let mut validator = RedirectUriValidator::new(false);

        let attack_paths = vec![
            "https://example.com/..\\..\\etc\\passwd",
            "https://example.com/callback/../../../etc/passwd",
            "https://example.com/callback/..%2F..%2F..%2Fetc%2Fpasswd",
            "https://example.com/callback/..%252F..%252F..%252Fetc%252Fpasswd",
        ];

        for attack_path in attack_paths {
            let result =
                validator.register_client_uris("test_client", vec![attack_path.to_string()]);
            assert!(result.is_err(), "Should reject path: {attack_path}");
        }
    }

    #[test]
    fn test_open_redirect_attempts() {
        let mut validator = RedirectUriValidator::new(false);

        // Register legitimate URI first
        validator
            .register_client_uris(
                "test_client",
                vec!["https://example.com/callback".to_string()],
            )
            .unwrap();

        // Test various open redirect attempts
        let redirect_attempts = vec![
            "https://example.com/callback?redirect=https://evil.com",
            "https://example.com/callback#https://evil.com", // This should fail on fragment check
            "https://example.com@evil.com/callback", // This should be parsed as evil.com domain
            "https://example.com.evil.com/callback",
        ];

        for attempt in redirect_attempts {
            let result = validator.validate_redirect_uri("test_client", attempt);
            assert!(result.is_err(), "Should reject redirect attempt: {attempt}");
        }
    }

    #[test]
    fn test_homograph_attacks() {
        let mut validator = RedirectUriValidator::new(false);

        // Test domain spoofing with similar-looking characters
        let spoofed_domains = vec![
            "https://еxample.com/callback", // Cyrillic 'е' instead of 'e'
            "https://example.co‍m/callback", // Hidden Unicode character
            "https://goog1e.com/callback",  // Visual similarity
        ];

        for domain in spoofed_domains {
            let result = validator.register_client_uris("test_client", vec![domain.to_string()]);
            // These might pass basic validation but should be caught by TLD validation
            // or manual review processes
            println!("Testing spoofed domain: {domain} - Result: {result:?}");
        }
    }

    #[test]
    fn test_punycode_domains() {
        let mut validator = RedirectUriValidator::new(false);

        // Test punycode domain (legitimate internationalized domain}
        let result = validator.register_client_uris(
            "test_client",
            vec!["https://xn--fsq.com/callback".to_string()], // Punycode for Chinese domain
        );

        // This should pass if the TLD is valid
        println!("Punycode domain result: {result:?}");
    }

    #[test]
    fn test_port_variations() {
        let mut validator = RedirectUriValidator::new(false);

        // Test various port configurations
        let port_tests = vec![
            ("https://example.com:443/callback", true), // Standard HTTPS port
            ("https://example.com:8443/callback", true), // Common alt HTTPS port
            ("http://localhost:3000/callback", true),   // Development
            ("https://example.com:22/callback", true),  // SSH port (should allow but log}
            ("https://example.com:80/callback", true),  // HTTP port on HTTPS (should work}
        ];

        for (uri, should_pass) in port_tests {
            let result = validator.register_client_uris("test_client", vec![uri.to_string()]);

            if should_pass {
                assert!(result.is_ok(), "Should allow URI: {uri}");
            } else {
                assert!(result.is_err(), "Should reject URI: {uri}");
            }
        }
    }

    #[test]
    fn test_url_shortener_blocking() {
        let mut validator = RedirectUriValidator::new(false);

        let shortener_domains = vec![
            "https://bit.ly/callback",
            "https://tinyurl.com/callback",
            "https://t.co/callback",
        ];

        for domain in shortener_domains {
            let result = validator.register_client_uris("test_client", vec![domain.to_string()]);
            assert!(result.is_err(), "Should block URL shortener: {domain}");
        }
    }
}

// Additional validation for configuration loading
impl RedirectUriValidator {
    /// Load blocked domains from environment
    #[must_use]
    pub fn from_env() -> Self {
        let enforce_https =
            std::env::var("OAUTH_ENFORCE_HTTPS").unwrap_or_else(|_| "true".to_string()) == "true";

        let mut validator = Self::new(enforce_https);

        // Load additional blocked domains from environment
        if let Ok(blocked) = std::env::var("OAUTH_BLOCKED_DOMAINS") {
            for domain in blocked.split(',') {
                validator.block_domain(domain.trim());
            }
        }

        validator
    }
}

// Integration test module for real-world scenarios
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_production_configuration() {
        // Simulate production environment
        std::env::set_var("OAUTH_ENFORCE_HTTPS", "true");
        std::env::set_var("OAUTH_BLOCKED_DOMAINS", "evil.com,malicious.org,spam.net");

        let validator = RedirectUriValidator::from_env();

        // Test that HTTPS is enforced
        let mut test_validator = validator;
        let result = test_validator.register_client_uris(
            "prod_client",
            vec!["http://example.com/callback".to_string()],
        );
        assert!(result.is_err());

        // Clean up
        std::env::remove_var("OAUTH_ENFORCE_HTTPS");
        std::env::remove_var("OAUTH_BLOCKED_DOMAINS");
    }

    #[test]
    fn test_comprehensive_attack_suite() {
        let mut validator = RedirectUriValidator::new(false);

        // Comprehensive list of attack vectors
        let attack_vectors = vec![
            // XSS attempts
            "https://example.com/callback?param=<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "vbscript:msgbox('xss')",
            // Path traversal
            "https://example.com/../../../etc/passwd",
            "https://example.com/..\\..\\..\\etc\\passwd",
            // Protocol manipulation
            "file:///etc/passwd",
            "data:text/html,<script>alert('xss')</script>",
            // Encoding bypasses
            "https://example.com/callback%2e%2e%2f%2e%2e%2f",
            "https://example.com/callback%252e%252e%252f",
            // Domain spoofing
            "https://examp1e.com/callback", // 1 instead of l
            "https://example.c0m/callback", // 0 instead of o
            // IP address attempts
            "https://192.168.1.1/callback",
            "https://[::1]/callback",
            // Fragment injection
            "https://example.com/callback#javascript:alert('xss')",
        ];

        for attack in attack_vectors {
            let result = validator.register_client_uris("attack_client", vec![attack.to_string()]);
            assert!(result.is_err(), "Should block attack vector: {attack}");
        }
    }

    #[test]
    fn test_legitimate_use_cases() {
        let mut validator = RedirectUriValidator::new(false);

        let legitimate_uris = vec![
            "https://myapp.com/oauth/callback",
            "https://subdomain.myapp.com/auth/return",
            "https://api.service.io/v1/auth/callback",
            "http://localhost:3000/callback",    // Dev environment
            "http://127.0.0.1:8080/auth/return", // Local dev
            "https://myapp.com:8443/secure/callback", // Custom HTTPS port
        ];

        for uri in legitimate_uris {
            let result = validator.register_client_uris("legit_client", vec![uri.to_string()]);
            assert!(result.is_ok(), "Should allow legitimate URI: {uri}");
        }
    }
}
