use std::collections::HashSet;
use url::Url;
use crate::AuthError;

/// Comprehensive redirect URI validation for OAuth2 security
pub struct RedirectUriValidator {
    /// Registered redirect URIs for each client
    client_redirect_uris: std::collections::HashMap<String, HashSet<String>>,
    /// Whether to enforce HTTPS in production
    enforce_https: bool,
    /// Allowed schemes (https, http for localhost only)
    allowed_schemes: HashSet<String>,
    /// Maximum URI length to prevent DoS
    max_uri_length: usize,
}

impl RedirectUriValidator {
    pub fn new(enforce_https: bool) -> Self {
        let mut allowed_schemes = HashSet::new();
        allowed_schemes.insert("https".to_string());

        // Allow http only for localhost in development
        if !enforce_https {
            allowed_schemes.insert("http".to_string());
        }

        Self {
            client_redirect_uris: std::collections::HashMap::new(),
            enforce_https,
            allowed_schemes,
            max_uri_length: 2048, // RFC 7519 recommendation
        }
    }

    /// Register allowed redirect URIs for a client
    pub fn register_client_uris(&mut self, client_id: &str, uris: Vec<String>) -> Result<(), AuthError> {
        let mut validated_uris = HashSet::new();

        for uri in uris {
            // Validate and also enforce security policies at registration time to align with tests
            self.validate_uri_format(&uri)?;
            // Reject path traversal early to prevent registration of suspicious URIs
            self.validate_security_policies(&uri)?;
            validated_uris.insert(uri);
        }

        self.client_redirect_uris.insert(client_id.to_string(), validated_uris);
        Ok(())
    }

    /// Comprehensive redirect URI validation
    pub fn validate_redirect_uri(&self, client_id: &str, redirect_uri: &str) -> Result<(), AuthError> {
        // 1. Length validation
        if redirect_uri.len() > self.max_uri_length {
            return Err(AuthError::InvalidRequest {
                reason: "Redirect URI exceeds maximum length".to_string()
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
    fn validate_uri_format(&self, uri: &str) -> Result<(), AuthError> {
        // Basic string-level path traversal guard prior to parsing (URL parsing may normalize dot segments)
        if uri.contains("/../") || uri.ends_with("/..") {
            return Err(AuthError::InvalidRequest {
                reason: "Path traversal detected in redirect URI".to_string()
            });
        }
        // Parse URL
        let parsed_url = Url::parse(uri)
            .map_err(|_| AuthError::InvalidRequest { reason: "Invalid redirect URI format".to_string() })?;

        // Basic scheme presence; detailed scheme enforcement happens in security policies
        if parsed_url.scheme() != "https" && parsed_url.scheme() != "http" {
            return Err(AuthError::InvalidRequest {
                reason: format!("Unsupported scheme: {}", parsed_url.scheme())
            });
        }

        // Validate host exists
        if parsed_url.host().is_none() {
            return Err(AuthError::InvalidRequest {
                reason: "Redirect URI must have a valid host".to_string()
            });
        }

        // Prevent fragment in redirect URI (OAuth2 security best practice)
        if parsed_url.fragment().is_some() {
            return Err(AuthError::InvalidRequest {
                reason: "Redirect URI must not contain fragments".to_string()
            });
        }

        Ok(())
    }

    /// Validate against client's registered redirect URIs
    fn validate_client_whitelist(&self, client_id: &str, redirect_uri: &str) -> Result<(), AuthError> {
        let client_uris = self.client_redirect_uris.get(client_id)
            .ok_or_else(|| AuthError::UnauthorizedClient { client_id: "Client not registered".to_string() })?;

        // Exact match required for security
        if !client_uris.contains(redirect_uri) {
            return Err(AuthError::InvalidRequest {
                reason: "Redirect URI not registered for this client".to_string()
            });
        }

        Ok(())
    }

    /// Apply additional security policies
    fn validate_security_policies(&self, redirect_uri: &str) -> Result<(), AuthError> {
        let parsed_url = Url::parse(redirect_uri).unwrap(); // Already validated above

        // HTTPS enforcement in production
        if self.enforce_https && parsed_url.scheme() != "https" {
            // Allow localhost for development
            if let Some(host) = parsed_url.host_str() {
                if !self.is_localhost(host) {
                    return Err(AuthError::InvalidRequest {
                        reason: "HTTPS required for redirect URIs in production".to_string()
                    });
                }
            }
        }

        // Prevent IP addresses (except localhost)
        if let Some(host) = parsed_url.host_str() {
            if self.is_ip_address(host) && !self.is_localhost(host) {
                return Err(AuthError::InvalidRequest {
                    reason: "IP addresses not allowed in redirect URIs".to_string()
                });
            }
        }

        // Prevent suspicious paths
        let raw_path = parsed_url.path();
        if raw_path.contains("..") || raw_path.contains("//") {
            return Err(AuthError::InvalidRequest {
                reason: "Path traversal detected in redirect URI".to_string()
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
}

/// Default redirect URI configurations for common clients
impl Default for RedirectUriValidator {
    fn default() -> Self {
        let mut validator = Self::new(std::env::var("ENVIRONMENT").unwrap_or_default() == "production");

        // Register default test client
        let _ = validator.register_client_uris(
            "test_client",
            vec![
                "https://example.com/callback".to_string(),
                "http://localhost:3000/callback".to_string(),
            ]
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
        validator.register_client_uris(
            "test_client",
            vec!["https://example.com/callback".to_string()]
        ).unwrap();

        assert!(validator.validate_redirect_uri("test_client", "https://example.com/callback").is_ok());
    }

    #[test]
    fn test_unregistered_redirect_uri() {
        let mut validator = RedirectUriValidator::new(false);
        validator.register_client_uris(
            "test_client",
            vec!["https://example.com/callback".to_string()]
        ).unwrap();

        assert!(validator.validate_redirect_uri("test_client", "https://evil.com/callback").is_err());
    }

    #[test]
    fn test_fragment_rejection() {
        let mut validator = RedirectUriValidator::new(false);
        validator.register_client_uris(
            "test_client",
            vec!["https://example.com/callback#fragment".to_string()]
        ).unwrap_err(); // Should fail during registration
    }

    #[test]
    fn test_https_enforcement() {
        let mut validator = RedirectUriValidator::new(true); // Production mode
        let result = validator.register_client_uris(
            "test_client",
            vec!["http://example.com/callback".to_string()]
        );

        // Should allow registration but fail validation
        if result.is_ok() {
            assert!(validator.validate_redirect_uri("test_client", "http://example.com/callback").is_err());
        }
    }

    #[test]
    fn test_localhost_exception() {
        let mut validator = RedirectUriValidator::new(true); // Production mode
        validator.register_client_uris(
            "test_client",
            vec!["http://localhost:3000/callback".to_string()]
        ).unwrap();

        assert!(validator.validate_redirect_uri("test_client", "http://localhost:3000/callback").is_ok());
    }

    #[test]
    fn test_path_traversal_prevention() {
        let mut validator = RedirectUriValidator::new(false);
        let result = validator.register_client_uris(
            "test_client",
            vec!["https://example.com/../callback".to_string()]
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_ip_address_rejection() {
        let mut validator = RedirectUriValidator::new(false);
        let result = validator.register_client_uris(
            "test_client",
            vec!["https://192.168.1.1/callback".to_string()]
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_uri_length_limit() {
        let validator = RedirectUriValidator::new(false);
        let long_uri = format!("https://example.com/{}", "a".repeat(3000));

        assert!(validator.validate_redirect_uri("test_client", &long_uri).is_err());
    }
}
