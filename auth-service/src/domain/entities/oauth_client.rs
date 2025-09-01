//! `OAuth` Client Entity
//!
//! Represents `OAuth` 2.0 clients in the system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// `OAuth` client entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    /// Unique client identifier
    pub client_id: String,

    /// Client secret (hashed for storage)
    pub client_secret_hash: String,

    /// Client name
    pub name: String,

    /// Allowed redirect URIs
    pub redirect_uris: Vec<String>,

    /// Allowed grant types
    pub grant_types: Vec<String>,

    /// Allowed response types
    pub response_types: Vec<String>,

    /// Client creation timestamp
    pub created_at: DateTime<Utc>,

    /// Client last modified timestamp
    pub updated_at: DateTime<Utc>,

    /// Whether the client is active
    pub is_active: bool,

    /// Client owner (user ID)
    pub owner_id: Option<String>,

    /// Scopes this client can request
    pub scopes: Vec<String>,
}

impl OAuthClient {
    /// Create a new `OAuth` client
    #[must_use] pub fn new(
        client_id: String,
        client_secret_hash: String,
        name: String,
        redirect_uris: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            client_id,
            client_secret_hash,
            name,
            redirect_uris,
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            created_at: now,
            updated_at: now,
            is_active: true,
            owner_id: None,
            scopes: vec!["read".to_string()],
        }
    }

    /// Check if a redirect URI is allowed
    #[must_use] pub fn is_redirect_uri_allowed(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|allowed| allowed == uri)
    }

    /// Check if a grant type is allowed
    #[must_use] pub fn is_grant_type_allowed(&self, grant_type: &str) -> bool {
        self.grant_types.iter().any(|allowed| allowed == grant_type)
    }

    /// Check if a response type is allowed
    #[must_use] pub fn is_response_type_allowed(&self, response_type: &str) -> bool {
        self.response_types
            .iter()
            .any(|allowed| allowed == response_type)
    }

    /// Check if a scope is allowed
    #[must_use] pub fn is_scope_allowed(&self, scope: &str) -> bool {
        self.scopes.iter().any(|allowed| allowed == scope)
    }

    /// Deactivate the client
    pub fn deactivate(&mut self) {
        self.is_active = false;
        self.updated_at = Utc::now();
    }

    /// Reactivate the client
    pub fn reactivate(&mut self) {
        self.is_active = true;
        self.updated_at = Utc::now();
    }

    /// Add a redirect URI
    pub fn add_redirect_uri(&mut self, uri: String) {
        if !self.redirect_uris.contains(&uri) {
            self.redirect_uris.push(uri);
            self.updated_at = Utc::now();
        }
    }

    /// Remove a redirect URI
    pub fn remove_redirect_uri(&mut self, uri: &str) {
        self.redirect_uris.retain(|u| u != uri);
        self.updated_at = Utc::now();
    }

    /// Add a scope
    pub fn add_scope(&mut self, scope: String) {
        if !self.scopes.contains(&scope) {
            self.scopes.push(scope);
            self.updated_at = Utc::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_client_creation() {
        let client = OAuthClient::new(
            "client123".to_string(),
            "secret_hash".to_string(),
            "Test Client".to_string(),
            vec!["https://example.com/callback".to_string()],
        );

        assert_eq!(client.client_id, "client123");
        assert_eq!(client.name, "Test Client");
        assert!(client.is_active);
        assert!(client.is_redirect_uri_allowed("https://example.com/callback"));
        assert!(!client.is_redirect_uri_allowed("https://evil.com/callback"));
    }

    #[test]
    fn test_grant_type_validation() {
        let client = OAuthClient::new(
            "client123".to_string(),
            "secret_hash".to_string(),
            "Test Client".to_string(),
            vec!["https://example.com/callback".to_string()],
        );

        assert!(client.is_grant_type_allowed("authorization_code"));
        assert!(!client.is_grant_type_allowed("password"));
    }

    #[test]
    fn test_scope_validation() {
        let client = OAuthClient::new(
            "client123".to_string(),
            "secret_hash".to_string(),
            "Test Client".to_string(),
            vec!["https://example.com/callback".to_string()],
        );

        assert!(client.is_scope_allowed("read"));
        assert!(!client.is_scope_allowed("write"));
    }

    #[test]
    fn test_client_deactivation() {
        let mut client = OAuthClient::new(
            "client123".to_string(),
            "secret_hash".to_string(),
            "Test Client".to_string(),
            vec!["https://example.com/callback".to_string()],
        );

        assert!(client.is_active);
        client.deactivate();
        assert!(!client.is_active);
    }
}
