//! Core authentication functionality
//!
//! This module contains the fundamental authentication types and functions
//! that are used throughout the authentication service.

use crate::core::errors::{CoreError, TokenError};
use common::TokenRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Authentication context containing user and session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// User identifier
    pub user_id: String,
    /// Session identifier
    pub session_id: String,
    /// Authentication timestamp
    pub authenticated_at: SystemTime,
    /// Token expiration time
    pub expires_at: SystemTime,
    /// Associated scopes
    pub scopes: Vec<String>,
    /// Additional claims
    pub claims: HashMap<String, String>,
}

impl AuthContext {
    /// Create a new authentication context
    #[must_use] pub fn new(
        user_id: String,
        session_id: String,
        expires_in: Duration,
        scopes: Vec<String>,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            user_id,
            session_id,
            authenticated_at: now,
            expires_at: now + expires_in,
            scopes,
            claims: HashMap::new(),
        }
    }

    /// Check if the authentication context is expired
    #[must_use] pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    /// Check if the context has a specific scope
    #[must_use] pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(&scope.to_string())
    }

    /// Add a custom claim
    pub fn add_claim(&mut self, key: String, value: String) {
        self.claims.insert(key, value);
    }

    /// Get a custom claim
    #[must_use] pub fn get_claim(&self, key: &str) -> Option<&String> {
        self.claims.get(key)
    }
}

/// Token information containing metadata about authentication tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token identifier
    pub token_id: String,
    /// Token type (Bearer, Basic, etc.)
    pub token_type: String,
    /// Issue timestamp
    pub issued_at: SystemTime,
    /// Expiration timestamp
    pub expires_at: SystemTime,
    /// Issuer identifier
    pub issuer: String,
    /// Subject (user) identifier
    pub subject: String,
    /// Audience
    pub audience: Vec<String>,
    /// Token scopes
    pub scopes: Vec<String>,
}

impl TokenInfo {
    /// Create new token information
    #[must_use] pub fn new(
        token_id: String,
        token_type: String,
        expires_in: Duration,
        issuer: String,
        subject: String,
        audience: Vec<String>,
        scopes: Vec<String>,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            token_id,
            token_type,
            issued_at: now,
            expires_at: now + expires_in,
            issuer,
            subject,
            audience,
            scopes,
        }
    }

    /// Check if token is expired
    #[must_use] pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    /// Check if token is valid for a specific audience
    #[must_use] pub fn is_valid_for_audience(&self, aud: &str) -> bool {
        self.audience.contains(&aud.to_string())
    }

    /// Get the remaining lifetime of the authentication context
    ///
    /// # Errors
    ///
    /// Returns `CoreError::Token(TokenError::Expired)` if the authentication has expired
    pub fn remaining_lifetime(&self) -> Result<Duration, CoreError> {
        self.expires_at
            .duration_since(SystemTime::now())
            .map_err(|_| CoreError::Token(TokenError::Expired))
    }
}

/// Authentication result containing context and token information
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Authentication context
    pub context: AuthContext,
    /// Token information
    pub token_info: TokenInfo,
    /// Associated token record
    pub token_record: TokenRecord,
}

impl AuthResult {
    /// Create a new authentication result
    #[must_use] pub const fn new(context: AuthContext, token_info: TokenInfo, token_record: TokenRecord) -> Self {
        Self {
            context,
            token_info,
            token_record,
        }
    }

    /// Check if the authentication result is valid
    #[must_use] pub fn is_valid(&self) -> bool {
        !self.context.is_expired() && !self.token_info.is_expired()
    }
}

/// Authentication provider trait for implementing different auth mechanisms
pub trait AuthProvider {
    /// Authenticate a user with credentials
    fn authenticate(
        &self,
        credentials: &AuthCredentials,
    ) -> impl std::future::Future<Output = Result<AuthResult, CoreError>> + Send;

    /// Validate an existing token
    fn validate_token(&self, token: &str) -> impl std::future::Future<Output = Result<AuthResult, CoreError>> + Send;

    /// Refresh an authentication token
    fn refresh_token(&self, refresh_token: &str) -> impl std::future::Future<Output = Result<AuthResult, CoreError>> + Send;

    /// Revoke a token
    fn revoke_token(&self, token: &str) -> impl std::future::Future<Output = Result<(), CoreError>> + Send;
}

/// Authentication credentials for different authentication methods
#[derive(Debug, Clone)]
pub enum AuthCredentials {
    /// Username and password credentials
    UsernamePassword {
        username: String,
        password: String,
    },
    /// API key credentials
    ApiKey {
        key: String,
    },
    /// Certificate-based credentials
    Certificate {
        cert_data: Vec<u8>,
    },
    /// `OAuth2` authorization code
    OAuth2Code {
        code: String,
        redirect_uri: String,
    },
    /// JWT token credentials
    JwtToken {
        token: String,
    },
}

impl AuthCredentials {
    /// Get the credential type as a string
    #[must_use] pub const fn credential_type(&self) -> &'static str {
        match self {
            Self::UsernamePassword { .. } => "username_password",
            Self::ApiKey { .. } => "api_key",
            Self::Certificate { .. } => "certificate",
            Self::OAuth2Code { .. } => "oauth2_code",
            Self::JwtToken { .. } => "jwt_token",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_auth_context_creation() {
        let context = AuthContext::new(
            "user123".to_string(),
            "session456".to_string(),
            Duration::from_secs(3600),
            vec!["read".to_string(), "write".to_string()],
        );

        assert_eq!(context.user_id, "user123");
        assert_eq!(context.session_id, "session456");
        assert!(!context.is_expired());
        assert!(context.has_scope("read"));
        assert!(context.has_scope("write"));
        assert!(!context.has_scope("admin"));
    }

    #[test]
    fn test_auth_context_claims() {
        let mut context = AuthContext::new(
            "user123".to_string(),
            "session456".to_string(),
            Duration::from_secs(3600),
            vec![],
        );

        context.add_claim("department".to_string(), "engineering".to_string());
        assert_eq!(context.get_claim("department"), Some(&"engineering".to_string()));
        assert_eq!(context.get_claim("nonexistent"), None);
    }

    #[test]
    fn test_token_info_creation() {
        let token_info = TokenInfo::new(
            "token123".to_string(),
            "Bearer".to_string(),
            Duration::from_secs(3600),
            "auth-service".to_string(),
            "user123".to_string(),
            vec!["api".to_string()],
            vec!["read".to_string()],
        );

        assert_eq!(token_info.token_id, "token123");
        assert_eq!(token_info.token_type, "Bearer");
        assert!(!token_info.is_expired());
        assert!(token_info.is_valid_for_audience("api"));
        assert!(!token_info.is_valid_for_audience("web"));
    }

    #[test]
    fn test_credential_types() {
        let creds = AuthCredentials::UsernamePassword {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        assert_eq!(creds.credential_type(), "username_password");

        let creds = AuthCredentials::ApiKey {
            key: "key123".to_string(),
        };
        assert_eq!(creds.credential_type(), "api_key");
    }
}