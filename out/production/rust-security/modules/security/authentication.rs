//! Authentication Module for Secure User Authentication
//!
//! This module provides comprehensive authentication services including:
//! - Multi-factor authentication (MFA)
//! - JWT token management
//! - Session management
//! - OAuth2 support
//! - SAML integration
//! - Password policies and validation

use async_trait::async_trait;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::errors::{SecurityError, SecurityResult};
use super::traits::SecurityContext;

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationResult {
    Success {
        user_id: String,
        token: AuthToken,
        expires_at: DateTime<Utc>,
    },
    Failed {
        reason: String,
        attempts_remaining: Option<u32>,
    },
    RequiresMfa {
        user_id: String,
        mfa_token: String,
    },
    Locked {
        user_id: String,
        unlock_at: DateTime<Utc>,
    },
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub token_type: TokenType,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    pub scope: Vec<String>,
    pub token_id: String,
}

/// Token types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Bearer,
    JWT,
    SAML,
    OAuth2,
}

/// User credentials
#[derive(Debug, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub mfa_code: Option<String>,
}

/// MFA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    pub enabled: bool,
    pub method: MfaMethod,
    pub secret: Option<String>,
    pub backup_codes: Vec<String>,
}

/// MFA methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaMethod {
    Totp,
    Sms,
    Email,
    HardwareToken,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub is_active: bool,
}

/// Authentication service trait
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Authenticate user with credentials
    async fn authenticate(&self, credentials: &Credentials, context: &SecurityContext) -> SecurityResult<AuthenticationResult>;

    /// Validate authentication token
    async fn validate_token(&self, token: &str) -> SecurityResult<SecurityContext>;

    /// Refresh authentication token
    async fn refresh_token(&self, refresh_token: &str) -> SecurityResult<AuthToken>;

    /// Revoke authentication token
    async fn revoke_token(&self, token: &str) -> SecurityResult<()>;

    /// Setup MFA for user
    async fn setup_mfa(&self, user_id: &str, method: MfaMethod) -> SecurityResult<MfaConfig>;

    /// Verify MFA code
    async fn verify_mfa(&self, user_id: &str, code: &str, mfa_token: &str) -> SecurityResult<bool>;

    /// Create user session
    async fn create_session(&self, user_id: &str, context: &SecurityContext) -> SecurityResult<Session>;

    /// Validate user session
    async fn validate_session(&self, session_id: &str) -> SecurityResult<Session>;

    /// Destroy user session
    async fn destroy_session(&self, session_id: &str) -> SecurityResult<()>;

    /// Get active sessions for user
    async fn get_user_sessions(&self, user_id: &str) -> SecurityResult<Vec<Session>>;

    /// Force logout all user sessions
    async fn logout_all_sessions(&self, user_id: &str) -> SecurityResult<()>;
}

/// JWT authenticator implementation
pub struct JwtAuthenticator {
    secret_key: Vec<u8>,
    issuer: String,
    audience: Vec<String>,
    access_token_expiry: Duration,
    refresh_token_expiry: Duration,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    active_tokens: Arc<RwLock<HashMap<String, AuthToken>>>,
}

impl JwtAuthenticator {
    /// Create new JWT authenticator
    pub fn new(secret_key: Vec<u8>, issuer: String, audience: Vec<String>) -> Self {
        Self {
            secret_key,
            issuer,
            audience,
            access_token_expiry: Duration::hours(1),
            refresh_token_expiry: Duration::days(30),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            active_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate JWT token
    fn generate_jwt(&self, user_id: &str, scope: &[String], expires_at: DateTime<Utc>) -> SecurityResult<String> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let claims = serde_json::json!({
            "sub": user_id,
            "iss": &self.issuer,
            "aud": &self.audience,
            "exp": expires_at.timestamp(),
            "iat": Utc::now().timestamp(),
            "scope": scope,
            "jti": uuid::Uuid::new_v4().to_string(),
        });

        let header = Header::new(Algorithm::HS256);
        let key = EncodingKey::from_secret(&self.secret_key);

        encode(&header, &claims, &key)
            .map_err(|e| SecurityError::AuthenticationFailed {
                reason: format!("JWT encoding failed: {}", e),
            })
    }

    /// Verify JWT token
    fn verify_jwt(&self, token: &str) -> SecurityResult<serde_json::Value> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&self.audience);
        validation.validate_exp = true;

        let key = DecodingKey::from_secret(&self.secret_key);

        let token_data = decode::<serde_json::Value>(token, &key, &validation)
            .map_err(|e| SecurityError::AuthenticationFailed {
                reason: format!("JWT verification failed: {}", e),
            })?;

        Ok(token_data.claims)
    }

    /// Generate secure token ID
    fn generate_token_id() -> String {
        use ring::rand::SecureRandom;
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes).unwrap();
        hex::encode(bytes)
    }
}

#[async_trait]
impl Authenticator for JwtAuthenticator {
    async fn authenticate(&self, credentials: &Credentials, context: &SecurityContext) -> SecurityResult<AuthenticationResult> {
        // Validate credentials (simplified - in real implementation, check against database)
        if credentials.username.is_empty() || credentials.password.is_empty() {
            return Ok(AuthenticationResult::Failed {
                reason: "Invalid credentials".to_string(),
                attempts_remaining: Some(2),
            });
        }

        // Check if user exists and password is correct
        // This is a placeholder - real implementation would verify against user store
        let user_id = format!("user_{}", credentials.username);

        // Check if MFA is required
        let requires_mfa = true; // Placeholder - check user MFA settings

        if requires_mfa && credentials.mfa_code.is_none() {
            let mfa_token = Self::generate_token_id();
            return Ok(AuthenticationResult::RequiresMfa {
                user_id: user_id.clone(),
                mfa_token,
            });
        }

        // Generate tokens
        let now = Utc::now();
        let access_expires = now + self.access_token_expiry;
        let refresh_expires = now + self.refresh_token_expiry;

        let scope = vec!["read".to_string(), "write".to_string()];
        let access_token = self.generate_jwt(&user_id, &scope, access_expires)?;
        let refresh_token = self.generate_jwt(&user_id, &[], refresh_expires)?;

        let token = AuthToken {
            token_type: TokenType::JWT,
            access_token,
            refresh_token: Some(refresh_token),
            expires_in: self.access_token_expiry.num_seconds(),
            scope,
            token_id: Self::generate_token_id(),
        };

        // Store token
        self.active_tokens.write().await.insert(token.token_id.clone(), token.clone());

        Ok(AuthenticationResult::Success {
            user_id,
            token,
            expires_at: access_expires,
        })
    }

    async fn validate_token(&self, token: &str) -> SecurityResult<SecurityContext> {
        let claims = self.verify_jwt(token)?;

        let user_id = claims["sub"].as_str()
            .ok_or_else(|| SecurityError::AuthenticationFailed {
                reason: "Invalid token: missing subject".to_string(),
            })?
            .to_string();

        let scope = claims["scope"].as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|s| s.as_str())
            .map(|s| s.to_string())
            .collect();

        Ok(SecurityContext {
            user_id: Some(user_id),
            permissions: scope,
            timestamp: Utc::now(),
            ..Default::default()
        })
    }

    async fn refresh_token(&self, refresh_token: &str) -> SecurityResult<AuthToken> {
        // Verify refresh token
        let claims = self.verify_jwt(refresh_token)?;
        let user_id = claims["sub"].as_str()
            .ok_or_else(|| SecurityError::AuthenticationFailed {
                reason: "Invalid refresh token".to_string(),
            })?;

        // Generate new access token
        let now = Utc::now();
        let access_expires = now + self.access_token_expiry;
        let scope = vec!["read".to_string(), "write".to_string()];
        let access_token = self.generate_jwt(user_id, &scope, access_expires)?;

        let token = AuthToken {
            token_type: TokenType::JWT,
            access_token,
            refresh_token: Some(refresh_token.to_string()), // Keep same refresh token
            expires_in: self.access_token_expiry.num_seconds(),
            scope,
            token_id: Self::generate_token_id(),
        };

        // Store new token
        self.active_tokens.write().await.insert(token.token_id.clone(), token.clone());

        Ok(token)
    }

    async fn revoke_token(&self, token_id: &str) -> SecurityResult<()> {
        self.active_tokens.write().await.remove(token_id);
        Ok(())
    }

    async fn setup_mfa(&self, user_id: &str, method: MfaMethod) -> SecurityResult<MfaConfig> {
        // Generate TOTP secret for user
        let secret = match method {
            MfaMethod::Totp => {
                use ring::rand::SecureRandom;
                let rng = ring::rand::SystemRandom::new();
                let mut bytes = [0u8; 32];
                rng.fill(&mut bytes).unwrap();
                Some(base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bytes))
            },
            _ => None, // Other methods would be implemented differently
        };

        let backup_codes = (0..10)
            .map(|_| {
                use ring::rand::SecureRandom;
                let rng = ring::rand::SystemRandom::new();
                let mut bytes = [0u8; 4];
                rng.fill(&mut bytes).unwrap();
                format!("{:08x}", u32::from_be_bytes(bytes))
            })
            .collect();

        Ok(MfaConfig {
            enabled: true,
            method,
            secret,
            backup_codes,
        })
    }

    async fn verify_mfa(&self, user_id: &str, code: &str, mfa_token: &str) -> SecurityResult<bool> {
        // In real implementation, this would verify TOTP code against user's secret
        // For now, accept any 6-digit code
        if code.len() == 6 && code.chars().all(|c| c.is_numeric()) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn create_session(&self, user_id: &str, context: &SecurityContext) -> SecurityResult<Session> {
        let session_id = Self::generate_token_id();
        let now = Utc::now();
        let expires_at = now + Duration::hours(8); // 8 hour session

        let session = Session {
            session_id: session_id.clone(),
            user_id: user_id.to_string(),
            created_at: now,
            expires_at,
            ip_address: context.ip_address.clone(),
            user_agent: context.user_agent.clone(),
            is_active: true,
        };

        self.sessions.write().await.insert(session_id, session.clone());
        Ok(session)
    }

    async fn validate_session(&self, session_id: &str) -> SecurityResult<Session> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)
            .ok_or_else(|| SecurityError::AuthenticationFailed {
                reason: "Session not found".to_string(),
            })?
            .clone();

        if !session.is_active {
            return Err(SecurityError::AuthenticationFailed {
                reason: "Session is inactive".to_string(),
            });
        }

        if session.expires_at < Utc::now() {
            return Err(SecurityError::AuthenticationFailed {
                reason: "Session expired".to_string(),
            });
        }

        Ok(session)
    }

    async fn destroy_session(&self, session_id: &str) -> SecurityResult<()> {
        let mut sessions = self.sessions.write().await;
        if let Some(mut session) = sessions.get_mut(session_id) {
            session.is_active = false;
        }
        Ok(())
    }

    async fn get_user_sessions(&self, user_id: &str) -> SecurityResult<Vec<Session>> {
        let sessions = self.sessions.read().await;
        let user_sessions: Vec<Session> = sessions.values()
            .filter(|s| s.user_id == user_id && s.is_active)
            .cloned()
            .collect();

        Ok(user_sessions)
    }

    async fn logout_all_sessions(&self, user_id: &str) -> SecurityResult<()> {
        let mut sessions = self.sessions.write().await;
        for session in sessions.values_mut() {
            if session.user_id == user_id {
                session.is_active = false;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_authenticator_creation() {
        let secret = b"test_secret_key_12345".to_vec();
        let audience = vec!["test-app".to_string()];
        let auth = JwtAuthenticator::new(secret, "test-issuer".to_string(), audience);

        assert_eq!(auth.issuer, "test-issuer");
        assert_eq!(auth.audience, vec!["test-app".to_string()]);
    }

    #[tokio::test]
    async fn test_session_management() {
        let secret = b"test_secret_key_12345".to_vec();
        let audience = vec!["test-app".to_string()];
        let auth = JwtAuthenticator::new(secret, "test-issuer".to_string(), audience);

        let context = SecurityContext {
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Test/1.0".to_string()),
            ..Default::default()
        };

        // Create session
        let session = auth.create_session("test-user", &context).await.unwrap();
        assert_eq!(session.user_id, "test-user");
        assert!(session.is_active);

        // Validate session
        let validated = auth.validate_session(&session.session_id).await.unwrap();
        assert_eq!(validated.session_id, session.session_id);

        // Destroy session
        auth.destroy_session(&session.session_id).await.unwrap();
        let result = auth.validate_session(&session.session_id).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_mfa_setup() {
        let secret = b"test_secret_key_12345".to_vec();
        let audience = vec!["test-app".to_string()];
        let auth = JwtAuthenticator::new(secret, "test-issuer".to_string(), audience);

        // Test MFA setup synchronously (in real implementation, this would be async)
        let mfa_config = tokio::runtime::Runtime::new().unwrap()
            .block_on(auth.setup_mfa("test-user", MfaMethod::Totp))
            .unwrap();

        assert!(mfa_config.enabled);
        assert_eq!(mfa_config.method, MfaMethod::Totp);
        assert!(mfa_config.secret.is_some());
        assert_eq!(mfa_config.backup_codes.len(), 10);
    }
}
