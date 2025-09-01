//! Cryptographic Service
//!
//! Provides cryptographic operations for the application.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::entities::{Session, User};
use crate::domain::value_objects::PasswordHash;

/// Cryptographic service errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Password hashing failed: {0}")]
    PasswordHash(String),
    #[error("Password verification failed: {0}")]
    PasswordVerify(String),
    #[error("JWT encoding failed: {0}")]
    JwtEncode(String),
    #[error("JWT decoding failed: {0}")]
    JwtDecode(String),
    #[error("Invalid token")]
    InvalidToken,
}

/// JWT claims for access tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,        // User ID
    pub email: String,      // User email
    pub name: String,       // User name
    pub roles: Vec<String>, // User roles
    pub exp: i64,           // Expiration time
    pub iat: i64,           // Issued at time
    pub iss: String,        // Issuer
    pub aud: String,        // Audience
    pub jti: String,        // JWT ID
    pub session_id: String, // Session ID
}

/// JWT claims for refresh tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,        // User ID
    pub exp: i64,           // Expiration time
    pub iat: i64,           // Issued at time
    pub iss: String,        // Issuer
    pub jti: String,        // JWT ID
    pub session_id: String, // Session ID
}

/// Cryptographic service trait
#[async_trait]
pub trait CryptoServiceTrait: Send + Sync {
    async fn hash_password(&self, password: &str) -> Result<PasswordHash, CryptoError>;
    async fn verify_password(
        &self,
        password: &str,
        hash: &PasswordHash,
    ) -> Result<bool, CryptoError>;
    async fn generate_access_token(
        &self,
        user: &User,
        session: &Session,
    ) -> Result<String, CryptoError>;
    async fn generate_refresh_token(
        &self,
        user: &User,
        session: &Session,
    ) -> Result<String, CryptoError>;
    async fn validate_refresh_token(&self, token: &str) -> Result<(User, Session), CryptoError>;
}

/// Cryptographic service implementation
pub struct CryptoService {
    jwt_secret: String,
    jwt_issuer: String,
    jwt_audience: String,
}

impl CryptoService {
    /// Create a new crypto service
    pub fn new(jwt_secret: String) -> Self {
        Self {
            jwt_secret,
            jwt_issuer: "rust-security-auth-service".to_string(),
            jwt_audience: "rust-security-platform".to_string(),
        }
    }

    /// Create crypto service with custom issuer and audience
    pub fn with_issuer_and_audience(jwt_secret: String, issuer: String, audience: String) -> Self {
        Self {
            jwt_secret,
            jwt_issuer: issuer,
            jwt_audience: audience,
        }
    }
}

#[async_trait]
impl CryptoServiceTrait for CryptoService {
    async fn hash_password(&self, password: &str) -> Result<PasswordHash, CryptoError> {
        // Use Argon2 for secure password hashing
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Argon2,
        };

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| CryptoError::PasswordHash(e.to_string()))?;

        PasswordHash::new(password_hash.to_string())
            .map_err(|e| CryptoError::PasswordHash(e.to_string()))
    }

    async fn verify_password(
        &self,
        password: &str,
        hash: &PasswordHash,
    ) -> Result<bool, CryptoError> {
        use argon2::{
            password_hash::{PasswordHash as ArgonPasswordHash, PasswordVerifier},
            Argon2,
        };

        let parsed_hash = ArgonPasswordHash::new(hash.as_str())
            .map_err(|e| CryptoError::PasswordVerify(e.to_string()))?;

        let argon2 = Argon2::default();

        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    async fn generate_access_token(
        &self,
        user: &User,
        session: &Session,
    ) -> Result<String, CryptoError> {
        let now = Utc::now();
        let expires_at = now + Duration::hours(1); // 1 hour

        let claims = AccessTokenClaims {
            sub: user.id.as_str().to_string(),
            email: user.email.as_str().to_string(),
            name: user.name.clone().unwrap_or_default(),
            roles: user.roles.iter().cloned().collect(),
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            iss: self.jwt_issuer.clone(),
            aud: self.jwt_audience.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
        };

        let header = Header::new(Algorithm::HS256);
        let key = EncodingKey::from_secret(self.jwt_secret.as_ref());

        encode(&header, &claims, &key).map_err(|e| CryptoError::JwtEncode(e.to_string()))
    }

    async fn generate_refresh_token(
        &self,
        user: &User,
        session: &Session,
    ) -> Result<String, CryptoError> {
        let now = Utc::now();
        let expires_at = now + Duration::days(30); // 30 days

        let claims = RefreshTokenClaims {
            sub: user.id.as_str().to_string(),
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            iss: self.jwt_issuer.clone(),
            jti: uuid::Uuid::new_v4().to_string(),
            session_id: session.id.clone(),
        };

        let header = Header::new(Algorithm::HS256);
        let key = EncodingKey::from_secret(self.jwt_secret.as_ref());

        encode(&header, &claims, &key).map_err(|e| CryptoError::JwtEncode(e.to_string()))
    }

    async fn validate_refresh_token(&self, token: &str) -> Result<(User, Session), CryptoError> {
        let key = DecodingKey::from_secret(self.jwt_secret.as_ref());
        let validation = Validation::new(Algorithm::HS256);

        let token_data = decode::<RefreshTokenClaims>(token, &key, &validation)
            .map_err(|_| CryptoError::InvalidToken)?;

        let _claims = token_data.claims;

        // For now, return a basic user and session
        // In a real implementation, you'd fetch these from repositories
        // This is just a placeholder for the interface
        Err(CryptoError::InvalidToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_password_hashing() {
        let crypto = CryptoService::new("test-secret".to_string());

        let password = "test-password-123";
        let hash = crypto.hash_password(password).await.unwrap();

        assert!(crypto.verify_password(password, &hash).await.unwrap());
        assert!(!crypto
            .verify_password("wrong-password", &hash)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_jwt_token_generation() {
        let crypto = CryptoService::new("test-secret".to_string());

        // Create a test user and session
        let user_id = crate::domain::value_objects::UserId::new();
        let email = crate::domain::value_objects::Email::new("test@example.com").unwrap();
        let password_hash = crypto.hash_password("password").await.unwrap();

        let user = User::new(email, password_hash, "Test User".to_string());
        let session = Session::new(user_id, Utc::now());

        let access_token = crypto.generate_access_token(&user, &session).await.unwrap();
        assert!(!access_token.is_empty());

        let refresh_token = crypto
            .generate_refresh_token(&user, &session)
            .await
            .unwrap();
        assert!(!refresh_token.is_empty());
    }
}
