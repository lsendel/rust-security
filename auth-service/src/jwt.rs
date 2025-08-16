use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,           // Subject (client_id)
    pub exp: i64,              // Expiration time
    pub iat: i64,              // Issued at
    pub iss: String,           // Issuer
    pub aud: String,           // Audience
    pub scope: Option<String>, // OAuth scopes
    pub jti: String,           // JWT ID (unique identifier)
}

#[derive(Debug)]
pub enum TokenError {
    InvalidToken,
    ExpiredToken,
    InvalidSignature,
    MissingClaims,
    EncodingError(jsonwebtoken::errors::Error),
}

impl From<jsonwebtoken::errors::Error> for TokenError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => TokenError::ExpiredToken,
            jsonwebtoken::errors::ErrorKind::InvalidSignature => TokenError::InvalidSignature,
            _ => TokenError::EncodingError(err),
        }
    }
}

pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    audience: String,
}

impl JwtManager {
    pub fn new(secret: &str, issuer: String, audience: String) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_ref()),
            decoding_key: DecodingKey::from_secret(secret.as_ref()),
            issuer,
            audience,
        }
    }

    pub fn create_token(
        &self,
        client_id: &str,
        scope: Option<String>,
        expires_in_seconds: i64,
    ) -> Result<String, TokenError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(expires_in_seconds);

        let claims = Claims {
            sub: client_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            scope,
            jti: uuid::Uuid::new_v4().to_string(),
        };

        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &self.encoding_key).map_err(TokenError::from)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, TokenError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    pub fn is_token_expired(&self, token: &str) -> bool {
        match self.validate_token(token) {
            Ok(_) => false,
            Err(TokenError::ExpiredToken) => true,
            Err(_) => true, // Treat any other error as expired for safety
        }
    }

    pub fn extract_client_id(&self, token: &str) -> Result<String, TokenError> {
        let claims = self.validate_token(token)?;
        Ok(claims.sub)
    }

    pub fn extract_scopes(&self, token: &str) -> Result<Vec<String>, TokenError> {
        let claims = self.validate_token(token)?;
        Ok(claims
            .scope
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default())
    }
}

/// Validate that requested scopes are allowed
pub fn validate_scopes(requested: &[String], allowed: &[String]) -> bool {
    let allowed_set: HashSet<&String> = allowed.iter().collect();
    requested.iter().all(|scope| allowed_set.contains(scope))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_jwt_manager() -> JwtManager {
        JwtManager::new(
            "test_secret_key_for_testing_only",
            "test-issuer".to_string(),
            "test-audience".to_string(),
        )
    }

    #[test]
    fn test_create_and_validate_token() {
        let jwt_manager = create_test_jwt_manager();

        let token = jwt_manager
            .create_token("test_client", Some("read write".to_string()), 3600)
            .unwrap();

        let claims = jwt_manager.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "test_client");
        assert_eq!(claims.scope, Some("read write".to_string()));
        assert_eq!(claims.iss, "test-issuer");
        assert_eq!(claims.aud, "test-audience");
    }

    #[test]
    fn test_expired_token() {
        let jwt_manager = create_test_jwt_manager();

        // Create token that expires in the past
        let token = jwt_manager
            .create_token("test_client", None, -3600)
            .unwrap();

        assert!(jwt_manager.is_token_expired(&token));
    }

    #[test]
    fn test_extract_client_id() {
        let jwt_manager = create_test_jwt_manager();

        let token = jwt_manager
            .create_token("test_client_123", None, 3600)
            .unwrap();

        let client_id = jwt_manager.extract_client_id(&token).unwrap();
        assert_eq!(client_id, "test_client_123");
    }

    #[test]
    fn test_extract_scopes() {
        let jwt_manager = create_test_jwt_manager();

        let token = jwt_manager
            .create_token("test_client", Some("read write admin".to_string()), 3600)
            .unwrap();

        let scopes = jwt_manager.extract_scopes(&token).unwrap();
        assert_eq!(scopes, vec!["read", "write", "admin"]);
    }

    #[test]
    fn test_validate_scopes() {
        let requested = vec!["read".to_string(), "write".to_string()];
        let allowed = vec!["read".to_string(), "write".to_string(), "admin".to_string()];

        assert!(validate_scopes(&requested, &allowed));

        let invalid_requested = vec!["read".to_string(), "delete".to_string()];
        assert!(!validate_scopes(&invalid_requested, &allowed));
    }
}
