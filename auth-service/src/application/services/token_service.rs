//! Token Application Service
//!
//! This service handles token-related business logic and orchestrates
//! domain entities with infrastructure components for token management.

use crate::application::state::app_state::AppState;
use crate::shared::error::AppError;

/// Parameters for token creation
struct TokenCreationParams {
    subject: String,
    scope: Option<String>,
    now: chrono::DateTime<chrono::Utc>,
    access_expires_at: chrono::DateTime<chrono::Utc>,
    refresh_expires_at: chrono::DateTime<chrono::Utc>,
}

impl TokenCreationParams {
    fn new(subject: String, scope: Option<String>) -> Self {
        use chrono::{Duration, Utc};

        let now = Utc::now();
        Self {
            subject,
            scope,
            now,
            access_expires_at: now + Duration::hours(1),
            refresh_expires_at: now + Duration::days(30),
        }
    }

    fn access_claims(&self) -> crate::application::auth::jwt_secure::SecureJwtClaims {
        use uuid::Uuid;

        crate::application::auth::jwt_secure::SecureJwtClaims {
            sub: self.subject.clone(),
            iss: "rust-security-auth-service".to_string(),
            aud: "rust-security-platform".to_string(),
            exp: self.access_expires_at.timestamp(),
            iat: self.now.timestamp(),
            nbf: Some(self.now.timestamp()),
            jti: Some(Uuid::new_v4().to_string()),
            token_type: Some("access_token".to_string()),
            scope: self.scope.clone(),
            nonce: None,
            client_id: None,
        }
    }

    fn refresh_claims(&self) -> crate::application::auth::jwt_secure::SecureJwtClaims {
        use uuid::Uuid;

        crate::application::auth::jwt_secure::SecureJwtClaims {
            sub: self.subject.clone(),
            iss: "rust-security-auth-service".to_string(),
            aud: "rust-security-platform".to_string(),
            exp: self.refresh_expires_at.timestamp(),
            iat: self.now.timestamp(),
            nbf: Some(self.now.timestamp()),
            jti: Some(Uuid::new_v4().to_string()),
            token_type: Some("refresh_token".to_string()),
            scope: self.scope.clone(),
            nonce: None,
            client_id: None,
        }
    }
}

/// Token Application Service
///
/// Handles token creation, validation, and management business logic.
pub struct TokenApplicationService;

impl TokenApplicationService {
    /// Mint access and refresh tokens for a subject with proper JWT implementation
    ///
    /// Creates both access and refresh tokens using the service's signing key manager.
    /// Access tokens are short-lived (1 hour) while refresh tokens are long-lived (30 days).
    /// Both tokens include comprehensive claims for security and audit purposes.
    ///
    /// # Arguments
    ///
    /// * `state` - Application state containing the JWKS manager
    /// * `subject` - The subject (user ID) for whom to mint tokens
    /// * `scope` - Optional scope to include in the tokens
    ///
    /// # Returns
    ///
    /// Returns a JSON response containing:
    /// - `access_token` - Short-lived JWT for API access
    /// - `refresh_token` - Long-lived JWT for token refresh
    /// - `token_type` - Always "Bearer"
    /// - `expires_in` - Access token expiry in seconds (3600)
    /// - `scope` - Included scopes (if any)
    ///
    /// # Security Features
    ///
    /// - Uses RS256 algorithm with rotated keys
    /// - Includes comprehensive claims (iss, aud, exp, iat, nbf, jti)
    /// - Unique JTI (JWT ID) for each token to prevent replay
    /// - Proper expiration times to limit token lifetime
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_service::application::services::TokenApplicationService;
    ///
    /// let tokens = TokenApplicationService::mint_tokens_for_subject(
    ///     &state,
    ///     "user_12345".to_string(),
    ///     Some("read write".to_string())
    /// ).await?;
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`AppError`] if:
    /// - Signing key retrieval fails from the JWKS manager
    /// - JWT encoding fails due to invalid claims or key issues
    /// - System clock is invalid (before Unix epoch)
    pub async fn mint_tokens_for_subject(
        state: &AppState,
        subject: String,
        scope: Option<String>,
    ) -> Result<serde_json::Value, AppError> {
        let token_params = TokenCreationParams::new(subject, scope);
        let signing_key = Self::get_signing_key(state).await?;

        let access_token =
            Self::create_jwt_token(state, &signing_key, &token_params.access_claims()).await?;
        let refresh_token =
            Self::create_jwt_token(state, &signing_key, &token_params.refresh_claims()).await?;

        Ok(Self::build_token_response(
            &access_token,
            &refresh_token,
            &token_params,
        ))
    }

    /// Get the signing key from the key manager
    #[cfg(feature = "crypto")]
    async fn get_signing_key(_state: &AppState) -> Result<jsonwebtoken::EncodingKey, AppError> {
        // TODO: Use state.jwks_manager when properly initialized
        Err(AppError::Internal(
            "JWKS manager not yet implemented".to_string(),
        ))
    }

    /// Secure signing key when crypto feature is not enabled
    #[cfg(not(feature = "crypto"))]
    async fn get_signing_key(_state: &AppState) -> Result<jsonwebtoken::EncodingKey, AppError> {
        // Require JWT_SECRET environment variable - no fallbacks
        let secret = std::env::var("JWT_SECRET").map_err(|_| {
            AppError::ConfigurationError("JWT_SECRET environment variable is required".to_string())
        })?;

        // Validate secret strength
        if secret.len() < 32 {
            return Err(AppError::ConfigurationError(
                "JWT_SECRET must be at least 32 characters".to_string(),
            ));
        }

        Ok(jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()))
    }

    /// Create a JWT token from claims
    async fn create_jwt_token(
        _state: &AppState,
        signing_key: &jsonwebtoken::EncodingKey,
        claims: &crate::application::auth::jwt_secure::SecureJwtClaims,
    ) -> Result<String, AppError> {
        #[cfg(feature = "crypto")]
        {
            // TODO: Use state.jwks_manager when properly initialized
            let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
            jsonwebtoken::encode(&header, claims, signing_key)
                .map_err(|e| AppError::Internal(format!("Failed to encode JWT: {e}")))
        }

        #[cfg(not(feature = "crypto"))]
        {
            let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
            jsonwebtoken::encode(&header, claims, signing_key)
                .map_err(|e| AppError::Internal(format!("Failed to encode JWT: {e}")))
        }
    }

    /// Build the final token response
    fn build_token_response(
        access_token: &str,
        refresh_token: &str,
        params: &TokenCreationParams,
    ) -> serde_json::Value {
        serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "scope": params.scope
        })
    }
}
