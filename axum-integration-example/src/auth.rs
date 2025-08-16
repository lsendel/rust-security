use crate::{AppError, Claims, UserRole};
use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

#[cfg(feature = "auth")]
use {
    bcrypt::{hash, verify, DEFAULT_COST},
    jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation},
    std::time::{SystemTime, UNIX_EPOCH},
};

/// JWT service for token generation and validation
#[derive(Clone)]
pub struct JwtService {
    #[cfg(feature = "auth")]
    secret: String,
    #[cfg(feature = "auth")]
    expiration_hours: u64,
}

impl JwtService {
    /// Create a new JWT service
    pub fn new(secret: String, expiration_hours: Option<u64>) -> Self {
        Self {
            #[cfg(feature = "auth")]
            secret,
            #[cfg(feature = "auth")]
            expiration_hours: expiration_hours.unwrap_or(24),
        }
    }

    #[cfg(feature = "auth")]
    /// Generate a JWT token for a user
    pub fn generate_token(&self, user_id: i32, email: &str, role: UserRole) -> Result<String, AppError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AppError::Internal)?
            .as_secs();

        let exp = now + (self.expiration_hours * 3600);

        let claims = Claims {
            sub: user_id,
            email: email.to_string(),
            role,
            exp: exp as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
        .map_err(|_| AppError::Auth("Failed to generate token".to_string()))
    }

    #[cfg(feature = "auth")]
    /// Validate a JWT token and return claims
    pub fn validate_token(&self, token: &str) -> Result<Claims, AppError> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::default(),
        )
        .map_err(|_| AppError::Auth("Invalid token".to_string()))?;

        Ok(token_data.claims)
    }

    #[cfg(not(feature = "auth"))]
    /// Generate a JWT token for a user (stub implementation)
    pub fn generate_token(&self, _user_id: i32, _email: &str, _role: UserRole) -> Result<String, AppError> {
        Err(AppError::Auth("Authentication feature not enabled".to_string()))
    }

    #[cfg(not(feature = "auth"))]
    /// Validate a JWT token and return claims (stub implementation)
    pub fn validate_token(&self, _token: &str) -> Result<Claims, AppError> {
        Err(AppError::Auth("Authentication feature not enabled".to_string()))
    }
}

/// Password service for hashing and verification
pub struct PasswordService;

impl PasswordService {
    #[cfg(feature = "auth")]
    /// Hash a password using bcrypt
    pub fn hash_password(password: &str) -> Result<String, AppError> {
        hash(password, DEFAULT_COST)
            .map_err(|_| AppError::Auth("Failed to hash password".to_string()))
    }

    #[cfg(feature = "auth")]
    /// Verify a password against a hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
        verify(password, hash)
            .map_err(|_| AppError::Auth("Failed to verify password".to_string()))
    }

    #[cfg(not(feature = "auth"))]
    /// Hash a password using bcrypt (stub implementation)
    pub fn hash_password(_password: &str) -> Result<String, AppError> {
        Ok("stub_hash".to_string())
    }

    #[cfg(not(feature = "auth"))]
    /// Verify a password against a hash (stub implementation)
    pub fn verify_password(_password: &str, _hash: &str) -> Result<bool, AppError> {
        Ok(true) // Always return true for stub
    }
}

/// Authentication middleware to validate JWT tokens
pub async fn auth_middleware(
    State(jwt_service): State<Arc<JwtService>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            header.strip_prefix("Bearer ").unwrap_or("")
        }
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    match jwt_service.validate_token(token) {
        Ok(claims) => {
            // Add claims to request extensions for use in handlers
            req.extensions_mut().insert(claims);
            Ok(next.run(req).await)
        }
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Authorization middleware to check user roles
pub fn require_role(required_role: UserRole) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> + Clone {
    move |req: Request, next: Next| {
        let required_role = required_role.clone();
        Box::pin(async move {
            let claims = req
                .extensions()
                .get::<Claims>()
                .ok_or(StatusCode::UNAUTHORIZED)?;

            match (&claims.role, &required_role) {
                (UserRole::Admin, _) => Ok(next.run(req).await), // Admin can access everything
                (user_role, required) if user_role == required => Ok(next.run(req).await),
                _ => Err(StatusCode::FORBIDDEN),
            }
        })
    }
}

/// Extract user claims from request extensions
pub fn extract_user_claims(req: &Request) -> Option<&Claims> {
    req.extensions().get::<Claims>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_service_creation() {
        let service = JwtService::new("test_secret".to_string(), Some(24));
        assert_eq!(service.expiration_hours, 24);
    }

    #[cfg(feature = "auth")]
    #[test]
    fn test_password_hashing() {
        let password = "test_password";
        let hash = PasswordService::hash_password(password).unwrap();
        
        assert!(PasswordService::verify_password(password, &hash).unwrap());
        assert!(!PasswordService::verify_password("wrong_password", &hash).unwrap());
    }

    #[cfg(feature = "auth")]
    #[test]
    fn test_jwt_token_generation_and_validation() {
        let service = JwtService::new("test_secret".to_string(), Some(1));
        
        let token = service.generate_token(1, "test@example.com", UserRole::User).unwrap();
        let claims = service.validate_token(&token).unwrap();
        
        assert_eq!(claims.sub, 1);
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.role, UserRole::User);
    }

    #[test]
    fn test_password_service_without_auth_feature() {
        // This should work even without auth feature
        let hash = PasswordService::hash_password("test").unwrap();
        let verified = PasswordService::verify_password("test", &hash).unwrap();
        
        #[cfg(not(feature = "auth"))]
        {
            assert_eq!(hash, "stub_hash");
            assert!(verified);
        }
    }
}