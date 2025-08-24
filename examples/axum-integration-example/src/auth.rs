use crate::{AppError, Claims, UserRole};
use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use bcrypt::{hash, verify};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT service for token generation and validation
#[derive(Clone)]
pub struct JwtService {
    secret: String,
    expiration_hours: u64,
}

impl JwtService {
    /// Create a new JWT service with secure configuration
    pub fn new(secret: String, expiration_hours: Option<u64>) -> Result<Self, AppError> {
        if secret.len() < 32 {
            return Err(AppError::Auth("JWT secret must be at least 32 characters long for security".to_string()));
        }
        
        Ok(Self { 
            secret, 
            expiration_hours: expiration_hours.unwrap_or(24).min(168) // Cap at 7 days max
        })
    }
    
    /// Create JWT service from environment variables (recommended)
    pub fn from_env() -> Result<Self, AppError> {
        let secret = std::env::var("JWT_SECRET_KEY")
            .map_err(|_| AppError::Auth("JWT_SECRET_KEY environment variable required".to_string()))?;
            
        let expiration_hours = std::env::var("JWT_EXPIRATION_HOURS")
            .ok()
            .and_then(|h| h.parse().ok())
            .unwrap_or(24);
            
        Self::new(secret, Some(expiration_hours))
    }

    /// Generate a JWT token for a user
    pub fn generate_token(
        &self,
        user_id: i32,
        email: &str,
        role: UserRole,
    ) -> Result<String, AppError> {
        let now =
            SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| AppError::Internal)?.as_secs();

        let exp = now + (self.expiration_hours * 3600);

        let claims = Claims { sub: user_id, email: email.to_string(), role, exp: exp as usize };

        encode(&Header::default(), &claims, &EncodingKey::from_secret(self.secret.as_ref()))
            .map_err(|_| AppError::Auth("Failed to generate token".to_string()))
    }

    /// Validate a JWT token and return claims with enhanced security
    pub fn validate_token(&self, token: &str) -> Result<Claims, AppError> {
        let mut validation = Validation::default();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 30; // 30 seconds clock skew tolerance
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &validation,
        )
        .map_err(|e| {
            tracing::warn!("JWT validation failed: {}", e);
            AppError::Auth("Invalid or expired token".to_string())
        })?;

        Ok(token_data.claims)
    }

    // No stub implementations when auth is not enabled because `auth` is now default
}

/// Password service for hashing and verification with enhanced security
pub struct PasswordService;

impl PasswordService {
    /// Validate password strength before hashing
    pub fn validate_password_strength(password: &str) -> Result<(), AppError> {
        if password.len() < 12 {
            return Err(AppError::Auth("Password must be at least 12 characters long".to_string()));
        }
        
        let mut score = 0;
        if password.chars().any(|c| c.is_uppercase()) { score += 1; }
        if password.chars().any(|c| c.is_lowercase()) { score += 1; }
        if password.chars().any(|c| c.is_numeric()) { score += 1; }
        if password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)) { score += 1; }
        
        if score < 3 {
            return Err(AppError::Auth("Password must contain at least 3 of: uppercase, lowercase, numbers, special characters".to_string()));
        }
        
        // Check for common patterns
        let common_patterns = ["password", "123456", "qwerty", "admin"];
        for pattern in &common_patterns {
            if password.to_lowercase().contains(pattern) {
                return Err(AppError::Auth("Password contains common patterns and is not secure".to_string()));
            }
        }
        
        Ok(())
    }
    
    /// Hash a password using bcrypt with enhanced cost
    pub fn hash_password(password: &str) -> Result<String, AppError> {
        Self::validate_password_strength(password)?;
        
        // Use higher cost for better security (12 instead of default 4)
        let cost = std::env::var("BCRYPT_COST")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(12)
            .max(10)  // Minimum cost 10
            .min(15); // Maximum cost 15 (avoid DoS)
            
        hash(password, cost)
            .map_err(|e| {
                tracing::error!("Password hashing failed: {}", e);
                AppError::Auth("Failed to hash password".to_string())
            })
    }

    /// Verify a password against a hash with timing attack protection
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
        // Use constant-time verification to prevent timing attacks
        verify(password, hash)
            .map_err(|e| {
                tracing::warn!("Password verification failed: {}", e);
                AppError::Auth("Authentication failed".to_string())
            })
    }

    // No stub implementations when auth is not enabled because `auth` is now default
}

/// Authentication middleware to validate JWT tokens
pub async fn auth_middleware(
    State(jwt_service): State<Arc<JwtService>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get(AUTHORIZATION).and_then(|header| header.to_str().ok());

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
pub fn require_role(
    required_role: UserRole,
) -> impl Fn(
    Request,
    Next,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>,
> + Clone {
    move |req: Request, next: Next| {
        let required_role = required_role.clone();
        Box::pin(async move {
            let claims = req.extensions().get::<Claims>().ok_or(StatusCode::UNAUTHORIZED)?;

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
        let service = JwtService::new("this-is-a-test-secret-with-enough-length".to_string(), Some(24)).unwrap();
        assert_eq!(service.expiration_hours, 24);
    }

    #[cfg(feature = "auth")]
    #[test]
    fn test_password_hashing() {
        let password = "SecureTest987#"; // Strong password meeting validation criteria
        let hash = PasswordService::hash_password(password).unwrap();

        assert!(PasswordService::verify_password(password, &hash).unwrap());
        assert!(!PasswordService::verify_password("WrongPassword123!", &hash).unwrap());
    }

    #[cfg(feature = "auth")]
    #[test]
    fn test_jwt_token_generation_and_validation() {
        let service = JwtService::new("this-is-a-test-secret-with-enough-length".to_string(), Some(1)).unwrap();

        let token = service.generate_token(1, "test@example.com", UserRole::User).unwrap();
        let claims = service.validate_token(&token).unwrap();

        assert_eq!(claims.sub, 1);
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.role, UserRole::User);
    }

    #[test]
    fn test_password_service_without_auth_feature() {
        // This should work even without auth feature
        let hash = PasswordService::hash_password("SecureTest987#").unwrap();
        let _verified = PasswordService::verify_password("SecureTest987#", &hash).unwrap();

        #[cfg(not(feature = "auth"))]
        {
            assert_eq!(hash, "stub_hash");
            assert!(verified);
        }
    }
}
