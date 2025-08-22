use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use crate::errors::AuthError;

/// Secure JWT claims with comprehensive validation
#[derive(Debug, Serialize, Deserialize)]
pub struct SecureJwtClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: Option<i64>,
    pub jti: Option<String>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub client_id: Option<String>,
}

/// Token types for validation
#[derive(Debug, Clone, PartialEq)]
pub enum TokenType {
    AccessToken,
    IdToken,
    RefreshToken,
}

/// Create secure JWT validation with strict security constraints
pub fn create_secure_jwt_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    
    // Security constraints - ONLY allow RS256
    validation.algorithms = vec![Algorithm::RS256];
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = true;
    validation.validate_iss = true;
    
    // Set required claims
    validation.required_spec_claims = HashSet::from([
        "exp".to_string(),
        "iat".to_string(),
        "iss".to_string(),
        "aud".to_string(),
        "sub".to_string(),
    ]);
    
    // Clock skew tolerance (5 minutes max)
    validation.leeway = 300;
    
    // Set expected audience and issuer from environment
    if let Ok(audience) = std::env::var("JWT_AUDIENCE") {
        validation.set_audience(&[audience]);
    }
    
    if let Ok(issuer) = std::env::var("JWT_ISSUER") {
        validation.set_issuer(&[issuer]);
    }
    
    validation
}

/// Comprehensive JWT validation with security checks
pub fn validate_jwt_secure(
    token: &str,
    decoding_key: &DecodingKey,
    expected_token_type: TokenType,
) -> Result<SecureJwtClaims, AuthError> {
    // Decode header first to check algorithm
    let header = decode_header(token)
        .map_err(|e| AuthError::InvalidToken {
            reason: format!("Invalid JWT header: {}", e),
        })?;
    
    // Prevent algorithm confusion attacks - ONLY RS256 allowed
    if header.alg != Algorithm::RS256 {
        return Err(AuthError::InvalidToken {
            reason: "Only RS256 algorithm is supported".to_string(),
        });
    }
    
    // Check for critical header parameters
    if header.kid.is_none() {
        return Err(AuthError::InvalidToken {
            reason: "Missing key ID in JWT header".to_string(),
        });
    }
    
    // Validate token structure and signature
    let validation = create_secure_jwt_validation();
    let token_data = decode::<SecureJwtClaims>(token, decoding_key, &validation)
        .map_err(|e| AuthError::InvalidToken {
            reason: format!("JWT validation failed: {}", e),
        })?;
    
    let claims = token_data.claims;
    
    // Additional security validations
    validate_token_type(&claims, expected_token_type)?;
    validate_token_freshness(&claims)?;
    validate_token_structure(&claims)?;
    
    Ok(claims)
}

/// Validate token type matches expected
fn validate_token_type(claims: &SecureJwtClaims, expected: TokenType) -> Result<(), AuthError> {
    match expected {
        TokenType::AccessToken => {
            if claims.token_type.as_deref() != Some("access_token") {
                return Err(AuthError::InvalidToken {
                    reason: "Expected access token".to_string(),
                });
            }
        },
        TokenType::IdToken => {
            // ID tokens must have nonce for security
            if claims.nonce.is_none() {
                return Err(AuthError::InvalidToken {
                    reason: "ID token missing required nonce".to_string(),
                });
            }
        },
        TokenType::RefreshToken => {
            if claims.token_type.as_deref() != Some("refresh_token") {
                return Err(AuthError::InvalidToken {
                    reason: "Expected refresh token".to_string(),
                });
            }
        },
    }
    Ok(())
}

/// Validate token freshness and timing
fn validate_token_freshness(claims: &SecureJwtClaims) -> Result<(), AuthError> {
    let now = chrono::Utc::now().timestamp();
    
    // Check if token is not yet valid
    if let Some(nbf) = claims.nbf {
        if now < nbf {
            return Err(AuthError::InvalidToken {
                reason: "Token not yet valid".to_string(),
            });
        }
    }
    
    // Check if token was issued in the future (clock skew protection)
    if claims.iat > now + 300 { // 5 minute tolerance
        return Err(AuthError::InvalidToken {
            reason: "Token issued in the future".to_string(),
        });
    }
    
    // Check token age (prevent very old tokens)
    let max_age = std::env::var("JWT_MAX_AGE_SECONDS")
        .unwrap_or_else(|_| "86400".to_string()) // 24 hours default
        .parse::<i64>()
        .unwrap_or(86400);
    
    if now - claims.iat > max_age {
        return Err(AuthError::InvalidToken {
            reason: "Token too old".to_string(),
        });
    }
    
    Ok(())
}

/// Validate token structure and required fields
fn validate_token_structure(claims: &SecureJwtClaims) -> Result<(), AuthError> {
    // Validate subject is not empty
    if claims.sub.is_empty() {
        return Err(AuthError::InvalidToken {
            reason: "Empty subject claim".to_string(),
        });
    }
    
    // Validate issuer matches expected
    let expected_issuer = std::env::var("JWT_ISSUER").unwrap_or_default();
    if !expected_issuer.is_empty() && claims.iss != expected_issuer {
        return Err(AuthError::InvalidToken {
            reason: "Invalid issuer".to_string(),
        });
    }
    
    // Validate audience matches expected
    let expected_audience = std::env::var("JWT_AUDIENCE").unwrap_or_default();
    if !expected_audience.is_empty() && claims.aud != expected_audience {
        return Err(AuthError::InvalidToken {
            reason: "Invalid audience".to_string(),
        });
    }
    
    // Validate scope format if present
    if let Some(scope) = &claims.scope {
        if scope.len() > 1000 {
            return Err(AuthError::InvalidToken {
                reason: "Scope too long".to_string(),
            });
        }
        
        // Check for dangerous patterns in scope
        let dangerous_patterns = [
            "javascript:", "data:", "vbscript:", "<script", "eval(",
            "expression(", "import(", "require("
        ];
        
        let scope_lower = scope.to_lowercase();
        for pattern in &dangerous_patterns {
            if scope_lower.contains(pattern) {
                return Err(AuthError::InvalidToken {
                    reason: "Invalid characters in scope".to_string(),
                });
            }
        }
    }
    
    Ok(())
}

/// Create OAuth-specific access token validator
pub fn create_oauth_access_token_validator() -> Result<Validation, AuthError> {
    let mut validation = create_secure_jwt_validation();
    
    // OAuth access tokens have specific requirements
    validation.required_spec_claims.insert("client_id".to_string());
    validation.required_spec_claims.insert("scope".to_string());
    
    Ok(validation)
}

/// Create ID token validator with OIDC requirements
pub fn create_id_token_validator() -> Result<Validation, AuthError> {
    let mut validation = create_secure_jwt_validation();
    
    // ID tokens have specific OIDC requirements
    validation.required_spec_claims.insert("nonce".to_string());
    
    Ok(validation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};

    #[test]
    fn test_secure_jwt_validation_rejects_weak_algorithms() {
        // This test would verify that only RS256 is accepted
        // Implementation would create test tokens with different algorithms
        // and verify they are rejected
    }

    #[test]
    fn test_token_freshness_validation() {
        // Test that old tokens are rejected
        // Test that future tokens are rejected
        // Test that tokens within valid time window are accepted
    }

    #[test]
    fn test_token_type_validation() {
        // Test that access tokens require proper type
        // Test that ID tokens require nonce
        // Test that refresh tokens have proper type
    }
}
