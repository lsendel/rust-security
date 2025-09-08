use chrono::Utc;
use common::crypto::{JwtAlgorithm, JwtConfig};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    AccessToken,
    IdToken,
    RefreshToken,
}

/// Create secure JWT validation with strict security constraints
#[must_use]
pub fn create_secure_jwt_validation(jwt_config: &JwtConfig) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);

    // Security constraints - ONLY allow RS256
    validation.algorithms = vec![Algorithm::RS256];
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = true;
    validation.validate_exp = true;

    // Set required claims
    validation.required_spec_claims = HashSet::from([
        "exp".to_string(),
        "iat".to_string(),
        "iss".to_string(),
        "aud".to_string(),
        "sub".to_string(),
    ]);

    // Clock skew tolerance (5 minutes max) - use default 5 minutes
    validation.leeway = 300; // 5 minutes in seconds

    // Set expected audience and issuer from environment
    if let Some(ref audiences) = jwt_config.audience {
        validation.set_audience(audiences);
    }

    validation.set_issuer(&[jwt_config.issuer.clone()]);

    validation
}

/// Comprehensive JWT validation with security checks
///
/// # Errors
///
/// Returns `crate::shared::error::AppError` if:
/// - JWT header is malformed or invalid
/// - Algorithm is not RS256 (prevents algorithm confusion attacks)
/// - Key ID (kid) is missing from header
/// - JWT signature verification fails
/// - Token type doesn't match expected type
/// - Token is expired, not yet valid, or too old
/// - Required claims are missing or invalid
/// - Issuer or audience doesn't match expected values
/// - Scope contains dangerous patterns or is too long
pub fn validate_jwt_secure(
    token: &str,
    decoding_key: &DecodingKey,
    expected_token_type: TokenType,
    jwt_config: &JwtConfig,
) -> Result<SecureJwtClaims, crate::shared::error::AppError> {
    // Decode header first to check algorithm
    let header = decode_header(token).map_err(|e| {
        crate::shared::error::AppError::InvalidToken(format!("Invalid JWT header: {e}"))
    })?;

    // Prevent algorithm confusion attacks - ONLY RS256 allowed
    if header.alg != Algorithm::RS256 {
        return Err(crate::shared::error::AppError::InvalidToken(
            "Only RS256 algorithm is supported".to_string(),
        ));
    }

    // Check for critical header parameters
    if header.kid.is_none() {
        return Err(crate::shared::error::AppError::InvalidToken(
            "Missing key ID in JWT header".to_string(),
        ));
    }

    // Validate token structure and signature
    let validation = create_secure_jwt_validation(jwt_config);
    let token_data = decode::<SecureJwtClaims>(token, decoding_key, &validation).map_err(|e| {
        crate::shared::error::AppError::InvalidToken(format!("JWT validation failed: {e}"))
    })?;

    let claims = token_data.claims;

    // Additional security validations
    validate_token_type(&claims, expected_token_type)?;
    validate_token_freshness(&claims, jwt_config)?;
    validate_token_structure(&claims, jwt_config)?;

    Ok(claims)
}

/// Validate token type matches expected
fn validate_token_type(
    claims: &SecureJwtClaims,
    expected: TokenType,
) -> Result<(), crate::shared::error::AppError> {
    match expected {
        TokenType::AccessToken => {
            if claims.token_type.as_deref() != Some("access_token") {
                return Err(crate::shared::error::AppError::InvalidToken(
                    "Expected access token".to_string(),
                ));
            }
        }
        TokenType::IdToken => {
            // ID tokens must have nonce for security
            if claims.nonce.is_none() {
                return Err(crate::shared::error::AppError::InvalidToken(
                    "ID token missing required nonce".to_string(),
                ));
            }
        }
        TokenType::RefreshToken => {
            if claims.token_type.as_deref() != Some("refresh_token") {
                return Err(crate::shared::error::AppError::InvalidToken(
                    "Expected refresh token".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Validate token freshness and timing
fn validate_token_freshness(
    claims: &SecureJwtClaims,
    jwt_config: &JwtConfig,
) -> Result<(), crate::shared::error::AppError> {
    let now = chrono::Utc::now().timestamp();

    // Check if token is not yet valid
    if let Some(nbf) = claims.nbf {
        if now < nbf {
            return Err(crate::shared::error::AppError::InvalidToken(
                "Token not yet valid".to_string(),
            ));
        }
    }

    // Check if token was issued in the future (clock skew protection)
    if claims.iat > now + 300 {
        // 5 minute tolerance
        return Err(crate::shared::error::AppError::InvalidToken(
            "Token issued in the future".to_string(),
        ));
    }

    // Check token age (prevent very old tokens) - use access token TTL
    let max_age = jwt_config.access_token_ttl as i64;
    if now - claims.iat > max_age {
        return Err(crate::shared::error::AppError::InvalidToken(
            "Token too old".to_string(),
        ));
    }

    Ok(())
}

/// Validate token structure and required fields
fn validate_token_structure(
    claims: &SecureJwtClaims,
    jwt_config: &JwtConfig,
) -> Result<(), crate::shared::error::AppError> {
    // Validate subject is not empty
    if claims.sub.is_empty() {
        return Err(crate::shared::error::AppError::InvalidToken(
            "Empty subject claim".to_string(),
        ));
    }

    // Validate issuer matches expected
    if claims.iss != jwt_config.issuer {
        return Err(crate::shared::error::AppError::InvalidToken(
            "Invalid issuer".to_string(),
        ));
    }

    // Validate audience matches expected
    if let Some(ref expected_audiences) = jwt_config.audience {
        if !expected_audiences.contains(&claims.aud) {
            return Err(crate::shared::error::AppError::InvalidToken(
                "Invalid audience".to_string(),
            ));
        }
    }

    // Validate scope format if present
    if let Some(scope) = &claims.scope {
        if scope.len() > 1000 {
            return Err(crate::shared::error::AppError::InvalidToken(
                "Scope too long".to_string(),
            ));
        }

        // Check for dangerous patterns in scope
        static DANGEROUS_PATTERNS: Lazy<[&str; 8]> = Lazy::new(|| {
            [
                "javascript:",
                "data:",
                "vbscript:",
                "<script",
                "eval(",
                "expression(",
                "import(",
                "require(",
            ]
        });

        let scope_lower = scope.to_lowercase();
        if DANGEROUS_PATTERNS.iter().any(|p| scope_lower.contains(p)) {
            return Err(crate::shared::error::AppError::InvalidToken(
                "Invalid characters in scope".to_string(),
            ));
        }
    }

    Ok(())
}

/// Create OAuth-specific access token validator
///
/// # Errors
///
/// This function currently never returns an error but uses Result for future compatibility
/// with potential configuration loading failures
pub fn create_oauth_access_token_validator(jwt_config: &JwtConfig) -> Validation {
    let mut validation = create_secure_jwt_validation(jwt_config);

    // OAuth access tokens have specific requirements
    validation
        .required_spec_claims
        .insert("client_id".to_string());
    validation.required_spec_claims.insert("scope".to_string());

    validation
}

/// Create ID token validator with OIDC requirements
///
/// # Errors
///
/// This function currently never returns an error but uses Result for future compatibility
/// with potential configuration loading failures
pub fn create_id_token_validator(jwt_config: &JwtConfig) -> Validation {
    let mut validation = create_secure_jwt_validation(jwt_config);

    // ID tokens have specific OIDC requirements
    validation.required_spec_claims.insert("nonce".to_string());

    validation
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{Duration, SystemTime};

    fn create_test_claims(exp_offset_secs: i64, iat_offset_secs: i64) -> SecureJwtClaims {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        SecureJwtClaims {
            sub: "test-user".to_string(),
            iss: "test-issuer".to_string(),
            aud: "test-audience".to_string(),
            exp: now + exp_offset_secs,
            iat: now + iat_offset_secs,
            nbf: None,
            jti: Some("test-jti".to_string()),
            token_type: Some("access_token".to_string()),
            scope: Some("read".to_string()),
            nonce: None,
            client_id: None,
        }
    }

    #[test]
    fn test_secure_jwt_validation_rejects_weak_algorithms() {
        let claims = create_test_claims(3600, 0);
        let header = Header::new(Algorithm::HS256);
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .unwrap();
        let decoding_key = DecodingKey::from_secret("secret".as_ref());
        let jwt_config = JwtConfig {
            secret: "secret".to_string(),
            issuer: "test-issuer".to_string(),
            audience: Some(vec!["test-audience".to_string()]),
            access_token_ttl: 3600,
            refresh_token_ttl: 3600,
            algorithm: common::crypto::JwtAlgorithm::RS256,
            key_rotation_interval: 3600,
            token_binding: false,
            max_keys: 3,
            enable_jwks: true,
        };
        let result =
            validate_jwt_secure(&token, &decoding_key, TokenType::AccessToken, &jwt_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_freshness_validation() {
        let decoding_key = DecodingKey::from_secret("secret".as_ref());
        let encoding_key = EncodingKey::from_secret("secret".as_ref());
        let jwt_config = JwtConfig {
            secret: "secret".to_string(),
            issuer: "test-issuer".to_string(),
            audience: Some(vec!["test-audience".to_string()]),
            access_token_ttl: 3600,
            refresh_token_ttl: 3600,
            algorithm: common::crypto::JwtAlgorithm::HS256,
            key_rotation_interval: 3600,
            token_binding: false,
            max_keys: 3,
            enable_jwks: true,
        };

        // Expired token
        let claims = create_test_claims(-3600, -7200);
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &encoding_key).unwrap();
        let result =
            validate_jwt_secure(&token, &decoding_key, TokenType::AccessToken, &jwt_config);
        assert!(result.is_err());

        // Token issued in the future
        let claims = create_test_claims(3600, 3600);
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &encoding_key).unwrap();
        let result =
            validate_jwt_secure(&token, &decoding_key, TokenType::AccessToken, &jwt_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_type_validation() {
        let decoding_key = DecodingKey::from_secret("secret".as_ref());
        let encoding_key = EncodingKey::from_secret("secret".as_ref());
        let jwt_config = JwtConfig {
            secret: "secret".to_string(),
            issuer: "test-issuer".to_string(),
            audience: Some(vec!["test-audience".to_string()]),
            access_token_ttl: 3600,
            refresh_token_ttl: 3600,
            algorithm: common::crypto::JwtAlgorithm::RS256,
            key_rotation_interval: 3600,
            token_binding: false,
            max_keys: 3,
            enable_jwks: true,
        };

        // Valid access token
        let claims = create_test_claims(3600, 0);
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &encoding_key).unwrap();
        let result =
            validate_jwt_secure(&token, &decoding_key, TokenType::AccessToken, &jwt_config);
        assert!(result.is_ok());

        // ID token missing nonce
        let mut claims = create_test_claims(3600, 0);
        claims.token_type = Some("id_token".to_string());
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &encoding_key).unwrap();
        let result = validate_jwt_secure(&token, &decoding_key, TokenType::IdToken, &jwt_config);
        assert!(result.is_err());

        // Valid ID token with nonce
        claims.nonce = Some("test-nonce".to_string());
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &encoding_key).unwrap();
        let result = validate_jwt_secure(&token, &decoding_key, TokenType::IdToken, &jwt_config);
        assert!(result.is_ok());
    }
}
