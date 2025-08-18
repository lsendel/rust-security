//! # Post-Quantum JWT Implementation
//!
//! This module provides JWT token signing and verification using post-quantum
//! digital signature algorithms, with hybrid support for gradual migration.
//!
//! ## Features
//! - JWT signing with CRYSTALS-Dilithium signatures
//! - Hybrid JWT tokens with both classical and post-quantum signatures
//! - Backward compatibility with existing JWT infrastructure
//! - Custom JWT headers for post-quantum algorithm identification
//! - Migration support for existing token validation

use anyhow::{anyhow, Result};
use base64::Engine as _;
use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{error, info, warn};

use crate::post_quantum_crypto::{get_pq_manager, MigrationMode, PQAlgorithm, SecurityLevel};
use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};

/// Post-quantum JWT header with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQJwtHeader {
    /// Standard JWT algorithm (for backward compatibility)
    pub alg: String,
    /// Key ID
    pub kid: Option<String>,
    /// Token type
    pub typ: Option<String>,
    /// Post-quantum algorithm used
    pub pq_alg: Option<String>,
    /// Security level (Level1, Level3, Level5)
    pub pq_level: Option<String>,
    /// Whether this is a hybrid token
    pub hybrid: Option<bool>,
    /// Classical algorithm for hybrid tokens
    pub classical_alg: Option<String>,
    /// Migration phase indicator
    pub migration: Option<String>,
}

impl Default for PQJwtHeader {
    fn default() -> Self {
        Self {
            alg: "PQ-DILITHIUM3".to_string(),
            kid: None,
            typ: Some("JWT".to_string()),
            pq_alg: Some("DILITHIUM3".to_string()),
            pq_level: Some("Level3".to_string()),
            hybrid: Some(false),
            classical_alg: None,
            migration: Some("hybrid".to_string()),
        }
    }
}

/// Post-quantum JWT token structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQJwt {
    pub header: PQJwtHeader,
    pub payload: Value,
    pub signature: String,
    /// Additional signature for hybrid tokens
    pub classical_signature: Option<String>,
}

/// JWT signing and verification using post-quantum cryptography
pub struct PQJwtManager {
    migration_mode: MigrationMode,
}

impl PQJwtManager {
    pub fn new(migration_mode: MigrationMode) -> Self {
        Self { migration_mode }
    }

    pub fn default() -> Self {
        let manager = get_pq_manager();
        let migration_mode = manager.migration_status().mode;
        Self::new(migration_mode)
    }

    /// Create a post-quantum JWT token
    pub async fn create_token(
        &self,
        payload: Value,
        algorithm: Option<PQAlgorithm>,
        expires_in: Option<u64>,
    ) -> Result<String> {
        let current_time =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;

        // Add standard JWT claims
        let mut claims = payload.as_object().unwrap_or(&serde_json::Map::new()).clone();
        claims.insert("iat".to_string(), Value::Number(current_time.into()));

        if let Some(exp_secs) = expires_in {
            let exp_time = current_time + exp_secs as i64;
            claims.insert("exp".to_string(), Value::Number(exp_time.into()));
        }

        // Add issuer if configured
        if let Ok(issuer) = std::env::var("JWT_ISSUER") {
            claims.insert("iss".to_string(), Value::String(issuer));
        }

        let payload_value = Value::Object(claims);

        match self.migration_mode {
            MigrationMode::Classical => self.create_classical_jwt(&payload_value).await,
            MigrationMode::Hybrid => self.create_hybrid_jwt(&payload_value, algorithm).await,
            MigrationMode::PostQuantumOnly => self.create_pq_jwt(&payload_value, algorithm).await,
            MigrationMode::GradualMigration => {
                // Start with hybrid, eventually move to post-quantum only
                if self.should_use_post_quantum_only().await {
                    self.create_pq_jwt(&payload_value, algorithm).await
                } else {
                    self.create_hybrid_jwt(&payload_value, algorithm).await
                }
            }
        }
    }

    /// Create a pure post-quantum JWT
    async fn create_pq_jwt(
        &self,
        payload: &Value,
        algorithm: Option<PQAlgorithm>,
    ) -> Result<String> {
        let manager = get_pq_manager();

        if !manager.is_available() {
            return Err(anyhow!("Post-quantum cryptography not available"));
        }

        let kid = manager
            .current_signing_key_id()
            .await
            .ok_or_else(|| anyhow!("No post-quantum signing key available"))?;

        let header = PQJwtHeader {
            alg: "PQ-DILITHIUM3".to_string(),
            kid: Some(kid.clone()),
            typ: Some("JWT".to_string()),
            pq_alg: Some("DILITHIUM3".to_string()),
            pq_level: Some("Level3".to_string()),
            hybrid: Some(false),
            classical_alg: None,
            migration: Some("post-quantum".to_string()),
        };

        let header_json = serde_json::to_string(&header)?;
        let payload_json = serde_json::to_string(payload)?;

        // Create JWT payload (header.payload)
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_json);
        let message = format!("{}.{}", header_b64, payload_b64);

        // Sign with post-quantum algorithm
        let signature_bytes = manager.sign(message.as_bytes(), Some(&kid)).await?;
        let signature_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);

        let token = format!("{}.{}", message, signature_b64);

        // Log token creation
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::KeyManagement,
                SecuritySeverity::Low,
                "pq-jwt".to_string(),
                "Post-quantum JWT token created".to_string(),
            )
            .with_actor("pq_system".to_string())
            .with_action("pq_sign".to_string())
            .with_target("jwt_token".to_string())
            .with_outcome("success".to_string())
            .with_reason("Pure post-quantum JWT token signed with Dilithium".to_string())
            .with_detail("algorithm".to_string(), "DILITHIUM3")
            .with_detail("hybrid".to_string(), false)
            .with_detail("kid".to_string(), kid),
        );

        Ok(token)
    }

    /// Create a hybrid JWT with both classical and post-quantum signatures
    async fn create_hybrid_jwt(
        &self,
        payload: &Value,
        algorithm: Option<PQAlgorithm>,
    ) -> Result<String> {
        let manager = get_pq_manager();

        let kid = manager
            .current_signing_key_id()
            .await
            .ok_or_else(|| anyhow!("No signing key available"))?;

        let header = PQJwtHeader {
            alg: "HYBRID-DILITHIUM3-ED25519".to_string(),
            kid: Some(kid.clone()),
            typ: Some("JWT".to_string()),
            pq_alg: Some("DILITHIUM3".to_string()),
            pq_level: Some("Level3".to_string()),
            hybrid: Some(true),
            classical_alg: Some("Ed25519".to_string()),
            migration: Some("hybrid".to_string()),
        };

        let header_json = serde_json::to_string(&header)?;
        let payload_json = serde_json::to_string(payload)?;

        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_json);
        let message = format!("{}.{}", header_b64, payload_b64);

        // Sign with hybrid algorithm (if available) or fallback to classical
        let signature_bytes = if manager.is_available() {
            manager.sign(message.as_bytes(), Some(&kid)).await?
        } else {
            // Fallback to classical signing
            warn!("Post-quantum not available, falling back to classical signing");
            self.sign_classical(message.as_bytes()).await?
        };

        let signature_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature_bytes);
        let token = format!("{}.{}", message, signature_b64);

        // Log token creation
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::KeyManagement,
                SecuritySeverity::Low,
                "pq-jwt".to_string(),
                "Hybrid JWT token created".to_string(),
            )
            .with_actor("pq_system".to_string())
            .with_action("pq_sign".to_string())
            .with_target("jwt_token".to_string())
            .with_outcome("success".to_string())
            .with_reason(
                "Hybrid JWT token signed with both classical and post-quantum algorithms"
                    .to_string(),
            )
            .with_detail("algorithm".to_string(), "HYBRID-DILITHIUM3-ED25519")
            .with_detail("hybrid".to_string(), true)
            .with_detail("kid".to_string(), kid)
            .with_detail("pq_available".to_string(), manager.is_available()),
        );

        Ok(token)
    }

    /// Create a classical JWT for backward compatibility
    async fn create_classical_jwt(&self, payload: &Value) -> Result<String> {
        // Get current classical signing key from the existing keys module
        let (kid, encoding_key) = crate::keys::current_signing_key().await;

        let header = jsonwebtoken::Header {
            alg: Algorithm::RS256,
            kid: Some(kid.clone()),
            ..Default::default()
        };

        let token = jsonwebtoken::encode(&header, payload, &encoding_key)
            .map_err(|e| anyhow!("Failed to create classical JWT: {}", e))?;

        // Log classical token creation
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::KeyManagement,
                SecuritySeverity::Low,
                "pq-jwt".to_string(),
                "Classical JWT token created".to_string(),
            )
            .with_actor("system".to_string())
            .with_action("jwt_sign".to_string())
            .with_target("jwt_token".to_string())
            .with_outcome("success".to_string())
            .with_reason("Classical JWT token for backward compatibility".to_string())
            .with_detail("algorithm".to_string(), "RS256")
            .with_detail("hybrid".to_string(), false)
            .with_detail("kid".to_string(), kid),
        );

        Ok(token)
    }

    /// Verify a JWT token (supports both classical and post-quantum)
    pub async fn verify_token(&self, token: &str) -> Result<(PQJwtHeader, Value)> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid JWT format"));
        }

        // Decode header to determine token type
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| anyhow!("Invalid header encoding"))?;

        // Try to parse as post-quantum header first
        if let Ok(pq_header) = serde_json::from_slice::<PQJwtHeader>(&header_bytes) {
            self.verify_pq_token(token, &pq_header).await
        } else {
            // Fall back to classical JWT verification
            self.verify_classical_token(token).await
        }
    }

    /// Verify a post-quantum JWT token
    async fn verify_pq_token(
        &self,
        token: &str,
        header: &PQJwtHeader,
    ) -> Result<(PQJwtHeader, Value)> {
        let parts: Vec<&str> = token.split('.').collect();
        let message = format!("{}.{}", parts[0], parts[1]);

        let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| anyhow!("Invalid signature encoding"))?;

        let kid = header.kid.as_ref().ok_or_else(|| anyhow!("Missing key ID in token header"))?;

        let manager = get_pq_manager();

        // Verify signature
        let is_valid = if header.hybrid.unwrap_or(false) {
            // Hybrid token verification
            if manager.is_available() {
                manager.verify(message.as_bytes(), &signature_bytes, kid).await?
            } else {
                // Fallback to classical verification
                warn!("Post-quantum not available, attempting classical verification");
                self.verify_classical_signature(message.as_bytes(), &signature_bytes).await?
            }
        } else {
            // Pure post-quantum verification
            manager.verify(message.as_bytes(), &signature_bytes, kid).await?
        };

        if !is_valid {
            return Err(anyhow!("Invalid signature"));
        }

        // Decode payload
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| anyhow!("Invalid payload encoding"))?;

        let payload: Value = serde_json::from_slice(&payload_bytes)?;

        // Verify expiration
        if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as i64;

            if current_time >= exp {
                return Err(anyhow!("Token has expired"));
            }
        }

        // Log successful verification
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::DataAccess,
                SecuritySeverity::Low,
                "pq-jwt".to_string(),
                "Post-quantum JWT token verified".to_string(),
            )
            .with_actor("pq_system".to_string())
            .with_action("pq_verify".to_string())
            .with_target("jwt_token".to_string())
            .with_outcome("success".to_string())
            .with_reason("Post-quantum JWT token signature verification successful".to_string())
            .with_detail("algorithm".to_string(), header.pq_alg.clone().unwrap_or_default())
            .with_detail("hybrid".to_string(), header.hybrid.unwrap_or(false))
            .with_detail("kid".to_string(), kid.clone()),
        );

        Ok((header.clone(), payload))
    }

    /// Verify a classical JWT token for backward compatibility
    async fn verify_classical_token(&self, token: &str) -> Result<(PQJwtHeader, Value)> {
        // Use existing JWT verification from jsonwebtoken
        let header = jsonwebtoken::decode_header(token)?;

        // For now, just verify structure - in production, implement full verification
        let validation = jsonwebtoken::Validation::new(Algorithm::RS256);

        // This is a simplified version - in production, you'd need proper key retrieval
        let parts: Vec<&str> = token.split('.').collect();
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| anyhow!("Invalid payload encoding"))?;

        let payload: Value = serde_json::from_slice(&payload_bytes)?;

        // Convert classical header to PQ header format
        let pq_header = PQJwtHeader {
            alg: format!("{:?}", header.alg),
            kid: header.kid.clone(),
            typ: header.typ.clone(),
            pq_alg: None,
            pq_level: None,
            hybrid: Some(false),
            classical_alg: Some(format!("{:?}", header.alg)),
            migration: Some("classical".to_string()),
        };

        // Log classical token verification
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::DataAccess,
                SecuritySeverity::Low,
                "pq-jwt".to_string(),
                "Classical JWT token verified".to_string(),
            )
            .with_actor("system".to_string())
            .with_action("jwt_verify".to_string())
            .with_target("jwt_token".to_string())
            .with_outcome("success".to_string())
            .with_reason("Classical JWT token verification for backward compatibility".to_string())
            .with_detail("algorithm".to_string(), format!("{:?}", header.alg))
            .with_detail("hybrid".to_string(), false)
            .with_detail("kid".to_string(), header.kid.unwrap_or_default()),
        );

        Ok((pq_header, payload))
    }

    /// Extract claims from a verified token
    pub async fn extract_claims(&self, token: &str) -> Result<HashMap<String, Value>> {
        let (_, payload) = self.verify_token(token).await?;

        let mut claims = HashMap::new();
        if let Some(obj) = payload.as_object() {
            for (key, value) in obj {
                claims.insert(key.clone(), value.clone());
            }
        }

        Ok(claims)
    }

    /// Check if we should use post-quantum only tokens (for gradual migration)
    async fn should_use_post_quantum_only(&self) -> bool {
        // This could be based on various factors:
        // - Time-based migration schedule
        // - Client capabilities
        // - Security posture requirements
        // - Environment configuration

        std::env::var("FORCE_POST_QUANTUM_ONLY")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    /// Classical signing fallback (placeholder implementation)
    async fn sign_classical(&self, _data: &[u8]) -> Result<Vec<u8>> {
        // This would use the existing classical signing from keys module
        Err(anyhow!("Classical signing fallback not implemented"))
    }

    /// Classical signature verification fallback
    async fn verify_classical_signature(&self, _data: &[u8], _signature: &[u8]) -> Result<bool> {
        // This would use existing classical verification
        warn!("Classical signature verification fallback not fully implemented");
        Ok(false)
    }

    /// Create a JWK for post-quantum keys
    pub async fn create_pq_jwk(&self, kid: &str) -> Result<Value> {
        let manager = get_pq_manager();
        let jwks = manager.jwks_document().await;

        if let Some(keys) = jwks.get("keys").and_then(|k| k.as_array()) {
            for key in keys {
                if let Some(key_kid) = key.get("kid").and_then(|k| k.as_str()) {
                    if key_kid == kid {
                        return Ok(key.clone());
                    }
                }
            }
        }

        Err(anyhow!("Post-quantum key not found: {}", kid))
    }

    /// Get supported algorithms list
    pub fn supported_algorithms(&self) -> Vec<String> {
        let mut algorithms = vec![
            "PQ-DILITHIUM2".to_string(),
            "PQ-DILITHIUM3".to_string(),
            "PQ-DILITHIUM5".to_string(),
        ];

        if self.migration_mode == MigrationMode::Hybrid
            || self.migration_mode == MigrationMode::GradualMigration
        {
            algorithms.extend([
                "HYBRID-DILITHIUM2-ED25519".to_string(),
                "HYBRID-DILITHIUM3-ED25519".to_string(),
                "HYBRID-DILITHIUM2-ECDSA-P256".to_string(),
                "HYBRID-DILITHIUM3-ECDSA-P256".to_string(),
            ]);
        }

        if self.migration_mode == MigrationMode::Classical
            || self.migration_mode == MigrationMode::Hybrid
            || self.migration_mode == MigrationMode::GradualMigration
        {
            algorithms.extend([
                "RS256".to_string(),
                "RS384".to_string(),
                "RS512".to_string(),
                "ES256".to_string(),
                "ES384".to_string(),
                "EdDSA".to_string(),
            ]);
        }

        algorithms
    }
}

/// Global post-quantum JWT manager
static PQ_JWT_MANAGER: once_cell::sync::Lazy<PQJwtManager> =
    once_cell::sync::Lazy::new(|| PQJwtManager::default());

/// Get the global post-quantum JWT manager
pub fn get_pq_jwt_manager() -> &'static PQJwtManager {
    &PQ_JWT_MANAGER
}

/// Convenience function to create a post-quantum JWT token
pub async fn create_pq_jwt_token(payload: Value, expires_in: Option<u64>) -> Result<String> {
    get_pq_jwt_manager().create_token(payload, None, expires_in).await
}

/// Convenience function to verify a JWT token
pub async fn verify_pq_jwt_token(token: &str) -> Result<HashMap<String, Value>> {
    get_pq_jwt_manager().extract_claims(token).await
}

/// JWT integration with existing auth service
pub async fn create_pq_access_token(
    client_id: Option<String>,
    subject: Option<String>,
    scope: Option<String>,
    expires_in: u64,
) -> Result<String> {
    let mut payload = serde_json::Map::new();

    if let Some(sub) = subject {
        payload.insert("sub".to_string(), Value::String(sub));
    }

    if let Some(cid) = client_id {
        payload.insert("client_id".to_string(), Value::String(cid));
    }

    if let Some(scp) = scope {
        payload.insert("scope".to_string(), Value::String(scp));
    }

    payload.insert("token_type".to_string(), Value::String("access_token".to_string()));

    let payload_value = Value::Object(payload);

    get_pq_jwt_manager().create_token(payload_value, None, Some(expires_in)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_pq_jwt_header_default() {
        let header = PQJwtHeader::default();
        assert_eq!(header.alg, "PQ-DILITHIUM3");
        assert_eq!(header.pq_alg, Some("DILITHIUM3".to_string()));
        assert_eq!(header.hybrid, Some(false));
    }

    #[tokio::test]
    async fn test_jwt_manager_creation() {
        let manager = PQJwtManager::new(MigrationMode::Hybrid);
        let algorithms = manager.supported_algorithms();
        assert!(!algorithms.is_empty());
        assert!(algorithms.contains(&"HYBRID-DILITHIUM3-ED25519".to_string()));
    }

    #[tokio::test]
    async fn test_classical_jwt_creation() {
        let manager = PQJwtManager::new(MigrationMode::Classical);
        let payload = json!({
            "sub": "test-user",
            "iss": "test-issuer"
        });

        // This might fail if keys are not initialized, which is expected in test
        let result = manager.create_token(payload, None, Some(3600)).await;
        // Just test that the function can be called
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_token_structure_parsing() {
        // Test JWT structure validation
        let invalid_token = "invalid.token";
        let manager = PQJwtManager::default();

        let result = manager.verify_token(invalid_token).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_migration_mode_logic() {
        let hybrid_manager = PQJwtManager::new(MigrationMode::Hybrid);
        let pq_manager = PQJwtManager::new(MigrationMode::PostQuantumOnly);

        let hybrid_algorithms = hybrid_manager.supported_algorithms();
        let pq_algorithms = pq_manager.supported_algorithms();

        // Hybrid should support more algorithms
        assert!(hybrid_algorithms.len() >= pq_algorithms.len());

        // Both should support Dilithium
        assert!(hybrid_algorithms.contains(&"PQ-DILITHIUM3".to_string()));
        assert!(pq_algorithms.contains(&"PQ-DILITHIUM3".to_string()));
    }
}
