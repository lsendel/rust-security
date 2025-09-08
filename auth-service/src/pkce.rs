//! PKCE (Proof Key for Code Exchange) Implementation
//!
//! Implements RFC 7636 for OAuth 2.0 public clients to prevent
//! authorization code interception attacks.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// PKCE code challenge methods as defined in RFC 7636
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    /// Plain text (not recommended, but supported for compatibility)
    #[serde(rename = "plain")]
    Plain,
    /// SHA256 hash (recommended)
    #[serde(rename = "S256")]
    S256,
}

impl std::fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::S256 => write!(f, "S256"),
        }
    }
}

/// PKCE challenge information stored during authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkceChallenge {
    /// The code challenge value
    pub code_challenge: String,
    /// The method used to derive the challenge from the verifier
    pub code_challenge_method: CodeChallengeMethod,
    /// Timestamp when challenge was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Client ID that created this challenge
    pub client_id: String,
}

/// PKCE errors
#[derive(Debug, Error)]
pub enum PkceError {
    #[error("Invalid code verifier format")]
    InvalidVerifier,
    #[error("Invalid code challenge format")]
    InvalidChallenge,
    #[error("Code verifier does not match challenge")]
    VerificationFailed,
    #[error("Challenge not found or expired")]
    ChallengeNotFound,
    #[error("Unsupported challenge method")]
    UnsupportedMethod,
    #[error("PKCE challenge expired")]
    ChallengeExpired,
}

/// PKCE manager for handling challenges and verification
pub struct PkceManager {
    /// Active challenges indexed by authorization code
    challenges: Arc<RwLock<HashMap<String, PkceChallenge>>>,
    /// Challenge expiration time in seconds (default: 10 minutes)
    challenge_lifetime: u64,
}

impl Default for PkceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PkceManager {
    /// Create a new PKCE manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            challenge_lifetime: 600, // 10 minutes
        }
    }

    /// Create a new PKCE manager with custom challenge lifetime
    #[must_use]
    pub fn with_lifetime(challenge_lifetime: u64) -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            challenge_lifetime,
        }
    }

    /// Store a PKCE challenge for later verification
    pub async fn store_challenge(
        &self,
        authorization_code: &str,
        code_challenge: String,
        code_challenge_method: CodeChallengeMethod,
        client_id: String,
    ) -> Result<(), PkceError> {
        // Validate challenge format
        self.validate_challenge(&code_challenge, &code_challenge_method)?;

        let challenge = PkceChallenge {
            code_challenge,
            code_challenge_method,
            created_at: chrono::Utc::now(),
            client_id,
        };

        let mut challenges = self.challenges.write().await;
        challenges.insert(authorization_code.to_string(), challenge);

        Ok(())
    }

    /// Verify a code verifier against a stored challenge
    pub async fn verify_and_consume(
        &self,
        authorization_code: &str,
        code_verifier: &str,
        client_id: &str,
    ) -> Result<(), PkceError> {
        // Validate verifier format
        self.validate_verifier(code_verifier)?;

        let mut challenges = self.challenges.write().await;
        let challenge = challenges
            .remove(authorization_code)
            .ok_or(PkceError::ChallengeNotFound)?;

        // Check if challenge has expired
        let now = chrono::Utc::now();
        if now.timestamp() - challenge.created_at.timestamp() > self.challenge_lifetime as i64 {
            return Err(PkceError::ChallengeExpired);
        }

        // Verify client ID matches
        if challenge.client_id != client_id {
            return Err(PkceError::VerificationFailed);
        }

        // Verify the code verifier against the challenge
        match challenge.code_challenge_method {
            CodeChallengeMethod::Plain => {
                if code_verifier != challenge.code_challenge {
                    return Err(PkceError::VerificationFailed);
                }
            }
            CodeChallengeMethod::S256 => {
                let computed_challenge = self.compute_s256_challenge(code_verifier);
                if computed_challenge != challenge.code_challenge {
                    return Err(PkceError::VerificationFailed);
                }
            }
        }

        Ok(())
    }

    /// Generate a cryptographically secure code verifier
    #[must_use]
    pub fn generate_code_verifier() -> String {
        let mut bytes = [0u8; 32]; // 256 bits
        rand::thread_rng().fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Compute S256 challenge from a code verifier
    #[must_use]
    pub fn compute_s256_challenge(&self, code_verifier: &str) -> String {
        let hash = Sha256::digest(code_verifier.as_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    }

    /// Validate code verifier format according to RFC 7636
    pub fn validate_verifier(&self, code_verifier: &str) -> Result<(), PkceError> {
        // RFC 7636: 43-128 characters, unreserved characters only
        if code_verifier.len() < 43 || code_verifier.len() > 128 {
            return Err(PkceError::InvalidVerifier);
        }

        // Check for valid unreserved characters: [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        if !code_verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
        {
            return Err(PkceError::InvalidVerifier);
        }

        Ok(())
    }

    /// Validate code challenge format
    fn validate_challenge(
        &self,
        code_challenge: &str,
        method: &CodeChallengeMethod,
    ) -> Result<(), PkceError> {
        match method {
            CodeChallengeMethod::Plain => {
                // Same validation as verifier for plain method
                self.validate_verifier(code_challenge)
            }
            CodeChallengeMethod::S256 => {
                // S256 challenges should be base64url-encoded SHA256 hashes (43 characters)
                if code_challenge.len() != 43 {
                    return Err(PkceError::InvalidChallenge);
                }

                // Validate base64url format
                if URL_SAFE_NO_PAD.decode(code_challenge).is_err() {
                    return Err(PkceError::InvalidChallenge);
                }

                Ok(())
            }
        }
    }

    /// Clean up expired challenges (should be called periodically)
    pub async fn cleanup_expired_challenges(&self) -> usize {
        let mut challenges = self.challenges.write().await;
        let now = chrono::Utc::now();
        let initial_count = challenges.len();

        challenges.retain(|_, challenge| {
            now.timestamp() - challenge.created_at.timestamp() <= self.challenge_lifetime as i64
        });

        initial_count - challenges.len()
    }

    /// Get statistics about stored challenges
    pub async fn get_stats(&self) -> PkceStats {
        let challenges = self.challenges.read().await;
        let now = chrono::Utc::now();

        let expired_count = challenges
            .values()
            .filter(|challenge| {
                now.timestamp() - challenge.created_at.timestamp() > self.challenge_lifetime as i64
            })
            .count();

        PkceStats {
            total_challenges: challenges.len(),
            expired_challenges: expired_count,
            active_challenges: challenges.len() - expired_count,
        }
    }
}

/// PKCE statistics for monitoring
#[derive(Debug, Serialize)]
pub struct PkceStats {
    pub total_challenges: usize,
    pub expired_challenges: usize,
    pub active_challenges: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[test]
    fn test_generate_code_verifier() {
        let verifier1 = PkceManager::generate_code_verifier();
        let verifier2 = PkceManager::generate_code_verifier();

        // Should be different each time
        assert_ne!(verifier1, verifier2);

        // Should be valid length
        assert!(verifier1.len() >= 43);
        assert!(verifier1.len() <= 128);
    }

    #[test]
    fn test_compute_s256_challenge() {
        let manager = PkceManager::new();
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let computed = manager.compute_s256_challenge(verifier);
        assert_eq!(computed, expected_challenge);
    }

    #[test]
    fn test_validate_verifier() {
        let manager = PkceManager::new();

        // Valid verifier
        let valid_verifier = PkceManager::generate_code_verifier();
        assert!(manager.validate_verifier(&valid_verifier).is_ok());

        // Too short
        assert!(manager.validate_verifier("short").is_err());

        // Too long (more than 128 characters)
        let too_long = "a".repeat(129);
        assert!(manager.validate_verifier(&too_long).is_err());

        // Invalid characters
        assert!(manager
            .validate_verifier("invalid+characters/here")
            .is_err());
    }

    #[tokio::test]
    async fn test_store_and_verify_challenge_s256() {
        let manager = PkceManager::new();
        let auth_code = "test_auth_code";
        let client_id = "test_client";
        let verifier = PkceManager::generate_code_verifier();
        let challenge = manager.compute_s256_challenge(&verifier);

        // Store challenge
        assert!(manager
            .store_challenge(
                auth_code,
                challenge,
                CodeChallengeMethod::S256,
                client_id.to_string()
            )
            .await
            .is_ok());

        // Verify with correct verifier
        assert!(manager
            .verify_and_consume(auth_code, &verifier, client_id)
            .await
            .is_ok());

        // Should fail on second attempt (challenge consumed)
        assert!(manager
            .verify_and_consume(auth_code, &verifier, client_id)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_store_and_verify_challenge_plain() {
        let manager = PkceManager::new();
        let auth_code = "test_auth_code_plain";
        let client_id = "test_client";
        let verifier = PkceManager::generate_code_verifier();

        // Store challenge (plain method uses verifier as challenge)
        assert!(manager
            .store_challenge(
                auth_code,
                verifier.clone(),
                CodeChallengeMethod::Plain,
                client_id.to_string()
            )
            .await
            .is_ok());

        // Verify with same verifier
        assert!(manager
            .verify_and_consume(auth_code, &verifier, client_id)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_challenge_expiration() {
        let manager = PkceManager::with_lifetime(1); // 1 second expiration
        let auth_code = "test_expiring_code";
        let client_id = "test_client";
        let verifier = PkceManager::generate_code_verifier();
        let challenge = manager.compute_s256_challenge(&verifier);

        // Store challenge
        assert!(manager
            .store_challenge(
                auth_code,
                challenge,
                CodeChallengeMethod::S256,
                client_id.to_string()
            )
            .await
            .is_ok());

        // Wait for expiration
        sleep(Duration::from_secs(2)).await;

        // Should fail due to expiration
        assert!(matches!(
            manager
                .verify_and_consume(auth_code, &verifier, client_id)
                .await
                .unwrap_err(),
            PkceError::ChallengeExpired
        ));
    }

    #[tokio::test]
    async fn test_cleanup_expired_challenges() {
        let manager = PkceManager::with_lifetime(1); // 1 second expiration

        // Store some challenges
        for i in 0..3 {
            let auth_code = format!("code_{i}");
            let verifier = PkceManager::generate_code_verifier();
            let challenge = manager.compute_s256_challenge(&verifier);

            assert!(manager
                .store_challenge(
                    &auth_code,
                    challenge,
                    CodeChallengeMethod::S256,
                    "test_client".to_string()
                )
                .await
                .is_ok());
        }

        // Wait for expiration
        sleep(Duration::from_secs(2)).await;

        // Cleanup should remove all expired challenges
        let cleaned = manager.cleanup_expired_challenges().await;
        assert_eq!(cleaned, 3);

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_challenges, 0);
    }

    #[tokio::test]
    async fn test_wrong_client_verification() {
        let manager = PkceManager::new();
        let auth_code = "test_auth_code";
        let client_id = "test_client";
        let wrong_client_id = "wrong_client";
        let verifier = PkceManager::generate_code_verifier();
        let challenge = manager.compute_s256_challenge(&verifier);

        // Store challenge
        assert!(manager
            .store_challenge(
                auth_code,
                challenge,
                CodeChallengeMethod::S256,
                client_id.to_string()
            )
            .await
            .is_ok());

        // Verify with wrong client ID should fail
        assert!(matches!(
            manager
                .verify_and_consume(auth_code, &verifier, wrong_client_id)
                .await
                .unwrap_err(),
            PkceError::VerificationFailed
        ));
    }
}
