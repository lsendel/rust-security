use crate::mfa::errors::{MfaError, MfaResult};
use crate::mfa::storage::MfaStorage;
use rand::RngCore;
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum WebAuthnError {
    #[error("Registration error: {0}")]
    Registration(String),
    #[error("Authentication error: {0}")]
    Authentication(String),
    #[error("Invalid challenge")]
    InvalidChallenge,
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Credential not found")]
    CredentialNotFound,
    #[error("User verification failed")]
    UserVerificationFailed,
    #[error("Invalid origin: {0}")]
    InvalidOrigin(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Base64 decode error: {0}")]
    Base64Decode(String),
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
}

// WebAuthn data structures (simplified - in production use webauthn-rs crate)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: String, // base64url encoded
    pub timeout: Option<u64>,
    pub rp_id: Option<String>,
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub user_verification: UserVerificationRequirement,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: RelyingParty,
    pub user: User,
    pub challenge: String, // base64url encoded
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: AttestationConveyancePreference,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String, // "public-key"
    pub id: String,              // base64url encoded credential ID
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,           // base64url encoded user handle
    pub name: String,         // user identifier (email)
    pub display_name: String, // human-readable name
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub credential_type: String, // "public-key"
    pub alg: i32,               // COSE algorithm identifier
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub resident_key: Option<ResidentKeyRequirement>,
    pub require_resident_key: Option<bool>,
    pub user_verification: UserVerificationRequirement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticatorAttachment {
    #[serde(rename = "platform")]
    Platform,
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResidentKeyRequirement {
    #[serde(rename = "discouraged")]
    Discouraged,
    #[serde(rename = "preferred")]
    Preferred,
    #[serde(rename = "required")]
    Required,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserVerificationRequirement {
    #[serde(rename = "required")]
    Required,
    #[serde(rename = "preferred")]
    Preferred,
    #[serde(rename = "discouraged")]
    Discouraged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationConveyancePreference {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "indirect")]
    Indirect,
    #[serde(rename = "direct")]
    Direct,
    #[serde(rename = "enterprise")]
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredential {
    pub id: String,
    pub raw_id: String, // base64url
    pub response: AuthenticatorResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuthenticatorResponse {
    Registration(AuthenticatorAttestationResponse),
    Authentication(AuthenticatorAssertionResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: String, // base64url
    pub attestation_object: String, // base64url
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: String, // base64url
    pub authenticator_data: String, // base64url
    pub signature: String,        // base64url
    pub user_handle: Option<String>, // base64url
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: String,
    pub user_id: String,
    pub public_key: String, // base64url encoded public key
    pub sign_count: u32,
    pub created_at: u64,
    pub last_used: Option<u64>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub device_type: String,
    pub aaguid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub challenge: String,
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub options: PublicKeyCredentialCreationOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub challenge: String,
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub options: PublicKeyCredentialRequestOptions,
}

pub struct WebAuthnMfa {
    redis: Option<ConnectionManager>,
    rp_id: String,
    rp_name: String,
    origin: String,
    challenge_timeout: Duration,
}

impl WebAuthnMfa {
    pub async fn new(rp_id: String, rp_name: String, origin: String) -> Self {
        let redis = Self::create_redis_connection().await;
        Self {
            redis,
            rp_id,
            rp_name,
            origin,
            challenge_timeout: Duration::from_secs(300), // 5 minutes
        }
    }

    async fn create_redis_connection() -> Option<ConnectionManager> {
        let url = std::env::var("REDIS_URL").ok()?;
        let client = redis::Client::open(url).ok()?;
        client.get_connection_manager().await.ok()
    }

    pub async fn start_registration(&self, user_id: &str, user_name: &str, display_name: &str) -> MfaResult<PublicKeyCredentialCreationOptions> {
        let challenge = self.generate_challenge();
        let user_handle = self.generate_user_handle(user_id);

        // Get existing credentials to exclude
        let existing_credentials = self.get_user_credentials(user_id).await?;
        let exclude_credentials: Vec<PublicKeyCredentialDescriptor> = existing_credentials
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: cred.credential_id,
                transports: Some(cred.transports),
            })
            .collect();

        let options = PublicKeyCredentialCreationOptions {
            rp: RelyingParty {
                id: self.rp_id.clone(),
                name: self.rp_name.clone(),
                icon: None,
            },
            user: User {
                id: user_handle,
                name: user_name.to_string(),
                display_name: display_name.to_string(),
                icon: None,
            },
            challenge: challenge.clone(),
            pub_key_cred_params: vec![
                // ES256 (ECDSA w/ SHA-256)
                PublicKeyCredentialParameters {
                    credential_type: "public-key".to_string(),
                    alg: -7,
                },
                // PS256 (RSASSA-PSS w/ SHA-256)
                PublicKeyCredentialParameters {
                    credential_type: "public-key".to_string(),
                    alg: -37,
                },
                // RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)
                PublicKeyCredentialParameters {
                    credential_type: "public-key".to_string(),
                    alg: -257,
                },
            ],
            timeout: Some(self.challenge_timeout.as_millis() as u64),
            exclude_credentials,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None, // Allow both platform and cross-platform
                resident_key: Some(ResidentKeyRequirement::Preferred),
                require_resident_key: Some(false),
                user_verification: UserVerificationRequirement::Preferred,
            }),
            attestation: AttestationConveyancePreference::None,
            extensions: None,
        };

        // Store challenge
        self.store_registration_challenge(user_id, &challenge, &options).await?;

        Ok(options)
    }

    pub async fn finish_registration(&self, user_id: &str, credential: &PublicKeyCredential) -> MfaResult<StoredCredential> {
        // Validate challenge
        let challenge_data = self.get_and_remove_registration_challenge(user_id).await?;

        // In a real implementation, you would:
        // 1. Verify the client data JSON
        // 2. Verify the attestation object
        // 3. Extract and validate the public key
        // 4. Verify the signature
        // 5. Check the origin matches

        // For this simplified implementation, we'll create a mock stored credential
        let stored_credential = StoredCredential {
            credential_id: credential.id.clone(),
            user_id: user_id.to_string(),
            public_key: "mock_public_key".to_string(), // In reality, extract from attestation
            sign_count: 0,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            last_used: None,
            transports: vec!["usb".to_string(), "nfc".to_string()],
            backup_eligible: false,
            backup_state: false,
            device_type: "security_key".to_string(),
            aaguid: None,
        };

        // Store the credential
        self.store_credential(&stored_credential).await?;

        tracing::info!(
            "WebAuthn credential registered for user: {} with credential ID: {}",
            user_id,
            credential.id
        );

        Ok(stored_credential)
    }

    pub async fn start_authentication(&self, user_id: &str) -> MfaResult<PublicKeyCredentialRequestOptions> {
        let challenge = self.generate_challenge();

        // Get user's credentials
        let credentials = self.get_user_credentials(user_id).await?;
        if credentials.is_empty() {
            return Err(MfaError::BadRequest {
                message: "No WebAuthn credentials found for user".to_string(),
            });
        }

        let allow_credentials: Vec<PublicKeyCredentialDescriptor> = credentials
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: cred.credential_id,
                transports: Some(cred.transports),
            })
            .collect();

        let options = PublicKeyCredentialRequestOptions {
            challenge: challenge.clone(),
            timeout: Some(self.challenge_timeout.as_millis() as u64),
            rp_id: Some(self.rp_id.clone()),
            allow_credentials,
            user_verification: UserVerificationRequirement::Preferred,
            extensions: None,
        };

        // Store challenge
        self.store_authentication_challenge(user_id, &challenge, &options).await?;

        Ok(options)
    }

    pub async fn finish_authentication(&self, user_id: &str, credential: &PublicKeyCredential) -> MfaResult<bool> {
        // Validate challenge
        let _challenge_data = self.get_and_remove_authentication_challenge(user_id).await?;

        // Get stored credential
        let mut stored_credential = self.get_credential(&credential.id).await?;

        // In a real implementation, you would:
        // 1. Verify the client data JSON
        // 2. Verify the authenticator data
        // 3. Verify the signature using the stored public key
        // 4. Check and update the sign count
        // 5. Verify the origin matches

        // For this simplified implementation, we'll assume success
        stored_credential.sign_count += 1;
        stored_credential.last_used = Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());

        // Update stored credential
        self.store_credential(&stored_credential).await?;

        tracing::info!(
            "WebAuthn authentication successful for user: {} with credential ID: {}",
            user_id,
            credential.id
        );

        Ok(true)
    }

    pub async fn list_user_credentials(&self, user_id: &str) -> MfaResult<Vec<StoredCredential>> {
        self.get_user_credentials(user_id).await
    }

    pub async fn delete_credential(&self, user_id: &str, credential_id: &str) -> MfaResult<bool> {
        let Some(mut conn) = self.redis.clone() else {
            return Err(MfaError::ServiceUnavailable {
                service: "Redis".to_string(),
            });
        };

        // Verify ownership
        let credential = self.get_credential(credential_id).await?;
        if credential.user_id != user_id {
            return Err(MfaError::Forbidden {
                message: "Cannot delete credential belonging to another user".to_string(),
            });
        }

        let key = format!("webauthn:credential:{}", credential_id);
        let deleted: u64 = conn.del(&key).await?;

        // Remove from user's credential list
        let user_key = format!("webauthn:user:{}:credentials", user_id);
        let _: u64 = conn.srem(&user_key, credential_id).await?;

        tracing::info!(
            "Deleted WebAuthn credential {} for user {}",
            credential_id,
            user_id
        );

        Ok(deleted > 0)
    }

    fn generate_challenge(&self) -> String {
        use rand::rngs::OsRng;
        let mut challenge = vec![0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        base64::encode_config(&challenge, base64::URL_SAFE_NO_PAD)
    }

    fn generate_user_handle(&self, user_id: &str) -> String {
        // Generate a stable user handle from user ID
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        user_id.hash(&mut hasher);
        let hash = hasher.finish();
        base64::encode_config(&hash.to_be_bytes(), base64::URL_SAFE_NO_PAD)
    }

    async fn store_registration_challenge(&self, user_id: &str, challenge: &str, options: &PublicKeyCredentialCreationOptions) -> MfaResult<()> {
        let Some(mut conn) = self.redis.clone() else {
            return Ok(()); // Graceful degradation
        };

        let challenge_data = RegistrationChallenge {
            challenge: challenge.to_string(),
            user_id: user_id.to_string(),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            expires_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + self.challenge_timeout.as_secs(),
            options: options.clone(),
        };

        let key = format!("webauthn:reg_challenge:{}", user_id);
        let serialized = serde_json::to_string(&challenge_data)?;
        conn.set_ex(&key, serialized, self.challenge_timeout.as_secs()).await?;

        Ok(())
    }

    async fn store_authentication_challenge(&self, user_id: &str, challenge: &str, options: &PublicKeyCredentialRequestOptions) -> MfaResult<()> {
        let Some(mut conn) = self.redis.clone() else {
            return Ok(()); // Graceful degradation
        };

        let challenge_data = AuthenticationChallenge {
            challenge: challenge.to_string(),
            user_id: user_id.to_string(),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            expires_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + self.challenge_timeout.as_secs(),
            options: options.clone(),
        };

        let key = format!("webauthn:auth_challenge:{}", user_id);
        let serialized = serde_json::to_string(&challenge_data)?;
        conn.set_ex(&key, serialized, self.challenge_timeout.as_secs()).await?;

        Ok(())
    }

    async fn get_and_remove_registration_challenge(&self, user_id: &str) -> MfaResult<RegistrationChallenge> {
        let Some(mut conn) = self.redis.clone() else {
            return Err(MfaError::ServiceUnavailable {
                service: "Redis".to_string(),
            });
        };

        let key = format!("webauthn:reg_challenge:{}", user_id);
        let data: Option<String> = conn.get(&key).await?;
        let _: u64 = conn.del(&key).await?; // Remove after getting

        match data {
            Some(serialized) => {
                let challenge_data: RegistrationChallenge = serde_json::from_str(&serialized)?;

                // Check if expired
                let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                if current_time > challenge_data.expires_at {
                    return Err(MfaError::BadRequest {
                        message: "Registration challenge expired".to_string(),
                    });
                }

                Ok(challenge_data)
            }
            None => Err(MfaError::BadRequest {
                message: "No registration challenge found".to_string(),
            }),
        }
    }

    async fn get_and_remove_authentication_challenge(&self, user_id: &str) -> MfaResult<AuthenticationChallenge> {
        let Some(mut conn) = self.redis.clone() else {
            return Err(MfaError::ServiceUnavailable {
                service: "Redis".to_string(),
            });
        };

        let key = format!("webauthn:auth_challenge:{}", user_id);
        let data: Option<String> = conn.get(&key).await?;
        let _: u64 = conn.del(&key).await?; // Remove after getting

        match data {
            Some(serialized) => {
                let challenge_data: AuthenticationChallenge = serde_json::from_str(&serialized)?;

                // Check if expired
                let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                if current_time > challenge_data.expires_at {
                    return Err(MfaError::BadRequest {
                        message: "Authentication challenge expired".to_string(),
                    });
                }

                Ok(challenge_data)
            }
            None => Err(MfaError::BadRequest {
                message: "No authentication challenge found".to_string(),
            }),
        }
    }

    async fn store_credential(&self, credential: &StoredCredential) -> MfaResult<()> {
        let Some(mut conn) = self.redis.clone() else {
            return Err(MfaError::ServiceUnavailable {
                service: "Redis".to_string(),
            });
        };

        let key = format!("webauthn:credential:{}", credential.credential_id);
        let serialized = serde_json::to_string(credential)?;
        conn.set(&key, serialized).await?;

        // Add to user's credential list
        let user_key = format!("webauthn:user:{}:credentials", credential.user_id);
        conn.sadd(&user_key, &credential.credential_id).await?;

        Ok(())
    }

    async fn get_credential(&self, credential_id: &str) -> MfaResult<StoredCredential> {
        let Some(mut conn) = self.redis.clone() else {
            return Err(MfaError::ServiceUnavailable {
                service: "Redis".to_string(),
            });
        };

        let key = format!("webauthn:credential:{}", credential_id);
        let data: Option<String> = conn.get(&key).await?;

        match data {
            Some(serialized) => {
                let credential: StoredCredential = serde_json::from_str(&serialized)?;
                Ok(credential)
            }
            None => Err(MfaError::BadRequest {
                message: format!("Credential not found: {}", credential_id),
            }),
        }
    }

    async fn get_user_credentials(&self, user_id: &str) -> MfaResult<Vec<StoredCredential>> {
        let Some(mut conn) = self.redis.clone() else {
            return Ok(vec![]);
        };

        let user_key = format!("webauthn:user:{}:credentials", user_id);
        let credential_ids: Vec<String> = conn.smembers(&user_key).await?;

        let mut credentials = Vec::new();
        for credential_id in credential_ids {
            if let Ok(credential) = self.get_credential(&credential_id).await {
                credentials.push(credential);
            }
        }

        Ok(credentials)
    }

    pub async fn cleanup_expired_challenges(&self) -> MfaResult<u64> {
        let Some(mut conn) = self.redis.clone() else {
            return Ok(0);
        };

        let mut cleaned = 0;

        // Clean registration challenges
        let reg_pattern = "webauthn:reg_challenge:*";
        let reg_keys: Vec<String> = conn.keys(&reg_pattern).await?;
        for key in reg_keys {
            let ttl: i64 = conn.ttl(&key).await?;
            if ttl < 0 && ttl != -1 {
                let deleted: u64 = conn.del(&key).await?;
                cleaned += deleted;
            }
        }

        // Clean authentication challenges
        let auth_pattern = "webauthn:auth_challenge:*";
        let auth_keys: Vec<String> = conn.keys(&auth_pattern).await?;
        for key in auth_keys {
            let ttl: i64 = conn.ttl(&key).await?;
            if ttl < 0 && ttl != -1 {
                let deleted: u64 = conn.del(&key).await?;
                cleaned += deleted;
            }
        }

        if cleaned > 0 {
            tracing::info!("Cleaned up {} expired WebAuthn challenges", cleaned);
        }

        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registration_flow() {
        let webauthn = WebAuthnMfa::new(
            "example.com".to_string(),
            "Example Service".to_string(),
            "https://example.com".to_string(),
        ).await;

        let user_id = "test_user";
        let options = webauthn
            .start_registration(user_id, "test@example.com", "Test User")
            .await
            .unwrap();

        assert_eq!(options.rp.id, "example.com");
        assert_eq!(options.user.name, "test@example.com");
        assert!(!options.challenge.is_empty());
        assert!(!options.pub_key_cred_params.is_empty());
    }

    #[tokio::test]
    async fn test_authentication_flow() {
        let webauthn = WebAuthnMfa::new(
            "example.com".to_string(),
            "Example Service".to_string(),
            "https://example.com".to_string(),
        ).await;

        let user_id = "test_user";

        // First register a credential (mock)
        let stored_credential = StoredCredential {
            credential_id: "test_credential".to_string(),
            user_id: user_id.to_string(),
            public_key: "mock_public_key".to_string(),
            sign_count: 0,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            last_used: None,
            transports: vec!["usb".to_string()],
            backup_eligible: false,
            backup_state: false,
            device_type: "security_key".to_string(),
            aaguid: None,
        };
        webauthn.store_credential(&stored_credential).await.unwrap();

        // Start authentication
        let options = webauthn.start_authentication(user_id).await.unwrap();
        assert!(!options.challenge.is_empty());
        assert_eq!(options.allow_credentials.len(), 1);
        assert_eq!(options.allow_credentials[0].id, "test_credential");
    }

    #[test]
    fn test_challenge_generation() {
        let webauthn = WebAuthnMfa {
            redis: None,
            rp_id: "test.com".to_string(),
            rp_name: "Test".to_string(),
            origin: "https://test.com".to_string(),
            challenge_timeout: Duration::from_secs(300),
        };

        let challenge1 = webauthn.generate_challenge();
        let challenge2 = webauthn.generate_challenge();

        assert_ne!(challenge1, challenge2);
        assert!(!challenge1.is_empty());
        assert!(!challenge2.is_empty());
    }

    #[test]
    fn test_user_handle_generation() {
        let webauthn = WebAuthnMfa {
            redis: None,
            rp_id: "test.com".to_string(),
            rp_name: "Test".to_string(),
            origin: "https://test.com".to_string(),
            challenge_timeout: Duration::from_secs(300),
        };

        let handle1 = webauthn.generate_user_handle("user1");
        let handle2 = webauthn.generate_user_handle("user2");
        let handle1_again = webauthn.generate_user_handle("user1");

        assert_ne!(handle1, handle2);
        assert_eq!(handle1, handle1_again); // Should be deterministic
    }
}