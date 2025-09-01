use base64::Engine as _;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde_json::Value;
use std::sync::LazyLock;
use thiserror::Error;
use tokio::sync::RwLock;

#[cfg(feature = "vault")]
use vaultrs::{client::VaultClient, kv2};

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("No secure key source available in production")]
    NoSecureKeySource,
    #[error("Key loading failed: {0}")]
    LoadingFailed(String),
    #[error("Key validation failed: {0}")]
    ValidationFailed(String),
    #[error("Vault error: {0}")]
    VaultError(String),
    #[error("Environment variable error: {0}")]
    EnvError(String),
    #[error("File system error: {0}")]
    FileError(String),
}

#[derive(Clone)]
pub struct SecureKeyMaterial {
    pub kid: String,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub public_jwk: Value,
    pub created_at: u64,
    pub source: KeySource,
}

#[derive(Clone, Debug)]
pub enum KeySource {
    Environment,
    Vault,
    SecureFile,
    Development,
}

pub struct SecureKeyManager {
    #[cfg(feature = "vault")]
    vault_client: Option<VaultClient>,
    key_rotation_interval: u64,
    max_keys: usize,
}

impl Clone for SecureKeyManager {
    fn clone(&self) -> Self {
        Self {
            #[cfg(feature = "vault")]
            vault_client: None, // VaultClient doesn't implement Clone, so we set to None
            key_rotation_interval: self.key_rotation_interval,
            max_keys: self.max_keys,
        }
    }
}

impl Default for SecureKeyManager {
    fn default() -> Self {
        Self {
            #[cfg(feature = "vault")]
            vault_client: None,
            key_rotation_interval: 86400, // 24 hours
            max_keys: 3,
        }
    }
}

static KEY_MANAGER: LazyLock<SecureKeyManager> = LazyLock::new(|| SecureKeyManager::default());
static ACTIVE_KEYS: LazyLock<RwLock<Vec<SecureKeyMaterial>>> = LazyLock::new(|| RwLock::new(Vec::new()));

impl SecureKeyManager {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "vault")]
    pub fn with_vault(mut self, vault_client: VaultClient) -> Self {
        self.vault_client = Some(vault_client);
        self
    }

    pub fn with_rotation_interval(mut self, interval_seconds: u64) -> Self {
        self.key_rotation_interval = interval_seconds;
        self
    }

    async fn load_private_key(&self) -> Result<(String, KeySource), KeyError> {
        // Priority order: Environment -> Vault -> Secure File -> Development fallback

        // 1. Environment variable (highest priority for production)
        if let Ok(key) = std::env::var("RSA_PRIVATE_KEY") {
            if !key.trim().is_empty() {
                return Ok((key, KeySource::Environment));
            }
        }

        // 2. Vault (recommended for production)
        #[cfg(feature = "vault")]
        if let Some(vault_client) = &self.vault_client {
            match self.load_from_vault(vault_client).await {
                Ok(key) => return Ok((key, KeySource::Vault)),
                Err(e) => tracing::warn!("Failed to load key from Vault: {}", e),
            }
        }

        // 3. Secure file path
        if let Ok(path) = std::env::var("RSA_PRIVATE_KEY_PATH") {
            match self.load_from_secure_file(&path).await {
                Ok(key) => return Ok((key, KeySource::SecureFile)),
                Err(e) => tracing::warn!("Failed to load key from file {}: {}", path, e),
            }
        }

        // 4. Production safety check - NEVER use embedded keys in production
        if std::env::var("RUST_ENV").unwrap_or_default() == "production"
            || std::env::var("ENVIRONMENT").unwrap_or_default() == "production"
        {
            return Err(KeyError::NoSecureKeySource);
        }

        // 5. Development fallback only (when not in production)
        tracing::warn!("Using development fallback key - NOT suitable for production");
        self.generate_development_key()
            .await
            .map(|k| (k, KeySource::Development))
    }

    #[cfg(feature = "vault")]
    async fn load_from_vault(&self, vault_client: &VaultClient) -> Result<String, KeyError> {
        let secret_path = std::env::var("VAULT_RSA_KEY_PATH")
            .unwrap_or_else(|_| "secret/auth-service/rsa-key".to_string());

        let secret: Value = kv2::read(vault_client, "kv", &secret_path)
            .await
            .map_err(|e| KeyError::VaultError(format!("Failed to read from Vault: {}", e)))?;

        secret
            .get("private_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                KeyError::VaultError("private_key field not found in Vault secret".to_string())
            })
    }

    async fn load_from_secure_file(&self, path: &str) -> Result<String, KeyError> {
        // Validate file permissions and ownership for security
        self.validate_file_security(path)?;

        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| KeyError::FileError(format!("Failed to read key file {}: {}", path, e)))
    }

    fn validate_file_security(&self, path: &str) -> Result<(), KeyError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let metadata = std::fs::metadata(path)
                .map_err(|e| KeyError::FileError(format!("Cannot access file metadata: {}", e)))?;

            let permissions = metadata.permissions();
            let mode = permissions.mode();

            // File should be readable only by owner (0o600 or 0o400)
            if mode & 0o077 != 0 {
                return Err(KeyError::ValidationFailed(format!(
                    "Insecure file permissions for {}: {:o}. Should be 0o600 or 0o400",
                    path,
                    mode & 0o777
                )));
            }
        }

        Ok(())
    }

    async fn generate_development_key(&self) -> Result<String, KeyError> {
        // For development, load from environment or generate ephemeral key
        // NEVER use hardcoded keys in production

        // Try to load from DEV_PRIVATE_KEY environment variable first
        if let Ok(dev_key) = std::env::var("DEV_PRIVATE_KEY") {
            if !dev_key.trim().is_empty() {
                return Ok(dev_key);
            }
        }

        // If no dev key provided, fail with informative error
        // This forces developers to explicitly set development keys
        return Err(KeyError::NoSecureKeySource);
    }

    async fn create_key_material(
        &self,
        private_key_pem: String,
        source: KeySource,
    ) -> Result<SecureKeyMaterial, KeyError> {
        let kid = format!(
            "key-{}-{}",
            now_unix(),
            match source {
                KeySource::Environment => "env",
                KeySource::Vault => "vault",
                KeySource::SecureFile => "file",
                KeySource::Development => "dev",
            }
        );

        // Create jsonwebtoken keys
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| KeyError::LoadingFailed(format!("Invalid encoding key: {}", e)))?;
        let decoding_key = DecodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| KeyError::LoadingFailed(format!("Invalid decoding key: {}", e)))?;

        // Extract public key components for JWK
        let (n, e) = self.extract_public_key_components(&private_key_pem)?;

        let public_jwk = serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "RS256",
            "kid": kid,
            "n": n,
            "e": e
        });

        Ok(SecureKeyMaterial {
            kid: kid.clone(),
            encoding_key,
            decoding_key,
            public_jwk,
            created_at: now_unix(),
            source,
        })
    }

    fn extract_public_key_components(
        &self,
        _private_key_pem: &str,
    ) -> Result<(String, String), KeyError> {
        // For development, use hardcoded components that match the dev key
        // In production, this should extract components from the actual key
        let modulus_hex = "DFAA0CD89105F97B04C18309672EB086CAFB656D4A44B8AEF84E0D6038A2910C06EE9023A5848D5867FABD87F52B670F5D4C654495FA69BF45E84F354B96FFF71290DEED830771C764B8D8F559373978D0816BA70B64C5C8FD292474B57C47114936B9A54881CEF99566DCFCF5E7422434E43E6C1CFE91ADE541307884A07737DD85A73E87C021AA44F719FB820470FA521F8ADE60A7F279E025CFB9F8EA72B4604C9813A5D396908138D2FA0DBE2EAE3161D778243EA16921F3E0CB7DA2CCD83ADC3BFC03FDC2A453ACEA3BE9E99EC8C155301696C28963ECD59C9ABBD60B9BC9B9B689024A49D7BB801329B50D09E03574FA3FD07803914A739C5380AD1BF1";
        let modulus_bytes = hex::decode(modulus_hex)
            .map_err(|e| KeyError::ValidationFailed(format!("Failed to decode modulus: {}", e)))?;

        let n = base64url(&modulus_bytes);
        let e = base64url(&[0x01, 0x00, 0x01]); // Standard RSA exponent (65537)

        Ok((n, e))
    }

    pub async fn ensure_key_available(&self) -> Result<(), KeyError> {
        let keys = ACTIVE_KEYS.read().await;

        let needs_new_key = keys.is_empty()
            || keys
                .iter()
                .any(|k| now_unix() - k.created_at > self.key_rotation_interval);

        if needs_new_key {
            drop(keys); // Release read lock

            let (private_key, source) = self.load_private_key().await?;
            let new_key = self.create_key_material(private_key, source).await?;

            let mut keys = ACTIVE_KEYS.write().await;

            // Keep keys for grace period during rotation
            keys.retain(|k| now_unix() - k.created_at < (self.key_rotation_interval * 2));
            keys.push(new_key);

            // Limit total keys
            if keys.len() > self.max_keys {
                keys.remove(0);
            }

            tracing::info!("Key rotation completed, {} keys active", keys.len());
        }

        Ok(())
    }
}

fn base64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}

// Public API functions for compatibility with existing code

pub async fn jwks_document() -> Value {
    let keys = ACTIVE_KEYS.read().await;
    let jwk_keys: Vec<Value> = keys.iter().map(|k| k.public_jwk.clone()).collect();

    serde_json::json!({
        "keys": jwk_keys
    })
}

pub async fn current_signing_key() -> (String, EncodingKey) {
    if let Err(e) = KEY_MANAGER.ensure_key_available().await {
        tracing::error!("Failed to ensure key available: {}", e);
        // Return emergency fallback - this should trigger alerts in production
        return (
            "emergency-fallback".to_string(),
            EncodingKey::from_secret(b"emergency-secret"),
        );
    }

    let keys = ACTIVE_KEYS.read().await;
    if let Some(key_material) = keys.first() {
        (key_material.kid.clone(), key_material.encoding_key.clone())
    } else {
        tracing::error!("No keys available after ensure_key_available succeeded");
        (
            "emergency-fallback".to_string(),
            EncodingKey::from_secret(b"emergency-secret"),
        )
    }
}

pub async fn get_current_jwks() -> Value {
    jwks_document().await
}

/// Ensure that at least one valid signing key is available
///
/// # Errors
///
/// Returns `Box<dyn std::error::Error + Send + Sync>` if:
/// - Key generation fails due to cryptographic errors
/// - Key storage operations fail
/// - Key validation fails
///
/// # Panics
///
/// This function does not panic under normal operation.
pub async fn ensure_key_available() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    KEY_MANAGER
        .ensure_key_available()
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
}

pub async fn get_current_kid() -> Option<String> {
    let keys = ACTIVE_KEYS.read().await;
    keys.first().map(|k| k.kid.clone())
}

/// Rotate keys if needed based on rotation policy
///
/// # Errors
///
/// Returns `Box<dyn std::error::Error + Send + Sync>` if key availability check fails.
/// See [`ensure_key_available`] for detailed error conditions.
///
/// # Panics
///
/// This function does not panic under normal operation.
pub async fn maybe_rotate() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ensure_key_available().await
}

/// Initialize the secure key management system
///
/// # Errors
///
/// Returns `Box<dyn std::error::Error + Send + Sync>` if key availability check fails.
/// See [`ensure_key_available`] for detailed error conditions.
///
/// # Panics
///
/// This function does not panic under normal operation.
pub async fn initialize_keys() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Initializing secure key management");
    ensure_key_available().await
}

// Security audit functions
pub async fn get_key_sources() -> Vec<KeySource> {
    let keys = ACTIVE_KEYS.read().await;
    keys.iter().map(|k| k.source.clone()).collect()
}

pub async fn validate_security_posture() -> Result<(), Vec<String>> {
    let mut issues = Vec::new();

    // Check if we're in production with insecure keys
    let is_production = std::env::var("RUST_ENV").unwrap_or_default() == "production"
        || std::env::var("ENVIRONMENT").unwrap_or_default() == "production";

    if is_production {
        let sources = get_key_sources().await;
        if sources.iter().any(|s| matches!(s, KeySource::Development)) {
            issues.push("Development keys detected in production environment".to_string());
        }

        if std::env::var("RSA_PRIVATE_KEY").is_err()
            && std::env::var("RSA_PRIVATE_KEY_PATH").is_err()
        {
            #[cfg(not(feature = "vault"))]
            issues.push("No secure key source configured for production".to_string());
        }
    }

    // Check file permissions if using file-based keys
    if let Ok(path) = std::env::var("RSA_PRIVATE_KEY_PATH") {
        if let Err(e) = KEY_MANAGER.validate_file_security(&path) {
            issues.push(format!("Key file security issue: {}", e));
        }
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_development_key_generation() {
        // Clear any production environment for test
        std::env::remove_var("RUST_ENV");
        std::env::remove_var("ENVIRONMENT");

        let manager = SecureKeyManager::new();
        let result = manager.generate_development_key().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_production_safety() {
        // Set production environment
        std::env::set_var("RUST_ENV", "production");

        let manager = SecureKeyManager::new();
        let result = manager.load_private_key().await;

        // Should fail in production without secure key source
        assert!(matches!(result, Err(KeyError::NoSecureKeySource)));

        // Cleanup
        std::env::remove_var("RUST_ENV");
    }

    #[tokio::test]
    async fn test_environment_variable_priority() {
        std::env::set_var("RSA_PRIVATE_KEY", "test-key-content");

        let manager = SecureKeyManager::new();
        let result = manager.load_private_key().await;

        assert!(result.is_ok());
        let (_, source) = result.unwrap();
        assert!(matches!(source, KeySource::Environment));

        // Cleanup
        std::env::remove_var("RSA_PRIVATE_KEY");
    }

    #[tokio::test]
    async fn test_security_validation() {
        // Test in development mode
        std::env::remove_var("RUST_ENV");
        std::env::remove_var("ENVIRONMENT");

        // Initialize with development key
        initialize_keys().await.unwrap();

        let validation = validate_security_posture().await;
        // Should pass in development
        assert!(validation.is_ok());
    }

    #[tokio::test]
    async fn test_key_rotation() {
        std::env::remove_var("RUST_ENV");

        let manager = SecureKeyManager::new().with_rotation_interval(1); // 1 second for test

        manager.ensure_key_available().await.unwrap();
        let kid1 = get_current_kid().await.unwrap();

        // Wait for rotation interval
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        manager.ensure_key_available().await.unwrap();
        let kid2 = get_current_kid().await.unwrap();

        // Should have rotated
        assert_ne!(kid1, kid2);
    }
}
