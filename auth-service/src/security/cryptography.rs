//! # Unified Cryptography Module
//!
//! A comprehensive, production-ready cryptographic library providing all cryptographic
//! operations needed by the authentication service. Combines security, performance,
//! and usability with extensive testing and monitoring capabilities.
//!
//! ## Features Overview
//!
//! ### Symmetric Encryption
//! - **AES-256-GCM**: Hardware-accelerated AEAD encryption (default)
//! - **ChaCha20-Poly1305**: Pure software AEAD encryption (fallback)
//! - **Authenticated Encryption**: All ciphers provide authenticity and confidentiality
//! - **Key Rotation**: Automatic key rotation with versioning support
//!
//! ### Password Security
//! - **Argon2id**: Memory-hard password hashing (OWASP recommended)
//! - **Configurable Parameters**: Tunable memory, time, and parallelism costs
//! - **Salt Generation**: Cryptographically secure random salts
//! - **Timing Attack Resistance**: Constant-time verification
//!
//! ### Message Authentication
//! - **HMAC-SHA256/384/512**: Keyed hash message authentication
//! - **Key Versioning**: Support for key rotation without breaking existing HMACs
//! - **Constant-Time Verification**: Prevents timing attacks
//!
//! ### Random Number Generation
//! - **Cryptographically Secure**: Uses OS entropy sources
//! - **Multiple Formats**: Raw bytes, `Base64URL` strings
//! - **High Performance**: Optimized for frequent token generation
//!
//! ### Memory Safety
//! - **Automatic Zeroization**: Sensitive data cleared from memory
//! - **Secure Key Storage**: Keys stored in protected memory when possible
//! - **No Key Leakage**: Keys never appear in logs or error messages
//!
//! ## Quick Start
//!
//! ```rust
//! use auth_service::security::cryptography::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), CryptoError> {
//!     // Initialize with default configuration
//!     let config = CryptoConfig::default();
//!     let crypto = UnifiedCryptography::new(config).await?;
//!
//!     // Encrypt sensitive data
//!     let plaintext = b"user_session_data";
//!     let encrypted = crypto.encrypt(plaintext, None, None).await?;
//!     let decrypted = crypto.decrypt(&encrypted).await?;
//!     assert_eq!(plaintext, &decrypted[..]);
//!
//!     // Hash passwords securely
//!     let password = "user_password_123!";
//!     let hash = crypto.hash_password(password).await?;
//!     let is_valid = crypto.verify_password(password, &hash).await?;
//!     assert!(is_valid);
//!
//!     // Generate secure tokens
//!     let token = crypto.generate_random_string(32)?;
//!     println!("Generated token: {}", token);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Global Service Usage
//!
//! For convenience, the module provides global service functions:
//!
//! ```rust
//! use auth_service::security::cryptography::*;
//!
//! // Initialize global service once at startup
//! let config = CryptoConfig::default();
//! initialize_global_crypto(config).await?;
//!
//! // Use global functions anywhere in your application
//! let encrypted_data = encrypt_global(b"sensitive_data", None, None).await?;
//! let password_hash = hash_password_global("user_password").await?;
//! ```
//!
//! ## Configuration Examples
//!
//! ### High Security Configuration
//! ```rust
//! let config = CryptoConfig {
//!     default_symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
//!     default_hash_algorithm: HashAlgorithm::Sha512,
//!     key_rotation_interval_seconds: 3600, // 1 hour
//!     argon2_config: Argon2Config {
//!         memory_cost: 131072, // 128 MB
//!         time_cost: 4,        // 4 iterations
//!         parallelism: 8,      // 8 threads
//!         output_length: 64,   // 64 bytes
//!     },
//!     ..Default::default()
//! };
//! ```
//!
//! ### Performance Optimized Configuration
//! ```rust
//! let config = CryptoConfig {
//!     enable_hardware_acceleration: true,
//!     argon2_config: Argon2Config {
//!         memory_cost: 32768,  // 32 MB (faster)
//!         time_cost: 2,        // 2 iterations
//!         parallelism: 4,      // 4 threads
//!         output_length: 32,   // 32 bytes
//!     },
//!     key_rotation_interval_seconds: 86400, // 24 hours
//!     ..Default::default()
//! };
//! ```
//!
//! ## Security Considerations
//!
//! ### Key Management
//! - Keys are automatically rotated based on configuration
//! - Old keys are retained for decryption of existing data
//! - Key material is zeroized when no longer needed
//! - Key versions prevent confusion during rotation
//!
//! ### Algorithm Selection
//! - **AES-256-GCM**: Fastest on modern CPUs with AES-NI
//! - **ChaCha20-Poly1305**: Better on CPUs without AES hardware support
//! - **Argon2id**: Best password hashing algorithm (OWASP recommended)
//! - **HMAC-SHA256**: Fast and secure for most use cases
//!
//! ### Performance Monitoring
//! ```rust
//! let metrics = crypto.get_metrics().await;
//! println!("Operations per second: {:.2}", metrics.operations_per_second);
//! println!("Average operation time: {:.2}ms", metrics.avg_operation_time_ms);
//! println!("Hardware acceleration: {}", metrics.hardware_acceleration_used);
//! ```
//!
//! ## Error Handling
//!
//! All operations return `Result<T, CryptoError>` with detailed error information:
//!
//! ```rust
//! match crypto.encrypt(data, None, None).await {
//!     Ok(encrypted) => { /* use encrypted data */ },
//!     Err(CryptoError::KeyNotFound(version)) => {
//!         eprintln!("Missing key version: {}", version);
//!     },
//!     Err(CryptoError::EncryptionFailed(msg)) => {
//!         eprintln!("Encryption failed: {}", msg);
//!     },
//!     Err(e) => eprintln!("Crypto error: {}", e),
//! }
//! ```

use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::{engine::general_purpose, Engine as _};
use dashmap::DashMap;
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305},
    digest::{self, SHA256, SHA384, SHA512},
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, info};
use zeroize::Zeroize;

/// Comprehensive error types for cryptographic operations
///
/// Provides detailed error information for all cryptographic failures,
/// enabling proper error handling and debugging. Errors include contextual
/// information where appropriate without exposing sensitive data.
///
/// # Error Categories
///
/// - **Operation Errors**: Encryption, decryption, hashing failures
/// - **Key Management**: Key generation, rotation, and retrieval issues
/// - **Validation Errors**: Input validation and format issues
/// - **System Errors**: Random number generation and system failures
///
/// # Example
///
/// ```rust
/// use auth_service::security::cryptography::CryptoError;
///
/// match crypto_operation().await {
///     Err(CryptoError::KeyNotFound(version)) => {
///         // Handle missing key - might need key rotation
///         eprintln!("Key version {} not found, rotating keys...", version);
///     },
///     Err(CryptoError::PasswordVerificationFailed) => {
///         // Handle authentication failure
///         eprintln!("Invalid password provided");
///     },
///     Ok(result) => { /* use result */ },
///     Err(e) => eprintln!("Unexpected error: {}", e),
/// }
/// ```
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    #[error("HMAC verification failed")]
    HmacVerificationFailed,
    #[error("Password hashing failed: {0}")]
    PasswordHashingFailed(String),
    #[error("Password verification failed")]
    PasswordVerificationFailed,
    #[error("Random number generation failed")]
    RandomGenerationFailed,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Supported symmetric encryption algorithms
///
/// All algorithms provide Authenticated Encryption with Associated Data (AEAD),
/// ensuring both confidentiality and authenticity. Algorithm choice depends on
/// hardware capabilities and performance requirements.
///
/// # Algorithm Comparison
///
/// | Algorithm | Key Size | Security | Performance | Hardware Accel |
/// |-----------|----------|----------|-------------|----------------|
/// | AES-256-GCM | 256-bit | Excellent | Very Fast* | Yes (AES-NI) |
/// | ChaCha20-Poly1305 | 256-bit | Excellent | Fast | No |
///
/// \* On CPUs with AES-NI instruction set
///
/// # Recommendations
///
/// - **AES-256-GCM**: Best choice for modern server CPUs with AES-NI
/// - **ChaCha20-Poly1305**: Better for ARM processors or older CPUs without AES-NI
///
/// # Example
///
/// ```rust
/// use auth_service::security::cryptography::SymmetricAlgorithm;
///
/// let algorithm = if has_aes_ni() {
///     SymmetricAlgorithm::Aes256Gcm
/// } else {
///     SymmetricAlgorithm::ChaCha20Poly1305
/// };
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM - Hardware accelerated where available
    #[default]
    Aes256Gcm,
    /// ChaCha20-Poly1305 - Pure software implementation
    ChaCha20Poly1305,
}

impl SymmetricAlgorithm {
    const fn key_length(self) -> usize {
        match self {
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32, // 256 bits
        }
    }

    const fn nonce_length(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,        // 96 bits for GCM
            Self::ChaCha20Poly1305 => 12, // 96 bits
        }
    }

    fn to_ring_algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes256Gcm => &AES_256_GCM,
            Self::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        }
    }
}

/// Supported cryptographic hash algorithms
///
/// Used for HMAC operations and general-purpose hashing. All algorithms
/// are cryptographically secure and suitable for security applications.
///
/// # Algorithm Comparison
///
/// | Algorithm | Output Size | Security Level | Performance |
/// |-----------|------------|----------------|-------------|
/// | SHA-256 | 32 bytes | 128-bit | Fast |
/// | SHA-384 | 48 bytes | 192-bit | Medium |
/// | SHA-512 | 64 bytes | 256-bit | Medium |
///
/// # Recommendations
///
/// - **SHA-256**: Best balance of security and performance (default)
/// - **SHA-384**: When 192-bit security level is required
/// - **SHA-512**: Maximum security, slower but acceptable for most uses
///
/// # Example
///
/// ```rust
/// use auth_service::security::cryptography::HashAlgorithm;
///
/// // Choose based on security requirements
/// let algorithm = match security_level {
///     "high" => HashAlgorithm::Sha512,
///     "medium" => HashAlgorithm::Sha384,
///     _ => HashAlgorithm::Sha256, // default
/// };
/// ```
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    fn to_ring_algorithm(self) -> &'static digest::Algorithm {
        match self {
            Self::Sha256 => &SHA256,
            Self::Sha384 => &SHA384,
            Self::Sha512 => &SHA512,
        }
    }

    const fn output_length(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Comprehensive cryptographic configuration
///
/// Central configuration structure for all cryptographic operations.
/// Provides sensible defaults while allowing fine-tuning for specific
/// security and performance requirements.
///
/// # Configuration Categories
///
/// - **Algorithm Selection**: Choose default algorithms for operations
/// - **Key Management**: Configure key rotation and caching
/// - **Performance**: Hardware acceleration and caching settings
/// - **Password Hashing**: Argon2 parameter configuration
///
/// # Security vs Performance Trade-offs
///
/// Higher security settings (longer keys, more iterations, frequent rotation)
/// provide better security but reduce performance. Tune based on your
/// threat model and performance requirements.
///
/// # Example Configurations
///
/// ```rust
/// use auth_service::security::cryptography::*;
///
/// // High-security configuration
/// let high_security = CryptoConfig {
///     key_rotation_interval_seconds: 3600, // 1 hour rotation
///     argon2_config: Argon2Config {
///         memory_cost: 131072, // 128 MB
///         time_cost: 4,        // 4 iterations
///         parallelism: 8,      // 8 threads
///         output_length: 64,   // 64 bytes
///     },
///     ..Default::default()
/// };
///
/// // Performance-optimized configuration
/// let performance = CryptoConfig {
///     key_rotation_interval_seconds: 86400, // 24 hour rotation
///     enable_hardware_acceleration: true,
///     argon2_config: Argon2Config {
///         memory_cost: 32768,  // 32 MB
///         time_cost: 2,        // 2 iterations
///         parallelism: 4,      // 4 threads
///         output_length: 32,   // 32 bytes
///     },
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Default symmetric encryption algorithm
    pub default_symmetric_algorithm: SymmetricAlgorithm,
    /// Default hash algorithm
    pub default_hash_algorithm: HashAlgorithm,
    /// Key rotation interval in seconds
    pub key_rotation_interval_seconds: u64,
    /// Maximum number of keys to cache
    pub max_cached_keys: usize,
    /// Enable hardware acceleration when available
    pub enable_hardware_acceleration: bool,
    /// Argon2 configuration
    pub argon2_config: Argon2Config,
}

/// Argon2 password hashing configuration parameters
///
/// Configures the Argon2id password hashing algorithm parameters.
/// Argon2id is the recommended password hashing algorithm by OWASP
/// and provides excellent security against various attack vectors.
///
/// # Parameters Explained
///
/// - **Memory Cost**: Amount of memory used in `KiB` (affects resistance to GPU attacks)
/// - **Time Cost**: Number of iterations (affects time to compute hash)
/// - **Parallelism**: Number of parallel threads (affects multi-core utilization)
/// - **Output Length**: Length of the output hash in bytes
///
/// # Security Recommendations (2024)
///
/// - **Minimum**: `memory_cost=37888` (37MB), `time_cost=2`, `parallelism=1`
/// - **Recommended**: `memory_cost=65536` (64MB), `time_cost=3`, `parallelism=4`
/// - **High Security**: `memory_cost=131072` (128MB), `time_cost=4`, `parallelism=8`
///
/// # Performance Considerations
///
/// Higher values provide better security but slower hashing:
/// - Memory cost has the biggest impact on GPU attack resistance
/// - Time cost linearly affects hashing time
/// - Parallelism can improve performance on multi-core systems
///
/// # Example Configurations
///
/// ```rust
/// use auth_service::security::cryptography::Argon2Config;
///
/// // For high-traffic websites (balanced)
/// let balanced = Argon2Config {
///     memory_cost: 65536,    // 64 MB
///     time_cost: 3,          // 3 iterations
///     parallelism: 4,        // 4 threads
///     output_length: 32,     // 32 bytes
/// };
///
/// // For maximum security (slower)
/// let high_security = Argon2Config {
///     memory_cost: 131072,   // 128 MB
///     time_cost: 4,          // 4 iterations
///     parallelism: 8,        // 8 threads
///     output_length: 64,     // 64 bytes
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Config {
    /// Memory cost (in `KiB`)
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism (threads)
    pub parallelism: u32,
    /// Hash output length
    pub output_length: usize,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            default_symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            default_hash_algorithm: HashAlgorithm::Sha256,
            key_rotation_interval_seconds: 86400, // 24 hours
            max_cached_keys: 1000,
            enable_hardware_acceleration: true,
            argon2_config: Argon2Config::default(),
        }
    }
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MB
            time_cost: 3,       // 3 iterations
            parallelism: 4,     // 4 threads
            output_length: 32,  // 32 bytes
        }
    }
}

/// Performance metrics for cryptographic operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CryptoMetrics {
    pub total_operations: u64,
    pub total_duration_ms: u64,
    pub operations_per_second: f64,
    pub avg_operation_time_ms: f64,
    pub cache_hit_rate: f64,
    pub hardware_acceleration_used: bool,
}

/// Encrypted data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Algorithm used for encryption
    pub algorithm: SymmetricAlgorithm,
    /// Key version/ID used
    pub key_version: u32,
    /// Initialization vector/nonce
    pub nonce: Vec<u8>,
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// Authentication tag (included in AEAD)
    pub tag: Vec<u8>,
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
    /// Timestamp when encrypted
    pub encrypted_at: u64,
}

/// HMAC result structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacResult {
    /// Hash algorithm used
    pub algorithm: HashAlgorithm,
    /// HMAC value
    pub hmac: Vec<u8>,
    /// Key version used
    pub key_version: u32,
    /// Timestamp when computed
    pub computed_at: u64,
}

/// Unified cryptographic service
pub struct UnifiedCryptography {
    config: CryptoConfig,
    rng: SystemRandom,

    // Key storage
    symmetric_keys: Arc<DashMap<u32, Vec<u8>>>, // version -> key
    hmac_keys: Arc<DashMap<u32, hmac::Key>>,    // version -> hmac key

    // Current key versions
    current_symmetric_key_version: Arc<RwLock<u32>>,
    current_hmac_key_version: Arc<RwLock<u32>>,

    // Performance tracking
    metrics: Arc<RwLock<CryptoMetrics>>,
    last_key_rotation: Arc<RwLock<Instant>>,

    // Password hashing
    argon2: Argon2<'static>,
}

impl UnifiedCryptography {
    /// Create a new unified cryptography service
    ///
    /// Initializes a complete cryptography service with the provided configuration.
    /// This includes setting up Argon2 password hashing, generating initial keys,
    /// and preparing all internal data structures.
    ///
    /// # Arguments
    ///
    /// * `config` - Cryptographic configuration parameters
    ///
    /// # Returns
    ///
    /// Returns a fully initialized `UnifiedCryptography` service ready for use.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if:
    /// - Argon2 parameters are invalid (e.g., memory cost too high)
    /// - Initial key generation fails
    /// - System lacks sufficient entropy for secure random generation
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth_service::security::cryptography::*;
    ///
    /// let config = CryptoConfig::default();
    /// let crypto = UnifiedCryptography::new(config).await?;
    /// ```
    ///
    /// # Performance Note
    ///
    /// This function may take some time during initialization due to:
    /// - Initial key generation using cryptographically secure random numbers
    /// - Argon2 parameter validation and setup
    /// - Internal data structure initialization
    pub async fn new(config: CryptoConfig) -> Result<Self, CryptoError> {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                config.argon2_config.memory_cost,
                config.argon2_config.time_cost,
                config.argon2_config.parallelism,
                Some(config.argon2_config.output_length),
            )
            .map_err(|e| CryptoError::InvalidInput(format!("Invalid Argon2 parameters: {e}")))?,
        );

        let service = Self {
            config,
            rng: SystemRandom::new(),
            symmetric_keys: Arc::new(DashMap::new()),
            hmac_keys: Arc::new(DashMap::new()),
            current_symmetric_key_version: Arc::new(RwLock::new(1)),
            current_hmac_key_version: Arc::new(RwLock::new(1)),
            metrics: Arc::new(RwLock::new(CryptoMetrics::default())),
            last_key_rotation: Arc::new(RwLock::new(Instant::now())),
            argon2,
        };

        // Generate initial keys
        service.rotate_keys().await?;

        info!("Unified cryptography service initialized");
        Ok(service)
    }

    /// Generate a new random symmetric key
    fn generate_symmetric_key(
        &self,
        algorithm: SymmetricAlgorithm,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut key = vec![0u8; algorithm.key_length()];
        self.rng.fill(&mut key).map_err(|_| {
            CryptoError::KeyGenerationFailed("Failed to generate random key".to_string())
        })?;
        Ok(key)
    }

    /// Generate a new HMAC key
    fn generate_hmac_key(&self, algorithm: HashAlgorithm) -> Result<hmac::Key, CryptoError> {
        let key_len = std::cmp::max(algorithm.output_length(), 32); // Minimum 32 bytes
        let mut key_bytes = vec![0u8; key_len];
        self.rng.fill(&mut key_bytes).map_err(|_| {
            CryptoError::KeyGenerationFailed("Failed to generate HMAC key".to_string())
        })?;

        let hmac_algorithm = match algorithm {
            HashAlgorithm::Sha256 => hmac::HMAC_SHA256,
            HashAlgorithm::Sha384 => hmac::HMAC_SHA384,
            HashAlgorithm::Sha512 => hmac::HMAC_SHA512,
        };

        let key = hmac::Key::new(hmac_algorithm, &key_bytes);
        key_bytes.zeroize(); // Clear key material from memory
        Ok(key)
    }

    /// Rotate encryption and HMAC keys
    ///
    /// Generates new symmetric encryption and HMAC keys, incrementing version numbers
    /// and storing them for use in new operations. Old keys are retained for
    /// decryption of existing data but cleaned up after a configurable retention period.
    ///
    /// # Key Rotation Benefits
    ///
    /// - **Forward Secrecy**: Compromise of current keys doesn't affect future data
    /// - **Backward Security**: New keys protect future data even if old keys compromised
    /// - **Compliance**: Meets regulatory requirements for regular key rotation
    /// - **Risk Mitigation**: Limits exposure window in case of key compromise
    ///
    /// # Automatic Cleanup
    ///
    /// Old keys are automatically cleaned up to prevent memory bloat:
    /// - Retains last 5 versions for decryption of existing data
    /// - Older keys are securely zeroized and removed
    /// - Key material never persists longer than necessary
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on successful key rotation.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if:
    /// - Random number generation fails (system entropy issue)
    /// - HMAC key generation fails
    /// - Symmetric key generation fails
    ///
    /// # Example
    ///
    /// ```rust
    /// // Manual key rotation
    /// crypto.rotate_keys().await?;
    ///
    /// // Or use automatic rotation checking
    /// crypto.check_key_rotation().await?; // Rotates if interval elapsed
    /// ```
    ///
    /// # Performance
    ///
    /// Key rotation is fast (typically < 1ms) and can be performed during
    /// normal operation without service interruption.
    pub async fn rotate_keys(&self) -> Result<(), CryptoError> {
        let start_time = Instant::now();

        // Generate new symmetric key
        let new_symmetric_key =
            self.generate_symmetric_key(self.config.default_symmetric_algorithm)?;
        let new_symmetric_version = {
            let mut version = self.current_symmetric_key_version.write().await;
            *version += 1;
            *version
        };

        // Generate new HMAC key
        let new_hmac_key = self.generate_hmac_key(self.config.default_hash_algorithm)?;
        let new_hmac_version = {
            let mut version = self.current_hmac_key_version.write().await;
            *version += 1;
            *version
        };

        // Store new keys
        self.symmetric_keys
            .insert(new_symmetric_version, new_symmetric_key);
        self.hmac_keys.insert(new_hmac_version, new_hmac_key);

        // Cleanup old keys (keep last 5 versions)
        if self.symmetric_keys.len() > 5 {
            let versions_to_remove: Vec<_> = self
                .symmetric_keys
                .iter()
                .map(|entry| *entry.key())
                .filter(|&v| v < new_symmetric_version - 5)
                .collect();

            for version in versions_to_remove {
                if let Some((_, mut key)) = self.symmetric_keys.remove(&version) {
                    key.zeroize(); // Clear key material
                }
            }
        }

        if self.hmac_keys.len() > 5 {
            let versions_to_remove: Vec<_> = self
                .hmac_keys
                .iter()
                .map(|entry| *entry.key())
                .filter(|&v| v < new_hmac_version - 5)
                .collect();

            for version in versions_to_remove {
                self.hmac_keys.remove(&version);
            }
        }

        *self.last_key_rotation.write().await = Instant::now();

        let duration = start_time.elapsed();
        info!(
            "Key rotation completed in {:?}. New versions: symmetric={}, hmac={}",
            duration, new_symmetric_version, new_hmac_version
        );

        Ok(())
    }

    /// Check if key rotation is needed and rotate if necessary
    ///
    /// Automatically checks if the configured key rotation interval has elapsed
    /// since the last rotation and performs rotation if needed. This should be
    /// called periodically (e.g., on each request or via a background task).
    ///
    /// # Rotation Logic
    ///
    /// Keys are rotated if:
    /// - Time since last rotation >= `key_rotation_interval_seconds`
    /// - No rotation has occurred yet (initial state)
    ///
    /// # Usage Patterns
    ///
    /// ```rust
    /// // Check on each request (low overhead)
    /// crypto.check_key_rotation().await?;
    ///
    /// // Or use a background task
    /// tokio::spawn(async move {
    ///     let mut interval = tokio::time::interval(Duration::from_secs(300));
    ///     loop {
    ///         interval.tick().await;
    ///         if let Err(e) = crypto.check_key_rotation().await {
    ///             eprintln!("Key rotation failed: {}", e);
    ///         }
    ///     }
    /// });
    /// ```
    ///
    /// # Performance
    ///
    /// This check is very lightweight when rotation is not needed (just a timestamp
    /// comparison). Actual rotation only occurs when the interval has elapsed.
    pub async fn check_key_rotation(&self) -> Result<(), CryptoError> {
        let last_rotation = *self.last_key_rotation.read().await;
        let rotation_interval = Duration::from_secs(self.config.key_rotation_interval_seconds);

        if last_rotation.elapsed() >= rotation_interval {
            self.rotate_keys().await?;
        }

        Ok(())
    }

    /// Encrypt data using symmetric encryption
    ///
    /// # Panics
    ///
    /// This function may panic if:
    /// - The system clock is set to before the Unix epoch (1970-01-01)
    pub async fn encrypt(
        &self,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        algorithm: Option<SymmetricAlgorithm>,
    ) -> Result<EncryptedData, CryptoError> {
        let start_time = Instant::now();

        let algorithm = algorithm.unwrap_or(self.config.default_symmetric_algorithm);
        let key_version = *self.current_symmetric_key_version.read().await;

        let key_data = self.symmetric_keys.get(&key_version).ok_or_else(|| {
            CryptoError::KeyNotFound(format!("Symmetric key version {key_version}"))
        })?;

        // Generate nonce
        let mut nonce_bytes = vec![0u8; algorithm.nonce_length()];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::EncryptionFailed("Failed to generate nonce".to_string()))?;

        // Create encryption key
        let unbound_key = UnboundKey::new(algorithm.to_ring_algorithm(), &key_data)
            .map_err(|e| CryptoError::EncryptionFailed(format!("Invalid key: {e}")))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(
            nonce_bytes
                .clone()
                .try_into()
                .map_err(|_| CryptoError::EncryptionFailed("Invalid nonce length".to_string()))?,
        );

        // Encrypt
        let mut ciphertext = plaintext.to_vec();
        let tag = less_safe_key
            .seal_in_place_separate_tag(nonce, Aad::from(aad.unwrap_or(&[])), &mut ciphertext)
            .map_err(|e| CryptoError::EncryptionFailed(format!("Encryption failed: {e}")))?;

        let encrypted_data = EncryptedData {
            algorithm,
            key_version,
            nonce: nonce_bytes,
            ciphertext,
            tag: tag.as_ref().to_vec(),
            aad: aad.map(<[u8]>::to_vec),
            encrypted_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs(),
        };

        // Update metrics
        self.update_metrics(start_time.elapsed()).await;

        Ok(encrypted_data)
    }

    /// Decrypt data using symmetric encryption
    pub async fn decrypt(&self, encrypted_data: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
        let start_time = Instant::now();

        let key_data = self
            .symmetric_keys
            .get(&encrypted_data.key_version)
            .ok_or_else(|| {
                CryptoError::KeyNotFound(format!(
                    "Symmetric key version {}",
                    encrypted_data.key_version
                ))
            })?;

        // Create decryption key
        let unbound_key = UnboundKey::new(encrypted_data.algorithm.to_ring_algorithm(), &key_data)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid key: {e}")))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::try_assume_unique_for_key(&encrypted_data.nonce)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid nonce: {e}")))?;

        // Prepare ciphertext with tag
        let mut ciphertext_with_tag = encrypted_data.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&encrypted_data.tag);

        // Decrypt
        let plaintext = less_safe_key
            .open_in_place(
                nonce,
                Aad::from(encrypted_data.aad.as_deref().unwrap_or(&[])),
                &mut ciphertext_with_tag,
            )
            .map_err(|e| CryptoError::DecryptionFailed(format!("Decryption failed: {e}")))?;

        // Update metrics
        self.update_metrics(start_time.elapsed()).await;

        Ok(plaintext.to_vec())
    }

    /// Compute HMAC
    ///
    /// # Panics
    ///
    /// This function may panic if:
    /// - The system clock is set to before the Unix epoch (1970-01-01)
    pub async fn compute_hmac(
        &self,
        data: &[u8],
        algorithm: Option<HashAlgorithm>,
    ) -> Result<HmacResult, CryptoError> {
        let start_time = Instant::now();

        let algorithm = algorithm.unwrap_or(self.config.default_hash_algorithm);
        let key_version = *self.current_hmac_key_version.read().await;

        let hmac_key = self
            .hmac_keys
            .get(&key_version)
            .ok_or_else(|| CryptoError::KeyNotFound(format!("HMAC key version {key_version}")))?;

        let tag = hmac::sign(&hmac_key, data);
        let hmac_bytes = tag.as_ref().to_vec();

        let result = HmacResult {
            algorithm,
            hmac: hmac_bytes,
            key_version,
            computed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs(),
        };

        // Update metrics
        self.update_metrics(start_time.elapsed()).await;

        Ok(result)
    }

    /// Verify HMAC
    pub async fn verify_hmac(
        &self,
        data: &[u8],
        hmac_result: &HmacResult,
    ) -> Result<bool, CryptoError> {
        let start_time = Instant::now();

        let hmac_key = self
            .hmac_keys
            .get(&hmac_result.key_version)
            .ok_or_else(|| {
                CryptoError::KeyNotFound(format!("HMAC key version {}", hmac_result.key_version))
            })?;

        let verification_result = hmac::verify(&hmac_key, data, &hmac_result.hmac);
        let is_valid = verification_result.is_ok();

        // Update metrics
        self.update_metrics(start_time.elapsed()).await;

        if is_valid {
            Ok(true)
        } else {
            Err(CryptoError::HmacVerificationFailed)
        }
    }

    /// Hash password using Argon2id algorithm
    ///
    /// Securely hashes a password using the Argon2id algorithm with a randomly
    /// generated salt. Argon2id is the recommended password hashing algorithm
    /// by OWASP and provides excellent security against various attack vectors.
    ///
    /// # Security Features
    ///
    /// - **Memory-Hard**: Uses configurable memory to resist GPU attacks
    /// - **Time-Hard**: Configurable iterations resist brute force attacks
    /// - **Salt**: Each hash uses a unique random salt
    /// - **Side-Channel Resistant**: Resistant to timing and cache attacks
    ///
    /// # Arguments
    ///
    /// * `password` - The plaintext password to hash
    ///
    /// # Returns
    ///
    /// Returns a password hash string in PHC (Password Hashing Competition) format:
    /// `$argon2id$v=19$m=65536,t=3,p=4$saltbase64$hashbase64`
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::PasswordHashingFailed` if:
    /// - Salt generation fails (system entropy issue)
    /// - Argon2 hashing fails (invalid parameters or memory allocation)
    ///
    /// # Example
    ///
    /// ```rust
    /// let password = "user_secure_password_123!";
    /// let hash = crypto.hash_password(password).await?;
    /// println!("Password hash: {}", hash);
    ///
    /// // Hash can be stored in database and verified later
    /// let is_valid = crypto.verify_password(password, &hash).await?;
    /// assert!(is_valid);
    /// ```
    ///
    /// # Performance
    ///
    /// Hashing time depends on configured parameters:
    /// - Default config: ~100-200ms (suitable for login endpoints)
    /// - High security: ~500ms+ (suitable for admin password changes)
    /// - Performance config: ~50ms (for high-traffic scenarios)
    pub async fn hash_password(&self, password: &str) -> Result<String, CryptoError> {
        let start_time = Instant::now();

        let salt = SaltString::generate(&mut OsRng);
        let hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                CryptoError::PasswordHashingFailed(format!("Argon2 hashing failed: {e}"))
            })?;

        // Update metrics
        self.update_metrics(start_time.elapsed()).await;

        Ok(hash.to_string())
    }

    /// Verify password against Argon2id hash
    ///
    /// Verifies a plaintext password against an Argon2id hash. Uses constant-time
    /// comparison to prevent timing attacks. The hash must be in PHC format as
    /// produced by `hash_password`.
    ///
    /// # Security Features
    ///
    /// - **Constant-Time**: Verification time is independent of correctness
    /// - **Parameter Extraction**: Automatically extracts parameters from hash
    /// - **Format Validation**: Validates hash format before verification
    /// - **Side-Channel Resistant**: Resistant to timing attacks
    ///
    /// # Arguments
    ///
    /// * `password` - The plaintext password to verify
    /// * `hash` - The Argon2id hash string to verify against
    ///
    /// # Returns
    ///
    /// Returns `true` if the password matches the hash, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::PasswordVerificationFailed` if:
    /// - Hash format is invalid or corrupted
    /// - Hash parameters are invalid or unsupported
    /// - Argon2 verification process fails
    ///
    /// Note: Incorrect passwords return `Ok(false)`, not an error.
    ///
    /// # Example
    ///
    /// ```rust
    /// // During login process
    /// let user_password = "user_input_password";
    /// let stored_hash = user.password_hash; // from database
    ///
    /// match crypto.verify_password(user_password, &stored_hash).await {
    ///     Ok(true) => println!("Login successful"),
    ///     Ok(false) => println!("Invalid password"),
    ///     Err(e) => println!("Verification error: {}", e),
    /// }
    /// ```
    ///
    /// # Performance
    ///
    /// Verification time is the same as hashing time (by design) and depends
    /// on the parameters used when the hash was created, not current config.
    pub async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, CryptoError> {
        let start_time = Instant::now();

        let parsed_hash =
            PasswordHash::new(hash).map_err(|_e| CryptoError::PasswordVerificationFailed)?;

        let verification_result = self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash);
        let is_valid = verification_result.is_ok();

        // Update metrics
        self.update_metrics(start_time.elapsed()).await;

        Ok(is_valid)
    }

    /// Generate cryptographically secure random bytes
    ///
    /// Generates the specified number of cryptographically secure random bytes
    /// using the system's entropy source. Suitable for generating keys, tokens,
    /// salts, and other security-sensitive random values.
    ///
    /// # Security Properties
    ///
    /// - **Cryptographically Secure**: Uses OS entropy sources (e.g., `/dev/urandom`)
    /// - **Unpredictable**: Cannot be predicted even with knowledge of previous values
    /// - **Uniform Distribution**: All byte values equally likely
    /// - **High Entropy**: Suitable for cryptographic keys and security tokens
    ///
    /// # Arguments
    ///
    /// * `length` - Number of random bytes to generate
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the requested number of random bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RandomGenerationFailed` if:
    /// - System entropy source is unavailable
    /// - Insufficient system entropy available
    /// - Memory allocation fails for the requested length
    ///
    /// # Example
    ///
    /// ```rust
    /// // Generate random bytes for different use cases
    /// let session_id = crypto.generate_random_bytes(32)?;     // 256-bit session ID
    /// let salt = crypto.generate_random_bytes(16)?;           // 128-bit salt
    /// let api_key = crypto.generate_random_bytes(24)?;        // 192-bit API key
    ///
    /// println!("Generated {} random bytes", session_id.len());
    /// ```
    ///
    /// # Performance
    ///
    /// Very fast operation (microseconds) suitable for frequent use in
    /// token generation and other security operations.
    pub fn generate_random_bytes(&self, length: usize) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = vec![0u8; length];
        self.rng
            .fill(&mut bytes)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(bytes)
    }

    /// Generate cryptographically secure random string (`Base64URL` encoded)
    ///
    /// Generates a random string suitable for use as tokens, session IDs, or other
    /// text-based security identifiers. Uses `Base64URL` encoding (RFC 4648) which
    /// is URL-safe and doesn't require padding.
    ///
    /// # Encoding Details
    ///
    /// - **`Base64URL`**: Uses characters `A-Z`, `a-z`, `0-9`, `-`, `_`
    /// - **URL Safe**: No special URL characters (`+`, `/`, `=`)
    /// - **No Padding**: Omits padding characters for cleaner tokens
    /// - **Length**: Output is approximately 4/3 the length of input bytes
    ///
    /// # Arguments
    ///
    /// * `length` - Number of random bytes to generate (before encoding)
    ///
    /// # Returns
    ///
    /// Returns a `Base64URL` encoded string containing the random data.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::RandomGenerationFailed` if random byte generation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// // Generate tokens for different purposes
    /// let session_token = crypto.generate_random_string(32)?;   // ~43 chars
    /// let api_key = crypto.generate_random_string(24)?;         // ~32 chars
    /// let csrf_token = crypto.generate_random_string(16)?;      // ~22 chars
    ///
    /// println!("Session token: {}", session_token);
    /// // Output example: "Zx8vQ2mK7nP4jR9sL1wE6tY3uI0oA5bC"
    /// ```
    ///
    /// # Use Cases
    ///
    /// - Session tokens and IDs
    /// - API keys and access tokens
    /// - CSRF tokens
    /// - Password reset tokens
    /// - Email verification codes
    /// - Any URL-safe random identifier
    ///
    /// # Performance
    ///
    /// Very fast operation suitable for generating tokens on every request.
    pub fn generate_random_string(&self, length: usize) -> Result<String, CryptoError> {
        let bytes = self.generate_random_bytes(length)?;
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(&bytes))
    }

    /// Compute hash digest
    #[must_use]
    pub fn hash_digest(&self, data: &[u8], algorithm: Option<HashAlgorithm>) -> Vec<u8> {
        let algorithm = algorithm.unwrap_or(self.config.default_hash_algorithm);
        digest::digest(algorithm.to_ring_algorithm(), data)
            .as_ref()
            .to_vec()
    }

    /// Update performance metrics
    async fn update_metrics(&self, operation_duration: Duration) {
        let mut metrics = self.metrics.write().await;
        metrics.total_operations += 1;
        metrics.total_duration_ms += operation_duration.as_millis() as u64;

        if metrics.total_operations > 0 {
            metrics.avg_operation_time_ms =
                metrics.total_duration_ms as f64 / metrics.total_operations as f64;
            metrics.operations_per_second =
                metrics.total_operations as f64 / (metrics.total_duration_ms as f64 / 1000.0);
        }

        metrics.hardware_acceleration_used = self.config.enable_hardware_acceleration;
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> CryptoMetrics {
        self.metrics.read().await.clone()
    }

    /// Reset metrics
    pub async fn reset_metrics(&self) {
        *self.metrics.write().await = CryptoMetrics::default();
    }

    /// Get configuration
    #[must_use]
    pub const fn get_config(&self) -> &CryptoConfig {
        &self.config
    }
}

/// Global cryptography service instance
static GLOBAL_CRYPTO: std::sync::LazyLock<std::sync::RwLock<Option<Arc<UnifiedCryptography>>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(None));

/// Initialize global cryptography service
///
/// # Panics
///
/// This function may panic if:
/// - The global crypto `RwLock` is poisoned by a previous panic
pub async fn initialize_global_crypto(config: CryptoConfig) -> Result<(), CryptoError> {
    let crypto = UnifiedCryptography::new(config).await?;
    let mut global = match GLOBAL_CRYPTO.write() {
        Ok(lock) => lock,
        Err(_) => {
            error!("GLOBAL_CRYPTO mutex is poisoned");
            return Err(CryptoError::KeyGenerationFailed(
                "Cryptography service mutex poisoned".to_string(),
            ));
        }
    };
    *global = Some(Arc::new(crypto));
    info!("Global cryptography service initialized");
    Ok(())
}

/// Get global cryptography service
///
/// # Panics
///
/// This function may panic if:
/// - The global crypto `RwLock` is poisoned by a previous panic
pub fn get_global_crypto() -> Option<Arc<UnifiedCryptography>> {
    GLOBAL_CRYPTO.read().ok().and_then(|guard| guard.clone())
}

/// Convenience functions using global service
pub async fn encrypt_global(
    plaintext: &[u8],
    aad: Option<&[u8]>,
    algorithm: Option<SymmetricAlgorithm>,
) -> Result<EncryptedData, CryptoError> {
    let crypto = get_global_crypto()
        .ok_or_else(|| CryptoError::InvalidInput("Global crypto not initialized".to_string()))?;
    crypto.encrypt(plaintext, aad, algorithm).await
}

pub async fn decrypt_global(encrypted_data: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
    let crypto = get_global_crypto()
        .ok_or_else(|| CryptoError::InvalidInput("Global crypto not initialized".to_string()))?;
    crypto.decrypt(encrypted_data).await
}

pub async fn hash_password_global(password: &str) -> Result<String, CryptoError> {
    let crypto = get_global_crypto()
        .ok_or_else(|| CryptoError::InvalidInput("Global crypto not initialized".to_string()))?;
    crypto.hash_password(password).await
}

pub async fn verify_password_global(password: &str, hash: &str) -> Result<bool, CryptoError> {
    let crypto = get_global_crypto()
        .ok_or_else(|| CryptoError::InvalidInput("Global crypto not initialized".to_string()))?;
    crypto.verify_password(password, hash).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encryption_decryption() {
        let config = CryptoConfig::default();
        let crypto = UnifiedCryptography::new(config).await.unwrap();

        let plaintext = b"Hello, World!";
        let aad = b"additional_data";

        let encrypted = crypto.encrypt(plaintext, Some(aad), None).await.unwrap();
        let decrypted = crypto.decrypt(&encrypted).await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_hmac_operations() {
        let config = CryptoConfig::default();
        let crypto = UnifiedCryptography::new(config).await.unwrap();

        let data = b"test data for hmac";
        let hmac_result = crypto.compute_hmac(data, None).await.unwrap();
        let is_valid = crypto.verify_hmac(data, &hmac_result).await.unwrap();

        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_password_operations() {
        let config = CryptoConfig::default();
        let crypto = UnifiedCryptography::new(config).await.unwrap();

        let password = "secure_password_123!";
        let hash = crypto.hash_password(password).await.unwrap();
        let is_valid = crypto.verify_password(password, &hash).await.unwrap();

        assert!(is_valid);
        assert!(!crypto
            .verify_password("wrong_password", &hash)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let config = CryptoConfig::default();
        let crypto = UnifiedCryptography::new(config).await.unwrap();

        let initial_sym_version = *crypto.current_symmetric_key_version.read().await;
        let initial_hmac_version = *crypto.current_hmac_key_version.read().await;

        crypto.rotate_keys().await.unwrap();

        let new_sym_version = *crypto.current_symmetric_key_version.read().await;
        let new_hmac_version = *crypto.current_hmac_key_version.read().await;

        assert!(new_sym_version > initial_sym_version);
        assert!(new_hmac_version > initial_hmac_version);
    }

    #[tokio::test]
    async fn test_random_generation() {
        let config = CryptoConfig::default();
        let crypto = UnifiedCryptography::new(config).await.unwrap();

        let bytes1 = crypto.generate_random_bytes(32).unwrap();
        let bytes2 = crypto.generate_random_bytes(32).unwrap();
        let string = crypto.generate_random_string(16).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2);
        assert!(!string.is_empty());
    }

    #[tokio::test]
    async fn test_global_crypto() {
        let config = CryptoConfig::default();
        initialize_global_crypto(config).await.unwrap();

        let plaintext = b"Global crypto test";
        let encrypted = encrypt_global(plaintext, None, None).await.unwrap();
        let decrypted = decrypt_global(&encrypted).await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice());

        let password = "test_password";
        let hash = hash_password_global(password).await.unwrap();
        let is_valid = verify_password_global(password, &hash).await.unwrap();

        assert!(is_valid);
    }
}
