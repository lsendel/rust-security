//! Service Initializer
//!
//! This module handles the initialization of all application services
//! including infrastructure components, security services, and background tasks.

use crate::application::auth::auth_api::AuthState;
use crate::config::Config;

/// Service initializer for setting up all application components
pub struct ServiceInitializer;

impl ServiceInitializer {
    /// Initialize all application services
    ///
    /// This method sets up all the required services in the correct order:
    /// 1. Infrastructure services (database, cache, etc.)
    /// 2. Security services (JWT, encryption, etc.)
    /// 3. Application services (user management, auth, etc.)
    /// 4. Background tasks (cleanup, monitoring, etc.)
    ///
    /// # Arguments
    ///
    /// * `config` - The application configuration
    ///
    /// # Errors
    ///
    /// Returns an error if any service initialization fails.
    pub async fn initialize_services(
        config: &Config,
    ) -> Result<AuthState, Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("🚀 Initializing Rust Security Platform - Auth Service v2.0");
        tracing::info!("🔐 Enhanced with OAuth 2.0, User Registration, and JWT Authentication");

        // Initialize JWT signing keys
        Self::initialize_jwt_keys().await?;

        // Initialize threat detection
        Self::initialize_threat_detection().await;

        // Initialize security test mode
        Self::initialize_test_mode_security();

        // Start background tasks
        Self::start_background_tasks(config);

        // Create AuthState with JWT secret
        let jwt_secret = config
            .get_jwt_secret()
            .map_err(|e| format!("Failed to get JWT secret: {}", e))?;
        let auth_state = AuthState::new(jwt_secret);

        tracing::info!("✅ All services initialized successfully");

        Ok(auth_state)
    }

    /// Initialize JWT signing keys
    async fn initialize_jwt_keys() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::infrastructure::crypto::keys::initialize_keys;

        if let Err(e) = initialize_keys().await {
            return Err(format!(
                "Failed to initialize JWT signing keys: {}. Set RSA key via RSA_PRIVATE_KEY or RSA_PRIVATE_KEY_PATH",
                e
            ).into());
        }

        tracing::info!("✅ JWKS key management initialized successfully");
        Ok(())
    }

    /// Initialize threat detection system
    async fn initialize_threat_detection() {
        use crate::middleware::initialize_threat_detection;
        use crate::security_enhancements::ThreatDetector;

        let threat_detector = ThreatDetector::new();
        threat_detector.initialize_default_patterns().await;

        initialize_threat_detection().await;
    }

    /// Initialize test mode security checks
    fn initialize_test_mode_security() {
        use crate::test_mode_security::initialize_test_mode_security;
        initialize_test_mode_security();
    }

    /// Start background tasks
    fn start_background_tasks(config: &Config) {
        use crate::infrastructure::security::security::start_rate_limiter_cleanup;

        // Start rate limiter cleanup task
        start_rate_limiter_cleanup();

        // Start key rotation task
        Self::start_key_rotation_task(config);
    }

    /// Start JWT key rotation background task
    fn start_key_rotation_task(config: &Config) {
        let key_rotation_check_interval = config.jwt.key_rotation_check_interval;

        tokio::spawn(async move {
            loop {
                let _ = crate::infrastructure::crypto::keys::maybe_rotate().await;
                tokio::time::sleep(key_rotation_check_interval).await;
            }
        });
    }
}
