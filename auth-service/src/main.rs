//! Auth Service Main Entry Point
//!
//! Enterprise-grade authentication service with comprehensive security features.

#![allow(clippy::multiple_crate_versions)]

use anyhow::Context;
use common::security::UnifiedSecurityConfig;
use std::sync::Arc;
use tracing::{error, info, warn};

mod config;

use auth_service::auth_api::AuthState;
use auth_service::infrastructure::security::security::start_rate_limiter_cleanup;
use auth_service::middleware::initialize_threat_detection;
use auth_service::security_enhancements::ThreatDetector;
use config::Config;
// Initialize secure JWT key management
use auth_service::infrastructure::crypto::keys::{initialize_keys, jwks_document};
use auth_service::middleware::threat_metrics;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // SECURITY: Load and validate configuration before doing anything else
    let config = auth_service::config_secure_validation::SecureConfig::from_env()
        .context("Failed to load secure configuration")?;

    // Validate production readiness if in production
    config
        .validate_production_ready()
        .context("Configuration failed production readiness check")?;

    // Log security configuration status (without sensitive values)
    config.log_security_status();

    // Initialize logging (structured in production, pretty in dev)
    // Prefer production logging configuration when APP_ENV=production
    if std::env::var("APP_ENV")
        .unwrap_or_default()
        .eq_ignore_ascii_case("production")
    {
        let _ = auth_service::production_logging::initialize_logging(
            &auth_service::production_logging::LoggingConfig::production(),
        );
    } else if std::env::var("APP_ENV")
        .unwrap_or_default()
        .eq_ignore_ascii_case("development")
    {
        let _ = auth_service::production_logging::initialize_logging(
            &auth_service::production_logging::LoggingConfig::development(),
        );
    } else {
        // Fallback to a simple subscriber for local runs/tests
        let _ = auth_service::production_logging::initialize_logging(
            &auth_service::production_logging::LoggingConfig::default(),
        );
    }

    info!("🚀 Starting Rust Security Platform - Auth Service v2.0");
    info!("🔐 Enhanced with OAuth 2.0, User Registration, and JWT Authentication");

    // Load unified configuration
    let config = Config::load().context("Failed to load configuration")?;

    // Validate configuration
    config.validate().context("Invalid configuration")?;

    let config = Arc::new(config);

    // Initialize signing keys for JWT (required for RS256 + JWKS)
    if let Err(e) = initialize_keys().await {
        return Err(anyhow::anyhow!(
            "Failed to initialize JWT signing keys: {}. Set RSA key via RSA_PRIVATE_KEY or RSA_PRIVATE_KEY_PATH",
            e
        )
        .into());
    }

    // SECURITY: Initialize authentication state with JWT secret from configuration
    // Fall back to JWT_SECRET environment variable for backward compatibility (deprecated)
    let jwt_secret = if config.jwt.secret == "change-me-in-production" {
        // Only fall back to env var if using default placeholder
        if let Ok(env_secret) = std::env::var("JWT_SECRET") {
            warn!("⚠️  Using deprecated JWT_SECRET environment variable. Please set Config.jwt.secret instead.");
            env_secret
        } else {
            return Err(anyhow::anyhow!(
                "JWT secret must be configured. Either:\n\
                1. Set Config.jwt.secret in your configuration file, or\n\
                2. Set JWT_SECRET environment variable (deprecated)\n\
                Generate a secure secret with: openssl rand -hex 32"
            ).into());
        }
    } else {
        config.jwt.secret.clone()
    };

    // Validate JWT secret strength
    if jwt_secret.len() < 32 {
        return Err(
            anyhow::anyhow!("JWT secret must be at least 32 characters long for security").into(),
        );
    }

    info!("✅ JWKS key management initialized successfully");

    let auth_state = AuthState::new(jwt_secret);

    // Initialize threat detection
    let threat_detector = ThreatDetector::new();
    threat_detector.initialize_default_patterns().await;

    // Initialize threat detection middleware
    initialize_threat_detection().await;

    // SECURITY: Initialize test mode security checks
    auth_service::test_mode_security::initialize_test_mode_security();

    // Start rate limiter cleanup task
    start_rate_limiter_cleanup();

    // Background task to ensure signing key is rotated when needed
    tokio::spawn(async move {
        use std::time::Duration;
        loop {
            let _ = auth_service::infrastructure::crypto::keys::maybe_rotate().await;
            tokio::time::sleep(Duration::from_secs(300)).await; // check every 5 minutes
        }
    });

    // Use centralized router with Extension state and config
    let app: axum::Router = auth_service::app::router::create_router_with_auth_state_and_config(auth_state, Some(config.clone()));

    let addr = config.server.bind_addr;
    info!("🌐 Auth service listening on {}", addr);
    info!("📋 Available endpoints:");
    info!("   • Health: GET /health");
    info!("   • Status: GET /api/v1/status");
    info!("   • Register: POST /api/v1/auth/register");
    info!("   • Login: POST /api/v1/auth/login");
    info!("   • User Info: GET /api/v1/auth/me");
    info!("   • JWKS: GET /.well-known/jwks.json");
    info!("   • JWKS (alt): GET /jwks.json");
    info!("   • OAuth Authorize: GET /oauth/authorize");
    info!("   • OAuth Token: POST /oauth/token");
    info!("   • Service Identity: POST /service/identity/register");
    info!("   • JIT Token: POST /token/jit");
    info!("   • Threat Metrics: GET /security/threats/metrics");
    #[cfg(feature = "metrics")]
    info!("   • Prometheus Metrics: GET /metrics");
    info!("🔑 Use registration endpoint to create users: POST /api/v1/auth/register");
    info!("🔑 Use OAuth client registration for applications");

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| {
            error!("❌ Server error: {}", e);
            e.into()
        })
}
// CSRF middleware moved to auth_service::middleware::csrf
