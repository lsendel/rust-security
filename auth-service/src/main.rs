//! Auth Service Main Entry Point
//!
//! Enterprise-grade authentication service with comprehensive security features.
//! This is a clean, modular entry point that delegates to the bootstrap system.

#![allow(clippy::multiple_crate_versions)]

use tracing::error;

mod config;

use auth_service::bootstrap::{AppBuilder, ConfigLoader, ServiceInitializer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging based on environment
    initialize_logging()?;

    // Load and validate configuration
    let config = ConfigLoader::load()?;

    // Initialize all services
    let app_state = ServiceInitializer::initialize_services(&config).await?;

    // Build and start the application
    let auth_service = AppBuilder::new()
        .with_config(config)
        .with_auth_state(app_state)
        .build();

    // Start the server
    auth_service.start().await.map_err(|e| {
        error!("❌ Server error: {}", e);
        e
    })
}

/// Initialize logging based on environment
fn initialize_logging() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    Ok(())
}
