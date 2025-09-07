//! Application Builder
//!
//! This module provides a builder pattern for constructing the application
//! with all its services, middleware, and configuration.

use crate::application::auth::auth_api::AuthState;
use crate::config::Config;

/// Application builder for constructing the auth service
pub struct AppBuilder {
    config: Option<Config>,
    auth_state: Option<AuthState>,
}

impl AppBuilder {
    /// Create a new application builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: None,
            auth_state: None,
        }
    }

    /// Set the application configuration
    #[must_use]
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the authentication state
    #[must_use]
    pub fn with_auth_state(mut self, auth_state: AuthState) -> Self {
        self.auth_state = Some(auth_state);
        self
    }

    /// Build the application with all components
    ///
    /// This method orchestrates the creation of all application components
    /// including services, middleware, and routing.
    ///
    /// # Panics
    ///
    /// Panics if required components (config, auth_state) are not provided.
    #[must_use]
    pub fn build(self) -> AuthService {
        let config = self.config.expect("Configuration must be provided");
        let auth_state = self.auth_state.expect("Authentication state must be provided");

        AuthService { config, auth_state }
    }
}

impl Default for AppBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The main authentication service
pub struct AuthService {
    pub config: Config,
    pub auth_state: AuthState,
}

impl AuthService {
    /// Start the authentication service
    ///
    /// This method starts the HTTP server and begins accepting requests.
    /// It handles graceful shutdown and error reporting.
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to start or encounters a fatal error.
    pub async fn start(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = self.config.server.bind_addr;

        tracing::info!("🌐 Auth service listening on {}", addr);
        tracing::info!("📋 Available endpoints:");
        tracing::info!("   • Health: GET /health");
        tracing::info!("   • Status: GET /api/v1/status");
        tracing::info!("   • Register: POST /api/v1/auth/register");
        tracing::info!("   • Login: POST /api/v1/auth/login");
        tracing::info!("   • User Info: GET /api/v1/auth/me");

        let app = crate::app::router::create_router_with_auth_state(self.auth_state);
        let listener = tokio::net::TcpListener::bind(&addr).await?;

        axum::serve(listener, app.into_make_service())
            .await
            .map_err(|e| {
                tracing::error!("❌ Server error: {}", e);
                e.into()
            })
    }
}
