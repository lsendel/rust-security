//! Application module for auth-service
//!
//! This module contains the main application setup and configuration.

use axum::Router;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

/// Main application structure
pub struct App {
    pub router: Router,
    pub config: Arc<crate::config::Config>,
}

impl App {
    /// Create a new application instance
    #[must_use]
    pub fn new(config: Arc<crate::config::Config>) -> Self {
        let router = crate::lib::api::create_router();

        Self { router, config }
    }

    /// Start the application server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Fix server config structure - using available fields
        let addr = self.config.server.bind_addr;

        info!("Starting auth-service on {}", addr);

        let listener = TcpListener::bind(&addr).await?;

        info!("Auth service listening on {}", addr);

        axum::serve(listener, self.router).await.map_err(|e| {
            error!("Server error: {}", e);
            e.into()
        })
    }
}
