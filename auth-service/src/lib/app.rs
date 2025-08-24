//! Application module for auth-service
//! 
//! This module contains the main application setup and configuration.

use std::sync::Arc;
use tokio::net::TcpListener;
use axum::Router;
use tracing::{info, error};

/// Main application structure
pub struct App {
    pub router: Router,
    pub config: Arc<crate::config::AppConfig>,
}

impl App {
    /// Create a new application instance
    pub fn new(config: Arc<crate::config::AppConfig>) -> Self {
        let router = crate::lib::api::create_router();
        
        Self {
            router,
            config,
        }
    }

    /// Start the application server
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("{}:{}", 
            self.config.server.bind_address, 
            self.config.server.port
        );
        
        info!("Starting auth-service on {}", addr);
        
        let listener = TcpListener::bind(&addr).await?;
        
        info!("Auth service listening on {}", addr);
        
        axum::serve(listener, self.router)
            .await
            .map_err(|e| {
                error!("Server error: {}", e);
                e.into()
            })
    }
}
