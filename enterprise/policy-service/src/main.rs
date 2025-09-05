//! MVP Policy Service Binary

use policy_service::{load_policies_and_entities, app};
use std::net::SocketAddr;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for MVP
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    // Load environment variables
    dotenvy::dotenv().ok();

    tracing::info!("Starting MVP Policy Service...");

    // Load policies and entities
    let app_state = load_policies_and_entities()
        .map_err(|e| {
            tracing::error!("Failed to load policies and entities: {}", e);
            e
        })?;

    tracing::info!("Policies and entities loaded successfully");

    // Create application
    let app = app(app_state);

    // Get bind address from environment or use default
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3001".to_string())
        .parse::<u16>()
        .unwrap_or(3001);
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    
    tracing::info!("MVP Policy Service listening on {}", addr);
    
    // Start the server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}