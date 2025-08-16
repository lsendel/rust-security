use axum_integration_example::create_app;
use std::env;
use std::net::SocketAddr;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for structured logging
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    // Get bind address from environment or use default
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let addr: SocketAddr = bind_addr.parse().map_err(|e| {
        eprintln!("Invalid bind address '{}': {}", bind_addr, e);
        e
    })?;

    // Create the application using our factory function
    let app = create_app();

    tracing::info!("Starting Axum integration example server");
    tracing::info!("Listening on http://{}", addr);
    tracing::info!("Available endpoints:");
    tracing::info!("  GET  /users     - List all users");
    tracing::info!("  POST /users     - Create a new user");
    tracing::info!("  GET  /users/:id - Get user by ID");

    // Create TCP listener
    let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
        eprintln!("Failed to bind to address {}: {}", addr, e);
        e
    })?;

    tracing::info!("Server successfully bound to {}", addr);

    // Start the server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| {
            eprintln!("Server error: {}", e);
            e
        })?;

    tracing::info!("Server shutdown complete");
    Ok(())
}

/// Handle graceful shutdown signals
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown");
        },
    }
}
