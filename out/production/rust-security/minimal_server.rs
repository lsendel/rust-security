//! Minimal OAuth 2.0 server example
//!
//! This example shows how to create the simplest possible OAuth server
//! with just a few lines of code.
//!
//! Run with: cargo run --example minimal_server --features jwt

use auth_core::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging (simplified - no external deps)
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    println!("🚀 Starting minimal OAuth 2.0 server...");

    // Create a minimal server with one client
    let server = AuthServer::minimal()
        .with_client("demo-client", "demo-secret")
        .with_client("service-a", "super-secret-key-a")
        .with_rate_limit(60) // 60 requests per minute
        .build();

    println!("\n📋 Available endpoints:");
    println!("  Health check:  http://localhost:8080/health");
    println!("  Token endpoint: http://localhost:8080/oauth/token");
    println!("  Introspection: http://localhost:8080/oauth/introspect");

    println!("\n🔑 Test with curl:");
    println!(r#"  curl -X POST http://localhost:8080/oauth/token \"#);
    println!(r#"       -H "Content-Type: application/x-www-form-urlencoded" \"#);
    println!(
        r#"       -d "grant_type=client_credentials&client_id=demo-client&client_secret=demo-secret""#
    );

    // Start the server
    server.serve("0.0.0.0:8080").await
}
