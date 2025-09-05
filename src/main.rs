use axum::{routing::get, Router};
use rust_security::{
    config::threat_intel::ThreatIntelConfig,
    integration::{service::ThreatAuthService, threat_auth::configure_threat_auth_integration},
    metrics::threat_intel::ThreatIntelMetrics,
};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::init();

    let config = ThreatIntelConfig::from_env();
    
    if !config.enabled {
        println!("Threat intelligence disabled, starting without protection");
        return start_basic_server().await;
    }

    let threat_service = ThreatAuthService::new(config.feed_urls.clone());
    threat_service.start().await;

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_handler));

    let protected_app = configure_threat_auth_integration(app, threat_service.intel_service);
    
    let app = protected_app.layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("Server running on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn start_basic_server() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

async fn metrics_handler() -> String {
    use prometheus::{Encoder, TextEncoder};
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    encoder.encode_to_string(&metric_families).unwrap_or_default()
}
