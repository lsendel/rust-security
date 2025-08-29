// Explicitly acknowledge unused dependencies for future functionality
use cedar_policy as _;
use cedar_policy_core as _;
use chrono as _;
use once_cell as _;
use prometheus as _;
use serde as _;
use serde_json as _;
use thiserror as _;
use tower_http as _;

// Dev dependencies used in tests (acknowledged to prevent clippy warnings)
#[cfg(test)]
use futures as _;
#[cfg(test)]
use reqwest as _;
#[cfg(test)]
use tempfile as _;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use policy_service::{app, load_policies_and_entities, ApiDoc};

mod config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = load_policies_and_entities()
        .map_err(|e| anyhow::anyhow!(e))
        .context("Failed to load policies and entities")?;
    let openapi = ApiDoc::openapi();

    let app = app(state).merge(SwaggerUi::new("/swagger-ui").url("/openapi.json", openapi.clone()));

    let cfg = config::AppConfig::from_env()?;
    let listener = TcpListener::bind(cfg.bind_addr).await?;
    tracing::info!("policy-service listening on {}", cfg.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
