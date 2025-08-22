// Explicitly acknowledge unused dependencies for future functionality
use cedar_policy as _;
use cedar_policy_core as _;
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

use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;

use policy_service::{app, load_policies_and_entities, ApiDoc};

mod config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = load_policies_and_entities()?;
    let openapi = ApiDoc::openapi();

    let app = app(state).route(
        "/openapi.json",
        axum::routing::get(move || async { axum::Json(openapi) }),
    );

    let cfg = config::AppConfig::from_env()?;
    let listener = TcpListener::bind(cfg.bind_addr).await?;
    tracing::info!("policy-service listening on {}", cfg.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
