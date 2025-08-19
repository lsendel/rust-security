use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntegrationError {
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("API error: {0}")]
    Api(String),
    #[error("Authentication error: {0}")]
    Authentication(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, IntegrationError>;
