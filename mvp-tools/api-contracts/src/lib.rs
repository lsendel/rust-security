#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, future_incompatible)]
//! # API Contracts and Versioning Framework
//!
//! This crate provides comprehensive API versioning, service contracts, and
//! context propagation for the Rust Security Platform.
//!
//! ## Features
//!
//! - **API Versioning**: Semantic versioning with deprecation policies
//! - **Service Contracts**: Clear interface definitions between services
//! - **Context Propagation**: Distributed tracing and request context
//! - **OpenAPI Documentation**: Auto-generated API specifications
//! - **Backward Compatibility**: Migration strategies and testing

pub mod context;
pub mod contracts;
pub mod documentation;
pub mod errors;
pub mod middleware;
pub mod types;
pub mod versioning;

pub use context::{
    ContextPropagation, ContextPropagationConfig, RequestContext, ServiceContext, UserContext,
};
pub use contracts::{AuthServiceContract, PolicyServiceContract, ServiceContract};
pub use errors::{ApiError, ContractError, VersioningError};
pub use middleware::{ApiVersioningMiddleware, ContextPropagationMiddleware};
pub use types::*;
pub use versioning::{ApiVersion, DeprecationPolicy, VersionedEndpoint};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Global API configuration for the platform
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Current API version
    pub current_version: ApiVersion,
    /// Supported API versions
    pub supported_versions: Vec<ApiVersion>,
    /// Deprecated versions with sunset dates
    pub deprecated_versions: HashMap<ApiVersion, chrono::DateTime<chrono::Utc>>,
    /// Service endpoints
    pub service_endpoints: HashMap<String, String>,
    /// Context propagation settings
    pub context_propagation: ContextPropagationConfig,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            current_version: ApiVersion::new(1, 0, 0),
            supported_versions: vec![ApiVersion::new(1, 0, 0), ApiVersion::new(1, 1, 0)],
            deprecated_versions: HashMap::new(),
            service_endpoints: HashMap::from([
                (
                    "auth-service".to_string(),
                    "http://auth-service:8080".to_string(),
                ),
                (
                    "policy-service".to_string(),
                    "http://policy-service:8081".to_string(),
                ),
            ]),
            context_propagation: ContextPropagationConfig::default(),
        }
    }
}

/// Initialize the API contracts framework
pub async fn init_api_framework(config: ApiConfig) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Initializing API contracts framework");

    // Validate configuration
    validate_api_config(&config)?;

    // Initialize context propagation
    context::init_context_propagation(&config.context_propagation)?;

    // Initialize versioning
    versioning::init_versioning(&config)?;

    tracing::info!("API contracts framework initialized successfully");
    Ok(())
}

/// Validate API configuration
fn validate_api_config(config: &ApiConfig) -> Result<(), ContractError> {
    // Ensure current version is in supported versions
    if !config.supported_versions.contains(&config.current_version) {
        return Err(ContractError::InvalidConfiguration(
            "Current version not in supported versions".to_string(),
        ));
    }

    // Ensure service endpoints are valid URLs
    for (service, endpoint) in &config.service_endpoints {
        if url::Url::parse(endpoint).is_err() {
            return Err(ContractError::InvalidConfiguration(format!(
                "Invalid endpoint URL for service {}: {}",
                service, endpoint
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ApiConfig::default();
        assert_eq!(config.current_version, ApiVersion::new(1, 0, 0));
        assert!(config
            .supported_versions
            .contains(&ApiVersion::new(1, 0, 0)));
    }

    #[test]
    fn test_config_validation() {
        let mut config = ApiConfig::default();
        config
            .service_endpoints
            .insert("invalid".to_string(), "not-a-url".to_string());

        assert!(validate_api_config(&config).is_err());
    }
}
