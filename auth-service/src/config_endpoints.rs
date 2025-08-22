//! Configuration management HTTP endpoints.
//!
//! Provides admin endpoints for configuration management including reload,
//! status monitoring, and rollback capabilities.

use crate::config_reload::{
    ConfigReloadManager, ConfigReloadRequest, ConfigReloadResponse, ConfigStatus,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};
use validator::Validate;

/// Configuration management state
#[derive(Clone)]
pub struct ConfigState {
    pub reload_manager: Arc<ConfigReloadManager>,
}

/// Configuration reload endpoint
///
/// Triggers manual configuration reload. Requires admin authentication.
///
/// # Security
/// This endpoint should be protected by admin middleware and request signing.
pub async fn reload_config(
    State(state): State<ConfigState>,
    Json(_request): Json<ConfigReloadRequest>,
) -> Result<Json<ConfigReloadResponse>, StatusCode> {
    info!("Configuration reload requested via HTTP endpoint");

    // Perform the reload
    match state.reload_manager.trigger_reload().await {
        Ok(()) => {
            let version = state.reload_manager.get_version().await;
            info!("Configuration reload successful (version: {})", version);

            Ok(Json(ConfigReloadResponse {
                success: true,
                version,
                changes: vec!["Configuration reloaded successfully".to_string()],
                errors: None,
                requires_restart: false, // TODO: Detect if restart is required
            }))
        }
        Err(e) => {
            error!("Configuration reload failed: {}", e);

            Ok(Json(ConfigReloadResponse {
                success: false,
                version: state.reload_manager.get_version().await,
                changes: vec![],
                errors: Some(vec![e.to_string()]),
                requires_restart: false,
            }))
        }
    }
}

/// Configuration status endpoint
///
/// Returns current configuration status and version information.
pub async fn config_status(
    State(state): State<ConfigState>,
) -> Result<Json<ConfigStatus>, StatusCode> {
    let version = state.reload_manager.get_version().await;
    let _config = state.reload_manager.get_config().await;

    // Determine configuration source
    let source = std::env::var("CONFIG_FILE")
        .map(|_| "file".to_string())
        .unwrap_or_else(|_| "environment".to_string());

    Ok(Json(ConfigStatus {
        version,
        last_reload: Some(chrono::Utc::now()), // TODO: Track actual last reload time
        source,
        validation_status: "valid".to_string(), // TODO: Implement validation status tracking
        requires_restart: false,                // TODO: Implement restart requirement detection
    }))
}

/// Configuration rollback endpoint
///
/// Rolls back to the previous configuration version.
pub async fn rollback_config(
    State(state): State<ConfigState>,
) -> Result<Json<ConfigReloadResponse>, StatusCode> {
    info!("Configuration rollback requested via HTTP endpoint");

    match state.reload_manager.rollback().await {
        Ok(()) => {
            let version = state.reload_manager.get_version().await;
            info!("Configuration rollback successful (version: {})", version);

            Ok(Json(ConfigReloadResponse {
                success: true,
                version,
                changes: vec!["Configuration rolled back successfully".to_string()],
                errors: None,
                requires_restart: false,
            }))
        }
        Err(e) => {
            error!("Configuration rollback failed: {}", e);

            Ok(Json(ConfigReloadResponse {
                success: false,
                version: state.reload_manager.get_version().await,
                changes: vec![],
                errors: Some(vec![e.to_string()]),
                requires_restart: false,
            }))
        }
    }
}

/// Configuration validation endpoint
///
/// Validates a configuration without applying it.
pub async fn validate_config(
    State(_state): State<ConfigState>,
    Json(config): Json<serde_json::Value>,
) -> Result<Json<ConfigValidationResponse>, StatusCode> {
    info!("Configuration validation requested via HTTP endpoint");

    // Parse the configuration
    let parsed_config: crate::config::AppConfig = match serde_json::from_value(config) {
        Ok(config) => config,
        Err(e) => {
            return Ok(Json(ConfigValidationResponse {
                valid: false,
                errors: vec![format!("Configuration parsing failed: {}", e)],
                warnings: vec![],
            }));
        }
    };

    // Validate the configuration (this is a simplified validation)
    // In a real implementation, we would use the ConfigReloadManager's validation
    match parsed_config.validate() {
        Ok(()) => Ok(Json(ConfigValidationResponse {
            valid: true,
            errors: vec![],
            warnings: vec![],
        })),
        Err(validation_errors) => {
            let errors = validation_errors
                .field_errors()
                .iter()
                .flat_map(|(field, errors)| {
                    errors
                        .iter()
                        .map(move |error| format!("Field '{}': {}", field, error.code))
                })
                .collect();

            Ok(Json(ConfigValidationResponse {
                valid: false,
                errors,
                warnings: vec![],
            }))
        }
    }
}

/// Configuration schema endpoint
///
/// Returns the JSON schema for the configuration format.
pub async fn config_schema() -> Result<Json<serde_json::Value>, StatusCode> {
    // TODO: Generate actual JSON schema from the AppConfig struct
    // For now, return a placeholder schema
    let schema = serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Auth Service Configuration",
        "type": "object",
        "description": "Configuration schema for the Auth Service",
        "properties": {
            "bind_addr": {
                "type": "string",
                "description": "Server bind address"
            },
            "redis_url": {
                "type": "string",
                "description": "Redis connection URL"
            },
            "security": {
                "type": "object",
                "description": "Security configuration"
            },
            "rate_limiting": {
                "type": "object",
                "description": "Rate limiting configuration"
            }
        },
        "required": ["bind_addr"]
    });

    Ok(Json(schema))
}

/// Configuration validation response
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigValidationResponse {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Create configuration management router
///
/// Sets up routes for configuration management endpoints.
/// These should be mounted under an admin-protected path.
pub fn config_router(reload_manager: Arc<ConfigReloadManager>) -> Router {
    let state = ConfigState { reload_manager };

    Router::new()
        .route("/reload", post(reload_config))
        .route("/status", get(config_status))
        .route("/rollback", post(rollback_config))
        .route("/validate", post(validate_config))
        .route("/schema", get(config_schema))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AppConfig, FeatureFlags, MonitoringConfig, OAuthConfig, OidcProviders, RateLimitConfig,
        ScimConfig, SecurityConfig, StoreBackend, StoreConfig,
    };
    use axum::body::Body;
    use axum::http::{Method, Request};
    use std::collections::HashMap;
    use tower::util::ServiceExt;

    fn create_test_config() -> AppConfig {
        AppConfig {
            bind_addr: "127.0.0.1:8080".to_string(),
            redis_url: Some("redis://localhost:6379".to_string()),
            oidc_providers: OidcProviders {
                google: None,
                microsoft: None,
                github: None,
            },
            security: SecurityConfig {
                jwt_access_token_ttl_seconds: 3600,
                jwt_refresh_token_ttl_seconds: 86400,
                rsa_key_size: 2048,
                request_signing_secret: None,
                request_timestamp_window_seconds: 300,
                session_ttl_seconds: 3600,
                allowed_origins: vec!["http://localhost:3000".to_string()],
                max_request_body_size: 1048576,
            },
            rate_limiting: RateLimitConfig {
                requests_per_minute_global: 1000,
                requests_per_minute_per_ip: 100,
                oauth_requests_per_minute: 60,
                admin_requests_per_minute: 10,
                enable_banlist: false,
                enable_allowlist: false,
                banlist_ips: vec![],
                allowlist_ips: vec![],
            },
            monitoring: MonitoringConfig {
                prometheus_metrics_enabled: true,
                opentelemetry_enabled: true,
                jaeger_endpoint: None,
                metrics_scrape_interval_seconds: 30,
                security_monitoring_enabled: true,
                audit_logging_enabled: true,
            },
            features: FeatureFlags {
                soar_integration: false,
                google_oidc: true,
                microsoft_oidc: true,
                github_oidc: true,
                webauthn: true,
                scim_v2: true,
                advanced_mfa: true,
                threat_detection: false,
                policy_engine: true,
            },
            oauth: OAuthConfig {
                authorization_code_ttl_seconds: 600,
                max_authorization_codes_per_client: 10,
                enforce_pkce: true,
                require_state_parameter: true,
                strict_redirect_validation: true,
                allowed_redirect_schemes: vec!["https".to_string(), "http".to_string()],
            },
            scim: ScimConfig {
                enabled: true,
                max_filter_length: 100,
                max_results_per_page: 100,
                default_results_per_page: 20,
            },
            store: StoreConfig {
                backend: StoreBackend::Hybrid,
                database_url: None,
            },
            client_credentials: HashMap::from([("client1".to_string(), "secret1".to_string())]),
            allowed_scopes: vec!["read".to_string(), "write".to_string()],
            jwt_secret: "test-secret".to_string(),
            token_expiry_seconds: 3600,
            rate_limit_requests_per_minute: 60,
        }
    }

    #[tokio::test]
    async fn test_config_status_endpoint() {
        let config = create_test_config();
        let (reload_manager, _receiver) = ConfigReloadManager::new(config, None);
        let router = config_router(Arc::new(reload_manager));

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_config_schema_endpoint() {
        let config = create_test_config();
        let (reload_manager, _receiver) = ConfigReloadManager::new(config, None);
        let router = config_router(Arc::new(reload_manager));

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/schema")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
