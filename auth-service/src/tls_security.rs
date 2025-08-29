//! Basic TLS Security Configuration (MVP Level)
//!
//! Simplified TLS configuration for basic secure connections.

use crate::error_handling::{SecurityError, SecurityResult};
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;
use tracing::info;

/// Basic TLS configuration for MVP
#[derive(Debug, Clone)]
pub struct TlsSecurityConfig {
    pub enabled: bool,
}

impl Default for TlsSecurityConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Create basic TLS client configuration with safe defaults
///
/// # Errors
///
/// Returns an error if TLS configuration creation fails or root certificates cannot be loaded
pub fn create_secure_client_config(
    _config: &TlsSecurityConfig,
) -> SecurityResult<Arc<ClientConfig>> {
    info!("Creating basic TLS client configuration");

    let client_config = ClientConfig::builder()
        .with_root_certificates({
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            root_store
        })
        .with_no_client_auth();

    info!("TLS client configuration created successfully");
    Ok(Arc::new(client_config))
}

/// Create basic TLS server configuration (stub for MVP)
///
/// # Errors
///
/// Always returns an error as TLS server configuration is not implemented in MVP
pub fn create_secure_server_config() -> SecurityResult<Arc<ServerConfig>> {
    info!("TLS server configuration not implemented in MVP");
    Err(SecurityError::Configuration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_config_creation() {
        let config = TlsSecurityConfig::default();
        assert!(config.enabled);

        let client_config = create_secure_client_config(&config);
        assert!(client_config.is_ok());
    }

    #[test]
    fn test_server_config_not_implemented() {
        let result = create_secure_server_config();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SecurityError::Configuration));
    }

    #[test]
    fn test_default_config() {
        let config = TlsSecurityConfig::default();
        assert!(config.enabled);
    }
}
