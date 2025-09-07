//! Application State
//!
//! This module defines the shared application state that is passed
//! between handlers and services throughout the application.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Application state shared across handlers
///
/// This structure contains all the shared services and state required by the authentication
/// service handlers. It's designed to be cloned cheaply using `Arc` internally for all
/// heavy resources.
///
/// # Thread Safety
///
/// All fields use thread-safe types (`Arc`, `RwLock`) allowing the state to be safely
/// shared across multiple request handlers running concurrently.
///
/// # Example
///
/// ```rust
/// use auth_service::application::state::AppState;
/// use std::sync::Arc;
///
/// // AppState is typically created by the application initialization
/// // and passed to the router as state
/// let state = AppState::new().await?;
/// let router = axum::Router::new()
///     .with_state(state);
/// ```
#[derive(Clone)]
pub struct AppState {
    #[cfg(feature = "redis-sessions")]
    pub store: Arc<crate::infrastructure::storage::store::hybrid::HybridStore>,
    #[cfg(feature = "api-keys")]
    pub api_key_store: Arc<crate::application::api::api_key_store::ApiKeyStore>,
    pub session_store: Arc<crate::infrastructure::storage::session::store::RedisSessionStore>,
    pub token_store: Arc<std::sync::RwLock<HashMap<String, common::TokenRecord>>>,
    pub client_credentials: Arc<std::sync::RwLock<HashMap<String, String>>>,
    pub allowed_scopes: Arc<std::sync::RwLock<HashSet<String>>>,
    pub authorization_codes: Arc<std::sync::RwLock<HashMap<String, String>>>,
    pub policy_cache: Arc<crate::infrastructure::storage::cache::policy_cache::PolicyCache>,
    pub backpressure_state: Arc<std::sync::RwLock<bool>>,
    // TODO: Fix JwksManager initialization
    // #[cfg(feature = "crypto")]
    // pub jwks_manager: Arc<crate::infrastructure::crypto::jwks_rotation::JwksManager>,
}

impl AppState {
    /// Create a new application state instance
    ///
    /// This method initializes all the required services and stores
    /// with their default configurations.
    #[must_use]
    pub fn new() -> Self {
        // Initialize session store
        let session_store = Arc::new(
            crate::infrastructure::storage::session::store::RedisSessionStore::new(
                // TODO: Load from configuration
                Some("redis://localhost:6379".to_string()),
            ),
        );

        // Initialize token store
        let token_store = Arc::new(std::sync::RwLock::new(HashMap::new()));

        // Initialize client credentials store
        let client_credentials = Arc::new(std::sync::RwLock::new(HashMap::new()));

        // Initialize allowed scopes
        let allowed_scopes = Arc::new(std::sync::RwLock::new(HashSet::new()));

        // Initialize authorization codes store
        let authorization_codes = Arc::new(std::sync::RwLock::new(HashMap::new()));

        // Initialize policy cache
        // TODO: Create proper PolicyCacheConfig
        let policy_cache = Arc::new(
            crate::infrastructure::storage::cache::policy_cache::PolicyCache::new(
                crate::infrastructure::storage::cache::policy_cache::PolicyCacheConfig::default(),
            ),
        );

        // Initialize backpressure state
        let backpressure_state = Arc::new(std::sync::RwLock::new(false));

        Self {
            #[cfg(feature = "redis-sessions")]
            store: Arc::new(crate::infrastructure::storage::store::hybrid::HybridStore::new()),
            #[cfg(feature = "api-keys")]
            api_key_store: Arc::new(crate::application::api::api_key_store::ApiKeyStore::new()),
            session_store,
            token_store,
            client_credentials,
            allowed_scopes,
            authorization_codes,
            policy_cache,
            backpressure_state,
            // TODO: Fix JwksManager initialization - requires async context and proper config
            // #[cfg(feature = "crypto")]
            // jwks_manager: Arc::new(...),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
