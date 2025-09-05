//! Shared test infrastructure to reduce integration test execution time
//! 
//! This module provides a singleton test server that can be shared across
//! multiple integration tests, dramatically reducing test execution time.

use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::storage::session::store::RedisSessionStore;
use auth_service::storage::store::hybrid::HybridStore;
use auth_service::{api_key_store::ApiKeyStore, app, AppState};
use common::TokenRecord;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Global shared test server instance
static SHARED_TEST_SERVER: OnceLock<Arc<SharedTestServer>> = OnceLock::new();

/// Shared test server that can be reused across multiple tests
pub struct SharedTestServer {
    pub base_url: String,
    pub client: Client,
    /// Mutex to ensure test isolation when needed
    pub test_mutex: Mutex<()>,
}

impl SharedTestServer {
    /// Get or create the shared test server instance
    /// This function is thread-safe and will only create one instance
    pub async fn instance() -> Arc<Self> {
        // Check if we already have an instance
        if let Some(server) = SHARED_TEST_SERVER.get() {
            return server.clone();
        }
        
        // Create the server instance
        let server = Arc::new(Self::create_server().await);
        
        // Try to store it (this might fail if another thread created one first)
        if let Err(_existing) = SHARED_TEST_SERVER.set(server.clone()) {
            // Another thread beat us to it, use their instance
            SHARED_TEST_SERVER.get().unwrap().clone()
        } else {
            // We successfully stored our instance
            server
        }
    }
    
    /// Create a new shared test server (called once)
    async fn create_server() -> Self {
        // Set test environment variables once
        std::env::set_var("TEST_MODE", "1");
        std::env::remove_var("POLICY_ENFORCEMENT");
        std::env::set_var("DISABLE_RATE_LIMIT", "1");
        std::env::set_var("EXTERNAL_BASE_URL", "http://localhost:8080");
        std::env::set_var("REQUEST_SIGNING_SECRET", "test_secret");
        std::env::set_var(
            "CLIENT_CREDENTIALS",
            "test_client:test_secret_12345;admin_client:admin_secret_67890;read_client:read_secret;write_client:write_secret",
        );
        std::env::set_var("GOOGLE_CLIENT_ID", "test-client-id");
        std::env::set_var("GOOGLE_CLIENT_SECRET", "test-client-secret");
        std::env::set_var("GOOGLE_REDIRECT_URI", "http://localhost:8080/oauth/google/callback");

        // Bind to available port
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Create shared application state
        let mut client_credentials = HashMap::new();
        client_credentials.insert("test_client".to_string(), "test_secret_12345".to_string());
        client_credentials.insert("admin_client".to_string(), "admin_secret_67890".to_string());
        client_credentials.insert("read_client".to_string(), "read_secret".to_string());
        client_credentials.insert("write_client".to_string(), "write_secret".to_string());

        // Create policy cache
        let policy_cache_config =
            auth_service::storage::cache::policy_cache::PolicyCacheConfig::default();
        let policy_cache = Arc::new(
            auth_service::storage::cache::policy_cache::PolicyCache::new(policy_cache_config),
        );

        // Create expensive resources once
        let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();
        let store = Arc::new(HybridStore::new().await);
        let session_store = Arc::new(RedisSessionStore::new(None));
        let jwks_manager = Arc::new(
            JwksManager::new(
                auth_service::jwks_rotation::KeyRotationConfig::default(),
                Arc::new(InMemoryKeyStorage::new()),
            )
            .await
            .unwrap(),
        );

        let app_state = AppState {
            store,
            session_store,
            token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
            client_credentials: Arc::new(std::sync::RwLock::new(client_credentials)),
            allowed_scopes: Arc::new(std::sync::RwLock::new(HashSet::from([
                "read".to_string(),
                "write".to_string(),
                "admin".to_string(),
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ]))),
            authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
            policy_cache,
            backpressure_state: Arc::new(std::sync::RwLock::new(false)),
            api_key_store: Arc::new(api_key_store),
            jwks_manager,
        };

        // Start the server
        let app = app(app_state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Wait for server to be ready
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        Self {
            base_url: format!("http://{addr}"),
            client: Client::new(),
            test_mutex: Mutex::new(()),
        }
    }

    /// Get a client for making HTTP requests
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get the base URL of the test server
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get an exclusive lock for tests that need isolation
    /// Use this when a test modifies global state
    pub async fn exclusive_lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.test_mutex.lock().await
    }

    /// Reset test state between tests (when using exclusive lock)
    pub async fn reset_test_state(&self) {
        // Clear any test-specific state that might interfere between tests
        // This is lighter than recreating the entire server
        
        // Example: Clear authorization codes
        // Note: You might want to expose methods on AppState for this
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

/// Test helper functions that work with the shared server
pub struct SharedTestHelpers;

impl SharedTestHelpers {
    /// Get a valid access token using the shared server
    pub async fn get_access_token() -> String {
        let server = SharedTestServer::instance().await;
        Self::get_access_token_with_client(&server.client, &server.base_url, None).await
    }

    /// Get access token with specific scope
    pub async fn get_access_token_with_scope(scope: &str) -> String {
        let server = SharedTestServer::instance().await;
        Self::get_access_token_with_client(&server.client, &server.base_url, Some(scope)).await
    }

    /// Get admin token
    pub async fn get_admin_token() -> String {
        Self::get_access_token_with_scope("admin").await
    }

    /// Get access token with specific client and scope
    async fn get_access_token_with_client(
        client: &Client,
        base_url: &str,
        scope: Option<&str>,
    ) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let mut body = "grant_type=client_credentials".to_string();
        if let Some(s) = scope {
            use std::fmt::Write as _;
            let _ = write!(body, "&scope={s}");
        }

        let credentials = "test_client:test_secret_12345";
        let encoded = STANDARD.encode(credentials.as_bytes());
        let auth_header = format!("Basic {encoded}");

        let response = client
            .post(format!("{base_url}/oauth/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", auth_header)
            .body(body)
            .send()
            .await
            .unwrap();

        let token_response: serde_json::Value = response.json().await.unwrap();
        token_response["access_token"].as_str().unwrap().to_string()
    }

    /// Create HTTP Basic Auth header
    pub fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let credentials = format!("{client_id}:{client_secret}");
        let encoded = STANDARD.encode(credentials.as_bytes());
        format!("Basic {encoded}")
    }

    /// Wait for async operations to complete
    pub async fn wait_for_async() {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

/// Macro to create a test that uses the shared server
#[macro_export]
macro_rules! shared_integration_test {
    ($test_name:ident, $test_body:block) => {
        #[tokio::test]
        async fn $test_name() {
            use $crate::shared_test_infrastructure::{SharedTestServer, SharedTestHelpers};
            
            let _server = SharedTestServer::instance().await;
            
            $test_body
        }
    };
}

/// Macro for tests that need exclusive access (modify global state)
#[macro_export]
macro_rules! exclusive_integration_test {
    ($test_name:ident, $test_body:block) => {
        #[tokio::test]
        async fn $test_name() {
            use $crate::shared_test_infrastructure::{SharedTestServer, SharedTestHelpers};
            
            let server = SharedTestServer::instance().await;
            let _lock = server.exclusive_lock().await;
            server.reset_test_state().await;
            
            $test_body
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shared_server_creation() {
        let server1 = SharedTestServer::instance().await;
        let server2 = SharedTestServer::instance().await;
        
        // Should be the same instance
        assert_eq!(server1.base_url(), server2.base_url());
        
        // Should be able to make requests
        let response = server1
            .client()
            .get(&format!("{}/health", server1.base_url()))
            .send()
            .await
            .unwrap();
        
        assert!(response.status().is_success());
    }

    #[tokio::test]
    async fn test_token_generation() {
        let token = SharedTestHelpers::get_access_token().await;
        assert!(!token.is_empty());
        
        let admin_token = SharedTestHelpers::get_admin_token().await;
        assert!(!admin_token.is_empty());
        assert_ne!(token, admin_token);
    }
}