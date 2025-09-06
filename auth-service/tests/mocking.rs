//! Comprehensive Mocking Layer
//!
//! Provides mock implementations for external dependencies to ensure test isolation,
//! reliability, and speed. This layer enables testing components in isolation.

use common::TokenRecord;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Mock implementation of the Store trait for testing
#[derive(Debug, Clone, Default)]
pub struct MockStore {
    tokens: Arc<Mutex<HashMap<String, TokenRecord>>>,
    operations: Arc<Mutex<Vec<MockOperation>>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MockOperation {
    GetActive {
        key: String,
    },
    SetActive {
        key: String,
        active: bool,
        ttl: Option<u64>,
    },
    Delete {
        key: String,
    },
}

impl MockStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create mock with pre-populated data
    #[must_use]
    pub fn with_data(data: HashMap<String, TokenRecord>) -> Self {
        Self {
            tokens: Arc::new(Mutex::new(data)),
            operations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get recorded operations for verification
    #[must_use]
    pub fn operations(&self) -> Vec<MockOperation> {
        self.operations.lock().unwrap().clone()
    }

    /// Clear recorded operations
    pub fn clear_operations(&self) {
        self.operations.lock().unwrap().clear();
    }

    /// Check if a specific operation was recorded
    #[must_use]
    pub fn has_operation(&self, operation: &MockOperation) -> bool {
        self.operations.lock().unwrap().contains(operation)
    }

    /// Get the number of recorded operations
    #[must_use]
    pub fn operation_count(&self) -> usize {
        self.operations.lock().unwrap().len()
    }

    /// Add a token to the mock store
    pub fn add_token(&self, key: String, token: TokenRecord) {
        self.tokens.lock().unwrap().insert(key, token);
    }

    /// Remove a token from the mock store
    pub fn remove_token(&self, key: &str) {
        self.tokens.lock().unwrap().remove(key);
    }

    /// Clear all tokens
    pub fn clear(&self) {
        self.tokens.lock().unwrap().clear();
    }
}

impl MockStore {
    async fn get_active(
        &self,
        key: &str,
    ) -> Result<Option<TokenRecord>, Box<dyn std::error::Error + Send + Sync>> {
        let operation = MockOperation::GetActive {
            key: key.to_string(),
        };
        self.operations.lock().unwrap().push(operation);

        Ok(self.tokens.lock().unwrap().get(key).cloned())
    }

    async fn set_active(
        &self,
        key: String,
        active: bool,
        ttl: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let operation = MockOperation::SetActive {
            key: key.clone(),
            active,
            ttl,
        };
        self.operations.lock().unwrap().push(operation);

        if let Some(token) = self.tokens.lock().unwrap().get_mut(&key) {
            token.active = active;
        }
        Ok(())
    }

    async fn delete(&self, key: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let operation = MockOperation::Delete { key: key.clone() };
        self.operations.lock().unwrap().push(operation);

        self.tokens.lock().unwrap().remove(&key);
        Ok(())
    }
}

/// Mock HTTP client for testing external API calls
#[derive(Debug, Clone, Default)]
pub struct MockHttpClient {
    responses: Arc<Mutex<HashMap<String, MockHttpResponse>>>,
    requests: Arc<Mutex<Vec<MockHttpRequest>>>,
}

#[derive(Debug, Clone)]
pub struct MockHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MockHttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl MockHttpClient {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mock a response for a specific URL
    pub fn mock_response(&self, url: impl Into<String>, response: MockHttpResponse) {
        self.responses.lock().unwrap().insert(url.into(), response);
    }

    /// Get recorded requests
    #[must_use]
    pub fn requests(&self) -> Vec<MockHttpRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// Clear recorded requests
    pub fn clear_requests(&self) {
        self.requests.lock().unwrap().clear();
    }

    /// Simulate an HTTP request (for testing purposes)
    pub async fn request(
        &self,
        method: &str,
        url: &str,
        headers: HashMap<String, String>,
        body: Option<&str>,
    ) -> Result<MockHttpResponse, String> {
        let request = MockHttpRequest {
            method: method.to_string(),
            url: url.to_string(),
            headers: headers.clone(),
            body: body.map(std::string::ToString::to_string),
        };
        self.requests.lock().unwrap().push(request);

        if let Some(response) = self.responses.lock().unwrap().get(url) {
            Ok(response.clone())
        } else {
            Err(format!("No mock response configured for URL: {url}"))
        }
    }
}

/// Mock Redis client for testing Redis operations
#[derive(Debug, Clone, Default)]
pub struct MockRedisClient {
    data: Arc<Mutex<HashMap<String, String>>>,
    operations: Arc<Mutex<Vec<MockRedisOperation>>>,
}

#[derive(Debug, Clone)]
pub enum MockRedisOperation {
    Get {
        key: String,
    },
    Set {
        key: String,
        value: String,
        ttl: Option<u64>,
    },
    Delete {
        key: String,
    },
    Exists {
        key: String,
    },
}

impl MockRedisClient {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populate mock data
    pub fn with_data(&self, data: HashMap<String, String>) {
        *self.data.lock().unwrap() = data;
    }

    /// Get recorded operations
    #[must_use]
    pub fn operations(&self) -> Vec<MockRedisOperation> {
        self.operations.lock().unwrap().clone()
    }

    /// Simulate Redis GET operation
    pub async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let operation = MockRedisOperation::Get {
            key: key.to_string(),
        };
        self.operations.lock().unwrap().push(operation);

        Ok(self.data.lock().unwrap().get(key).cloned())
    }

    /// Simulate Redis SET operation
    pub async fn set(&self, key: String, value: String, ttl: Option<u64>) -> Result<(), String> {
        let operation = MockRedisOperation::Set {
            key: key.clone(),
            value: value.clone(),
            ttl,
        };
        self.operations.lock().unwrap().push(operation);

        self.data.lock().unwrap().insert(key, value);
        Ok(())
    }

    /// Simulate Redis DELETE operation
    pub async fn delete(&self, key: String) -> Result<bool, String> {
        let operation = MockRedisOperation::Delete { key: key.clone() };
        self.operations.lock().unwrap().push(operation);

        let existed = self.data.lock().unwrap().remove(&key).is_some();
        Ok(existed)
    }

    /// Simulate Redis EXISTS operation
    pub async fn exists(&self, key: &str) -> Result<bool, String> {
        let operation = MockRedisOperation::Exists {
            key: key.to_string(),
        };
        self.operations.lock().unwrap().push(operation);

        Ok(self.data.lock().unwrap().contains_key(key))
    }
}

/// Mock database client for testing database operations
#[derive(Debug, Clone, Default)]
pub struct MockDatabaseClient {
    records: Arc<Mutex<HashMap<String, serde_json::Value>>>,
    queries: Arc<Mutex<Vec<String>>>,
}

impl MockDatabaseClient {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populate mock records
    pub fn with_records(&self, records: HashMap<String, serde_json::Value>) {
        *self.records.lock().unwrap() = records;
    }

    /// Get recorded queries
    #[must_use]
    pub fn queries(&self) -> Vec<String> {
        self.queries.lock().unwrap().clone()
    }

    /// Simulate database query
    pub async fn query(
        &self,
        sql: &str,
        _params: Vec<serde_json::Value>,
    ) -> Result<Vec<serde_json::Value>, String> {
        self.queries.lock().unwrap().push(sql.to_string());

        // Simple mock: return records that match table name in query
        let records = self.records.lock().unwrap();
        let results: Vec<serde_json::Value> = records.values().cloned().collect();
        Ok(results)
    }

    /// Simulate database execute
    pub async fn execute(&self, sql: &str, _params: Vec<serde_json::Value>) -> Result<u64, String> {
        self.queries.lock().unwrap().push(sql.to_string());
        Ok(1) // Mock affected rows
    }
}

/// Test utilities for mocking
pub mod test_utils {
    use super::*;
    // Note: TestFixtures import removed due to circular dependency

    /// Create a mock store with test data
    #[must_use]
    pub fn create_mock_store_with_data() -> MockStore {
        let mut data = HashMap::new();
        // Create test tokens directly
        let token1 = TokenRecord {
            active: true,
            scope: None,
            client_id: Some("test_client".to_string()),
            exp: None,
            iat: None,
            sub: Some("user1".to_string()),
            token_binding: None,
            mfa_verified: false,
        };
        let token2 = TokenRecord {
            active: false,
            scope: None,
            client_id: Some("test_client".to_string()),
            exp: Some(1_600_000_000),
            iat: None,
            sub: Some("user2".to_string()),
            token_binding: None,
            mfa_verified: false,
        };
        let admin_token = TokenRecord {
            active: true,
            scope: Some("admin".to_string()),
            client_id: Some("admin_client".to_string()),
            exp: None,
            iat: None,
            sub: Some("admin".to_string()),
            token_binding: None,
            mfa_verified: true,
        };

        data.insert("token1".to_string(), token1);
        data.insert("token2".to_string(), token2);
        data.insert("admin_token".to_string(), admin_token);

        MockStore::with_data(data)
    }

    /// Create a mock HTTP client with predefined responses
    #[must_use]
    pub fn create_mock_http_client() -> MockHttpClient {
        let client = MockHttpClient::new();

        // Mock OAuth token endpoint
        client.mock_response(
            "http://localhost:8080/oauth/token",
            MockHttpResponse {
                status: 200,
                headers: HashMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: r#"{"access_token":"mock_token","token_type":"Bearer","expires_in":3600}"#
                    .to_string(),
            },
        );

        client
    }

    /// Create a mock Redis client with session data
    #[must_use]
    pub fn create_mock_redis_client() -> MockRedisClient {
        let client = MockRedisClient::new();
        let mut data = HashMap::new();
        data.insert(
            "session:user1".to_string(),
            r#"{"user_id":"user1","expires":1700000000}"#.to_string(),
        );
        client.with_data(data);
        client
    }

    /// Create a mock database client with test records
    #[must_use]
    pub fn create_mock_database_client() -> MockDatabaseClient {
        let client = MockDatabaseClient::new();
        let mut records = HashMap::new();
        records.insert(
            "user1".to_string(),
            serde_json::json!({
                "id": "user1",
                "email": "user1@example.com",
                "active": true
            }),
        );
        client.with_records(records);
        client
    }
}

// Macros for easy mocking in tests (commented out due to import issues)
// #[macro_export]
// macro_rules! mock_store {
//     () => {
//         std::sync::Arc::new($crate::mocking::test_utils::create_mock_store_with_data())
//     };
//     ($data:expr) => {
//         std::sync::Arc::new($crate::mocking::MockStore::with_data($data))
//     };
// }
//
// #[macro_export]
// macro_rules! mock_http_client {
//     () => {
//         std::sync::Arc::new($crate::mocking::test_utils::create_mock_http_client())
//     };
// }
//
// #[macro_export]
// macro_rules! mock_redis_client {
//     () => {
//         std::sync::Arc::new($crate::mocking::test_utils::create_mock_redis_client())
//     };
// }
//
// #[macro_export]
// macro_rules! mock_database_client {
//     () => {
//         std::sync::Arc::new($crate::mocking::test_utils::create_mock_database_client())
//     };
// }

#[cfg(test)]
mod tests {
    use super::*;
    // TestFixtures import removed

    #[tokio::test]
    async fn test_mock_store_operations() {
        let store = MockStore::new();
        let token = TokenRecord {
            active: true,
            scope: None,
            client_id: Some("test_client".to_string()),
            exp: None,
            iat: None,
            sub: Some("test_user".to_string()),
            token_binding: None,
            mfa_verified: false,
        };

        // Test set operation
        store.add_token("test_key".to_string(), token.clone());
        let result = MockStore::get_active(&store, "test_key").await.unwrap();
        assert!(result.is_some());

        // Check operations were recorded
        let operations = store.operations();
        assert_eq!(operations.len(), 1);
        match &operations[0] {
            MockOperation::GetActive { key } => assert_eq!(key, "test_key"),
            _ => panic!("Expected GetActive operation"),
        }
    }

    #[tokio::test]
    async fn test_mock_http_client() {
        let client = test_utils::create_mock_http_client();

        let response = client
            .request(
                "GET",
                "http://localhost:8080/oauth/token",
                HashMap::new(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        assert!(response.body.contains("access_token"));

        // Check request was recorded
        let requests = client.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "http://localhost:8080/oauth/token");
    }

    #[tokio::test]
    async fn test_mock_redis_client() {
        let client = test_utils::create_mock_redis_client();

        let result = client.get("session:user1").await.unwrap();
        assert!(result.is_some());

        let operations = client.operations();
        assert_eq!(operations.len(), 1);
        match &operations[0] {
            MockRedisOperation::Get { key } => assert_eq!(key, "session:user1"),
            _ => panic!("Expected Get operation"),
        }
    }

    #[tokio::test]
    async fn test_mock_creation() {
        let _store = test_utils::create_mock_store_with_data();
        let _http = test_utils::create_mock_http_client();
        let _redis = test_utils::create_mock_redis_client();
        let _db = test_utils::create_mock_database_client();

        // If we get here without panicking, the creation works
        // Test passed
    }
}
