//! Mock implementations for testing
//!
//! This module provides mock implementations of complex dependencies like database
//! connections, external services, and async operations to enable comprehensive
//! unit testing without requiring actual external services.

use crate::database::{DatabaseError, DatabaseResult};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Mock database connection that simulates database operations in memory
#[derive(Debug, Clone)]
pub struct MockDatabaseConnection {
    /// Simulated data storage
    data: Arc<Mutex<HashMap<String, String>>>,
    /// Connection state
    connected: Arc<Mutex<bool>>,
    /// Simulate connection failures
    should_fail: Arc<Mutex<bool>>,
}

impl MockDatabaseConnection {
    /// Create a new mock database connection
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
            connected: Arc::new(Mutex::new(true)),
            should_fail: Arc::new(Mutex::new(false)),
        }
    }

    /// Create a mock connection that will fail operations
    pub fn failing() -> Self {
        let mock = Self::new();
        mock.set_should_fail(true);
        mock
    }

    /// Set whether operations should fail
    pub fn set_should_fail(&self, should_fail: bool) {
        *self.should_fail.lock().unwrap() = should_fail;
    }

    /// Set connection status
    pub fn set_connected(&self, connected: bool) {
        *self.connected.lock().unwrap() = connected;
    }

    /// Check if connection is healthy
    pub async fn health_check(&self) -> DatabaseResult<()> {
        if *self.should_fail.lock().unwrap() {
            return Err(DatabaseError::ConnectionError(
                "Mock connection failure".to_string(),
            ));
        }

        if !*self.connected.lock().unwrap() {
            return Err(DatabaseError::ConnectionError(
                "Mock connection not available".to_string(),
            ));
        }

        Ok(())
    }

    /// Simulate a database query
    pub async fn query(&self, sql: &str) -> DatabaseResult<MockQueryResult> {
        self.health_check().await?;

        // Simple simulation based on query type
        if sql.to_uppercase().contains("SELECT") {
            Ok(MockQueryResult::new(vec![
                vec!["id".to_string(), "name".to_string()],
                vec!["1".to_string(), "test".to_string()],
            ]))
        } else {
            // INSERT, UPDATE, DELETE or any other SQL command
            Ok(MockQueryResult::new(vec![]))
        }
    }

    /// Simulate executing a command
    pub async fn execute(&self, sql: &str) -> DatabaseResult<u64> {
        self.health_check().await?;

        // Return affected rows based on operation
        if sql.to_uppercase().contains("INSERT")
            || sql.to_uppercase().contains("UPDATE")
            || sql.to_uppercase().contains("DELETE")
        {
            Ok(1)
        } else {
            Ok(0)
        }
    }

    /// Store a key-value pair (simulating Redis-like operations)
    pub async fn set(&self, key: &str, value: &str) -> DatabaseResult<()> {
        self.health_check().await?;
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }

    /// Retrieve a value by key
    pub async fn get(&self, key: &str) -> DatabaseResult<Option<String>> {
        self.health_check().await?;
        Ok(self.data.lock().unwrap().get(key).cloned())
    }

    /// Delete a key
    pub async fn del(&self, key: &str) -> DatabaseResult<bool> {
        self.health_check().await?;
        Ok(self.data.lock().unwrap().remove(key).is_some())
    }

    /// Clear all data
    pub async fn flush_all(&self) -> DatabaseResult<()> {
        self.health_check().await?;
        self.data.lock().unwrap().clear();
        Ok(())
    }

    /// Get info about the mock connection
    pub async fn info(&self) -> DatabaseResult<String> {
        self.health_check().await?;
        let data_count = self.data.lock().unwrap().len();
        Ok(format!(
            "# Mock Database\r\nkeys:{}\r\nconnected:1\r\n",
            data_count
        ))
    }
}

impl Default for MockDatabaseConnection {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock query result that simulates database query responses
#[derive(Debug, Clone)]
pub struct MockQueryResult {
    rows: Vec<Vec<String>>,
    current_row: usize,
}

impl MockQueryResult {
    /// Create a new mock query result
    pub fn new(rows: Vec<Vec<String>>) -> Self {
        Self {
            rows,
            current_row: 0,
        }
    }

    /// Get the number of rows
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Check if there are more rows
    pub fn has_next(&self) -> bool {
        self.current_row < self.rows.len()
    }

    /// Get the next row
    pub fn next_row(&mut self) -> Option<Vec<String>> {
        if self.has_next() {
            let row = self.rows[self.current_row].clone();
            self.current_row += 1;
            Some(row)
        } else {
            None
        }
    }

    /// Get all rows
    pub fn all_rows(&self) -> &Vec<Vec<String>> {
        &self.rows
    }
}

/// Mock connection factory for testing
#[derive(Debug)]
pub struct MockConnectionFactory {
    /// PostgreSQL connection mock
    postgres_mock: Option<MockDatabaseConnection>,
    /// Redis connection mock
    redis_mock: Option<MockDatabaseConnection>,
    /// Whether to simulate connection failures
    simulate_failures: bool,
}

impl MockConnectionFactory {
    /// Create a new mock connection factory
    pub fn new() -> Self {
        Self {
            postgres_mock: Some(MockDatabaseConnection::new()),
            redis_mock: Some(MockDatabaseConnection::new()),
            simulate_failures: false,
        }
    }

    /// Create a factory that simulates connection failures
    pub fn failing() -> Self {
        Self {
            postgres_mock: Some(MockDatabaseConnection::failing()),
            redis_mock: Some(MockDatabaseConnection::failing()),
            simulate_failures: true,
        }
    }

    /// Enable or disable PostgreSQL mock
    pub fn with_postgres(&mut self, enabled: bool) -> &mut Self {
        self.postgres_mock = if enabled {
            Some(if self.simulate_failures {
                MockDatabaseConnection::failing()
            } else {
                MockDatabaseConnection::new()
            })
        } else {
            None
        };
        self
    }

    /// Enable or disable Redis mock
    pub fn with_redis(&mut self, enabled: bool) -> &mut Self {
        self.redis_mock = if enabled {
            Some(if self.simulate_failures {
                MockDatabaseConnection::failing()
            } else {
                MockDatabaseConnection::new()
            })
        } else {
            None
        };
        self
    }

    /// Get PostgreSQL mock connection
    pub fn postgres(&self) -> Option<&MockDatabaseConnection> {
        self.postgres_mock.as_ref()
    }

    /// Get Redis mock connection
    pub fn redis(&self) -> Option<&MockDatabaseConnection> {
        self.redis_mock.as_ref()
    }

    /// Test all mock connections
    pub async fn test_connections(&self) -> DatabaseResult<MockConnectionTestResult> {
        let (postgres_configured, postgres_success, postgres_error) =
            if let Some(pg_mock) = &self.postgres_mock {
                let success = pg_mock.health_check().await.is_ok();
                let error = if success {
                    None
                } else {
                    Some("Mock PostgreSQL connection failed".to_string())
                };
                (true, success, error)
            } else {
                (false, false, None)
            };

        let (redis_configured, redis_success, redis_error) =
            if let Some(redis_mock) = &self.redis_mock {
                let success = redis_mock.health_check().await.is_ok();
                let error = if success {
                    None
                } else {
                    Some("Mock Redis connection failed".to_string())
                };
                (true, success, error)
            } else {
                (false, false, None)
            };

        Ok(MockConnectionTestResult {
            postgres_configured,
            postgres_success,
            postgres_error,
            redis_configured,
            redis_success,
            redis_error,
        })
    }
}

impl Default for MockConnectionFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock connection test result
#[derive(Debug, Default)]
pub struct MockConnectionTestResult {
    pub postgres_configured: bool,
    pub postgres_success: bool,
    pub postgres_error: Option<String>,
    pub redis_configured: bool,
    pub redis_success: bool,
    pub redis_error: Option<String>,
}

impl MockConnectionTestResult {
    /// Check if all configured connections succeeded
    pub fn all_successful(&self) -> bool {
        (!self.postgres_configured || self.postgres_success)
            && (!self.redis_configured || self.redis_success)
    }

    /// Get summary of test results
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        if self.postgres_configured {
            if self.postgres_success {
                parts.push("PostgreSQL: OK".to_string());
            } else {
                parts.push(format!(
                    "PostgreSQL: FAILED ({})",
                    self.postgres_error
                        .as_ref()
                        .unwrap_or(&"Unknown error".to_string())
                ));
            }
        }

        if self.redis_configured {
            if self.redis_success {
                parts.push("Redis: OK".to_string());
            } else {
                parts.push(format!(
                    "Redis: FAILED ({})",
                    self.redis_error
                        .as_ref()
                        .unwrap_or(&"Unknown error".to_string())
                ));
            }
        }

        if parts.is_empty() {
            "No databases configured".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Mock HTTP client for testing external API calls
#[derive(Debug, Clone)]
pub struct MockHttpClient {
    responses: Arc<Mutex<HashMap<String, MockHttpResponse>>>,
    default_response: Arc<Mutex<Option<MockHttpResponse>>>,
}

impl MockHttpClient {
    /// Create a new mock HTTP client
    pub fn new() -> Self {
        Self {
            responses: Arc::new(Mutex::new(HashMap::new())),
            default_response: Arc::new(Mutex::new(None)),
        }
    }

    /// Set a response for a specific URL
    pub fn set_response(&self, url: &str, response: MockHttpResponse) {
        self.responses
            .lock()
            .unwrap()
            .insert(url.to_string(), response);
    }

    /// Set a default response for unmatched URLs
    pub fn set_default_response(&self, response: MockHttpResponse) {
        *self.default_response.lock().unwrap() = Some(response);
    }

    /// Simulate an HTTP GET request
    pub async fn get(&self, url: &str) -> Result<MockHttpResponse, String> {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await; // Simulate network delay

        // Check for specific URL response
        if let Some(response) = self.responses.lock().unwrap().get(url) {
            return Ok(response.clone());
        }

        // Check for default response
        if let Some(response) = self.default_response.lock().unwrap().clone() {
            return Ok(response);
        }

        // Return 404 if no response configured
        Ok(MockHttpResponse {
            status: 404,
            body: "Not Found".to_string(),
            headers: HashMap::new(),
        })
    }

    /// Simulate an HTTP POST request
    pub async fn post(&self, url: &str, _body: &str) -> Result<MockHttpResponse, String> {
        // For simplicity, POST uses the same logic as GET
        self.get(url).await
    }
}

impl Default for MockHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock HTTP response
#[derive(Debug, Clone)]
pub struct MockHttpResponse {
    pub status: u16,
    pub body: String,
    pub headers: HashMap<String, String>,
}

impl MockHttpResponse {
    /// Create a successful response
    pub fn ok(body: &str) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            headers: HashMap::new(),
        }
    }

    /// Create an error response
    pub fn error(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_string(),
            headers: HashMap::new(),
        }
    }

    /// Create a JSON response
    pub fn json(status: u16, json: &str) -> Self {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        Self {
            status,
            body: json.to_string(),
            headers,
        }
    }

    /// Check if response is successful (2xx status)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Mock timer for testing time-based operations
#[derive(Debug)]
pub struct MockTimer {
    current_time: Arc<Mutex<std::time::SystemTime>>,
}

impl MockTimer {
    /// Create a new mock timer
    pub fn new() -> Self {
        Self {
            current_time: Arc::new(Mutex::new(std::time::SystemTime::now())),
        }
    }

    /// Set the current time
    pub fn set_time(&self, time: std::time::SystemTime) {
        *self.current_time.lock().unwrap() = time;
    }

    /// Advance time by duration
    pub fn advance_by(&self, duration: std::time::Duration) {
        let mut current = self.current_time.lock().unwrap();
        *current += duration;
    }

    /// Get the current mock time
    pub fn now(&self) -> std::time::SystemTime {
        *self.current_time.lock().unwrap()
    }

    /// Get elapsed time since a specific time
    pub fn elapsed_since(&self, since: std::time::SystemTime) -> std::time::Duration {
        self.now()
            .duration_since(since)
            .unwrap_or(std::time::Duration::ZERO)
    }
}

impl Default for MockTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_database_connection_basic_operations() {
        let mock = MockDatabaseConnection::new();

        // Test health check
        assert!(mock.health_check().await.is_ok());

        // Test key-value operations
        assert!(mock.set("key1", "value1").await.is_ok());
        assert_eq!(mock.get("key1").await.unwrap(), Some("value1".to_string()));
        assert!(mock.del("key1").await.is_ok());
        assert_eq!(mock.get("key1").await.unwrap(), None);

        // Test info
        let info = mock.info().await.unwrap();
        assert!(info.contains("Mock Database"));
    }

    #[tokio::test]
    async fn test_mock_database_connection_failures() {
        let mock = MockDatabaseConnection::failing();

        // Health check should fail
        assert!(mock.health_check().await.is_err());

        // Operations should fail
        assert!(mock.set("key1", "value1").await.is_err());
        assert!(mock.get("key1").await.is_err());
    }

    #[tokio::test]
    async fn test_mock_database_queries() {
        let mock = MockDatabaseConnection::new();

        // Test SELECT query
        let result = mock.query("SELECT * FROM users").await.unwrap();
        assert!(result.row_count() > 0);

        // Test INSERT query
        let result = mock
            .query("INSERT INTO users (name) VALUES ('test')")
            .await
            .unwrap();
        assert_eq!(result.row_count(), 0); // INSERT returns empty result set

        // Test execute operation
        let affected = mock
            .execute("UPDATE users SET name = 'updated'")
            .await
            .unwrap();
        assert_eq!(affected, 1);
    }

    #[tokio::test]
    async fn test_mock_connection_factory() {
        let mut factory = MockConnectionFactory::new();

        // Test with both databases enabled
        let result = factory.test_connections().await.unwrap();
        assert!(result.all_successful());

        // Test with only PostgreSQL
        factory.with_redis(false);
        let result = factory.test_connections().await.unwrap();
        assert!(result.postgres_configured);
        assert!(!result.redis_configured);
        assert!(result.all_successful());

        // Test failing factory
        let failing_factory = MockConnectionFactory::failing();
        let result = failing_factory.test_connections().await.unwrap();
        assert!(!result.all_successful());
    }

    #[tokio::test]
    async fn test_mock_http_client() {
        let client = MockHttpClient::new();

        // Set specific response
        client.set_response(
            "https://api.example.com/test",
            MockHttpResponse::ok("success"),
        );

        // Test GET request
        let response = client.get("https://api.example.com/test").await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "success");

        // Test unknown URL (should return 404)
        let response = client.get("https://unknown.com/api").await.unwrap();
        assert_eq!(response.status, 404);

        // Set default response
        client.set_default_response(MockHttpResponse::json(200, r#"{"default": true}"#));
        let response = client.get("https://another-unknown.com").await.unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("default"));
    }

    #[test]
    fn test_mock_timer() {
        let timer = MockTimer::new();
        let start_time = timer.now();

        // Advance time by 1 hour
        timer.advance_by(std::time::Duration::from_secs(3600));

        let elapsed = timer.elapsed_since(start_time);
        assert_eq!(elapsed.as_secs(), 3600);
    }

    #[test]
    fn test_mock_http_response_helpers() {
        let ok_response = MockHttpResponse::ok("test");
        assert!(ok_response.is_success());
        assert_eq!(ok_response.status, 200);

        let error_response = MockHttpResponse::error(404, "Not Found");
        assert!(!error_response.is_success());
        assert_eq!(error_response.status, 404);

        let json_response = MockHttpResponse::json(201, r#"{"created": true}"#);
        assert!(json_response.is_success());
        assert_eq!(
            json_response.headers.get("Content-Type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_mock_query_result() {
        let mut result = MockQueryResult::new(vec![
            vec!["1".to_string(), "John".to_string()],
            vec!["2".to_string(), "Jane".to_string()],
        ]);

        assert_eq!(result.row_count(), 2);
        assert!(result.has_next());

        let first_row = result.next_row().unwrap();
        assert_eq!(first_row, vec!["1".to_string(), "John".to_string()]);

        let second_row = result.next_row().unwrap();
        assert_eq!(second_row, vec!["2".to_string(), "Jane".to_string()]);

        assert!(!result.has_next());
        assert!(result.next_row().is_none());
    }
}
