//! Comprehensive Test Suite
//!
//! High-coverage test suite including unit tests, integration tests,
//! property-based tests, and performance benchmarks.

pub mod integration_tests;
pub mod performance_tests;
pub mod property_tests;
pub mod security_tests;

// Re-export all test modules
pub use integration_tests::*;
pub use performance_tests::*;
pub use property_tests::*;
pub use security_tests::*;

/// Test utilities and helpers
pub mod utils {
    use crate::domain::entities::User;
    use crate::domain::value_objects::{Email, PasswordHash, UserId};
    use crate::services::PasswordService;

    /// Create a test user with valid data
    pub fn create_test_user() -> User {
        let user_id = UserId::new();
        let email = Email::new("test@example.com".to_string()).unwrap();
        let password_hash =
            PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();

        User::new(user_id, email, password_hash, Some("Test User".to_string()))
    }

    /// Create a test password hash
    pub fn create_test_password_hash() -> PasswordHash {
        let service = PasswordService::new();
        service.hash_password("TestPassword123!").unwrap()
    }

    /// Generate a random test email
    pub fn random_email() -> Email {
        let random_id = uuid::Uuid::new_v4().simple().to_string();
        Email::new(format!("test.{}@example.com", &random_id[..8])).unwrap()
    }

    /// Generate a random test user ID
    pub fn random_user_id() -> UserId {
        UserId::new()
    }
}

/// Test configuration helpers
pub mod config {
    use crate::infrastructure::cache::advanced_cache::AdvancedCacheConfig;
    use crate::infrastructure::database::connection_pool::ConnectionPoolConfig;
    use crate::middleware::security_enhanced::SecurityConfig;
    use std::time::Duration;

    /// Create test security configuration
    pub fn test_security_config() -> SecurityConfig {
        SecurityConfig {
            csrf_enabled: true,
            rate_limiting_enabled: true,
            input_validation_enabled: true,
            rate_limit_requests: 1000, // Higher for tests
            rate_limit_window: Duration::from_secs(60),
            max_body_size: 1024 * 1024, // 1MB
            ..Default::default()
        }
    }

    /// Create test cache configuration
    pub fn test_cache_config() -> AdvancedCacheConfig {
        AdvancedCacheConfig {
            l1_max_size: 1000,
            l2_ttl: Duration::from_secs(300),  // 5 minutes for tests
            l3_ttl: Duration::from_secs(3600), // 1 hour for tests
            warming_enabled: false,            // Disable for tests
            compression_threshold: 1024,
            adaptive_ttl: true,
            dependency_tracking: true,
        }
    }

    /// Create test database configuration
    pub fn test_db_config() -> ConnectionPoolConfig {
        ConnectionPoolConfig {
            max_connections: 5, // Lower for tests
            min_connections: 1,
            acquire_timeout: Duration::from_secs(5),
            max_lifetime: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(60),
            database_url: "postgresql://test:test@localhost:5432/test_db".to_string(),
            prepared_statements: true,
            health_check_interval: Duration::from_secs(30),
        }
    }
}

/// Test macros for common patterns
#[macro_export]
macro_rules! assert_ok {
    ($result:expr) => {
        assert!($result.is_ok(), "Expected Ok, got Err: {:?}", $result);
    };
}

#[macro_export]
macro_rules! assert_err {
    ($result:expr) => {
        assert!($result.is_err(), "Expected Err, got Ok: {:?}", $result);
    };
}

#[macro_export]
macro_rules! assert_matches {
    ($expression:expr, $pattern:pat) => {
        match $expression {
            $pattern => {}
            ref e => panic!("Expected pattern {}, got {:?}", stringify!($pattern), e),
        }
    };
}

/// Async test helpers
pub mod async_helpers {
    use std::time::Duration;
    use tokio::time;

    /// Wait for a condition to become true with timeout
    pub async fn wait_for_condition<F, Fut>(
        condition: F,
        timeout: Duration,
        interval: Duration,
    ) -> Result<(), String>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            if condition().await {
                return Ok(());
            }
            time::sleep(interval).await;
        }

        Err(format!("Condition not met within {:?}", timeout))
    }

    /// Retry an operation with exponential backoff
    pub async fn retry_with_backoff<F, Fut, T, E>(
        mut operation: F,
        max_attempts: u32,
        base_delay: Duration,
    ) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        let mut attempt = 0;

        loop {
            attempt += 1;

            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    if attempt >= max_attempts {
                        return Err(error);
                    }

                    let delay = base_delay * (2_u32.pow(attempt - 1));
                    time::sleep(delay).await;
                }
            }
        }
    }
}

/// Mock implementations for testing
pub mod mocks {
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use crate::domain::entities::{Session, User};
    use crate::domain::repositories::{DynSessionRepository, DynUserRepository};
    use crate::domain::repositories::{RepositoryError, SessionRepository, UserRepository};
    use crate::domain::value_objects::{Email, UserId};

    /// In-memory user repository for testing
    pub struct MockUserRepository {
        users: Arc<RwLock<HashMap<String, User>>>,
        emails: Arc<RwLock<HashMap<String, String>>>,
    }

    impl MockUserRepository {
        pub fn new() -> Self {
            Self {
                users: Arc::new(RwLock::new(HashMap::new())),
                emails: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        pub fn with_user(mut self, user: User) -> Self {
            let users = Arc::clone(&self.users);
            let emails = Arc::clone(&self.emails);

            tokio::spawn(async move {
                let mut users_guard = users.write().await;
                let mut emails_guard = emails.write().await;

                users_guard.insert(user.id.to_string(), user.clone());
                emails_guard.insert(user.email.as_str().to_string(), user.id.to_string());
            });

            self
        }
    }

    #[async_trait::async_trait]
    impl UserRepository for MockUserRepository {
        async fn find_by_email(&self, email: &Email) -> Result<Option<User>, RepositoryError> {
            let emails = self.emails.read().await;
            let users = self.users.read().await;

            if let Some(user_id) = emails.get(email.as_str()) {
                if let Some(user) = users.get(user_id) {
                    return Ok(Some(user.clone()));
                }
            }

            Ok(None)
        }

        async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, RepositoryError> {
            let users = self.users.read().await;
            Ok(users.get(&id.to_string()).cloned())
        }

        async fn save(&self, user: &User) -> Result<(), RepositoryError> {
            let mut users = self.users.write().await;
            let mut emails = self.emails.write().await;

            users.insert(user.id.to_string(), user.clone());
            emails.insert(user.email.as_str().to_string(), user.id.to_string());

            Ok(())
        }

        async fn update_last_login(
            &self,
            _id: &UserId,
            _login_time: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), RepositoryError> {
            // Mock implementation - do nothing
            Ok(())
        }

        async fn delete(&self, _id: &UserId) -> Result<(), RepositoryError> {
            // Mock implementation - do nothing
            Ok(())
        }

        async fn exists_by_email(&self, email: &Email) -> Result<bool, RepositoryError> {
            let emails = self.emails.read().await;
            Ok(emails.contains_key(email.as_str()))
        }
    }

    /// In-memory session repository for testing
    pub struct MockSessionRepository {
        sessions: Arc<RwLock<HashMap<String, Session>>>,
    }

    impl MockSessionRepository {
        pub fn new() -> Self {
            Self {
                sessions: Arc::new(RwLock::new(HashMap::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl SessionRepository for MockSessionRepository {
        async fn find_by_id(&self, id: &str) -> Result<Option<Session>, RepositoryError> {
            let sessions = self.sessions.read().await;
            Ok(sessions.get(id).cloned())
        }

        async fn find_by_token(&self, token: &str) -> Result<Option<Session>, RepositoryError> {
            let sessions = self.sessions.read().await;
            for session in sessions.values() {
                if session.token == token {
                    return Ok(Some(session.clone()));
                }
            }
            Ok(None)
        }

        async fn find_by_user_id(&self, user_id: &UserId) -> Result<Vec<Session>, RepositoryError> {
            let sessions = self.sessions.read().await;
            let user_sessions: Vec<Session> = sessions
                .values()
                .filter(|s| s.user_id == *user_id)
                .cloned()
                .collect();
            Ok(user_sessions)
        }

        async fn save(&self, session: &Session) -> Result<(), RepositoryError> {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.id.clone(), session.clone());
            Ok(())
        }

        async fn update(&self, session: &Session) -> Result<(), RepositoryError> {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session.id.clone(), session.clone());
            Ok(())
        }

        async fn delete(&self, id: &str) -> Result<(), RepositoryError> {
            let mut sessions = self.sessions.write().await;
            sessions.remove(id);
            Ok(())
        }

        async fn cleanup_expired(&self) -> Result<usize, RepositoryError> {
            let mut sessions = self.sessions.write().await;
            let now = chrono::Utc::now();
            let expired_count = sessions.len();

            sessions.retain(|_, session| session.expires_at > now);

            Ok(expired_count - sessions.len())
        }
    }

    /// Create mock repositories for testing
    pub fn create_mock_repositories() -> (DynUserRepository, DynSessionRepository) {
        let user_repo: DynUserRepository = Box::new(MockUserRepository::new());
        let session_repo: DynSessionRepository = Box::new(MockSessionRepository::new());

        (user_repo, session_repo)
    }
}
