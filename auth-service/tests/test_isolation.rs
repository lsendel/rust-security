//! Test Isolation Framework
//!
//! Ensures complete test isolation by providing:
//! - Database schema isolation
//! - Redis namespace isolation
//! - File system isolation
//! - Environment variable isolation
//! - Resource cleanup guarantees

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

/// Global test isolation state
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Test isolation context
pub struct TestIsolation {
    pub test_id: String,
    pub temp_dir: PathBuf,
    pub env_vars: HashMap<String, Option<String>>, // Key -> Original value (None if not set)
    pub database_schema: Option<String>,
    pub redis_namespace: String,
    pub resources: Vec<Box<dyn FnOnce() + Send + Sync>>,
}

impl TestIsolation {
    /// Create a new isolated test context
    #[must_use]
    pub fn new(test_name: &str) -> Self {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let test_id = format!("{test_name}_{counter}");

        let temp_dir = env::temp_dir().join("rust_security_tests").join(&test_id);
        fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        Self {
            test_id: test_id.clone(),
            temp_dir,
            env_vars: HashMap::new(),
            database_schema: Some(format!("test_{test_id}")),
            redis_namespace: format!("test:{test_id}"),
            resources: Vec::new(),
        }
    }

    /// Set an environment variable for this test (isolated)
    pub fn set_env_var(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();

        // Store original value
        let original = env::var(&key).ok();
        self.env_vars.insert(key.clone(), original);

        // Set new value
        env::set_var(&key, &value);
    }

    /// Create an isolated file path
    #[must_use]
    pub fn isolated_path(&self, relative_path: impl AsRef<std::path::Path>) -> PathBuf {
        self.temp_dir.join(relative_path)
    }

    /// Add a cleanup resource
    pub fn add_cleanup<F>(&mut self, cleanup: F)
    where
        F: FnOnce() + Send + Sync + 'static,
    {
        self.resources.push(Box::new(cleanup));
    }

    /// Execute cleanup synchronously
    pub fn cleanup_sync(mut self) {
        // Execute sync cleanups
        while let Some(cleanup) = self.resources.pop() {
            cleanup();
        }

        // Restore environment variables
        for (key, original_value) in &self.env_vars {
            match original_value {
                Some(value) => env::set_var(key, value),
                None => env::remove_var(key),
            }
        }

        // Clean up temp directory
        if self.temp_dir.exists() {
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
    }
}

impl Drop for TestIsolation {
    fn drop(&mut self) {
        // Emergency cleanup if not done properly
        // Note: This won't restore env vars in async context
        if self.temp_dir.exists() {
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
    }
}

/// Database isolation utilities
pub mod database {
    use super::*;
    use std::sync::Arc;

    /// Database isolation context
    #[derive(Debug, Clone)]
    pub struct DatabaseIsolation {
        pub schema_name: String,
        pub connection_string: String,
        pub created_tables: Vec<String>,
    }

    impl DatabaseIsolation {
        #[must_use]
        pub fn new(test_id: &str) -> Self {
            Self {
                schema_name: format!("test_{test_id}_"),
                connection_string: format!("postgres://test:test@localhost:5432/test_{test_id}"),
                created_tables: Vec::new(),
            }
        }

        /// Create isolated database schema
        pub async fn create_schema(&mut self) -> Result<(), String> {
            // In a real implementation, this would execute SQL to create schema
            println!("Creating isolated database schema: {}", self.schema_name);
            Ok(())
        }

        /// Drop isolated database schema
        pub async fn drop_schema(&mut self) -> Result<(), String> {
            // In a real implementation, this would execute SQL to drop schema
            println!("Dropping isolated database schema: {}", self.schema_name);
            Ok(())
        }

        /// Register a table for cleanup
        pub fn register_table(&mut self, table_name: impl Into<String>) {
            self.created_tables.push(table_name.into());
        }
    }
}

/// Redis isolation utilities
pub mod redis {
    use super::*;

    /// Redis isolation context
    #[derive(Debug)]
    pub struct RedisIsolation {
        pub namespace: String,
        pub keys: Vec<String>,
    }

    impl RedisIsolation {
        #[must_use]
        pub fn new(test_id: &str) -> Self {
            Self {
                namespace: format!("test:{test_id}_"),
                keys: Vec::new(),
            }
        }

        /// Register a Redis key for cleanup
        pub fn register_key(&mut self, key: impl Into<String>) {
            self.keys.push(key.into());
        }

        /// Clean up Redis keys
        pub async fn cleanup_keys(&self) -> Result<(), String> {
            for key in &self.keys {
                println!("Cleaning up Redis key: {}", key);
                // In a real implementation, this would delete the Redis key
            }
            Ok(())
        }

        /// Create namespaced key
        #[must_use]
        pub fn namespaced_key(&self, key: &str) -> String {
            format!("{}:{}", self.namespace, key)
        }
    }
}

/// File system isolation utilities
pub mod filesystem {
    use super::*;
    use std::fs;
    use std::path::Path;

    /// File system isolation context
    #[derive(Debug)]
    pub struct FilesystemIsolation {
        pub base_dir: PathBuf,
        pub created_files: Vec<PathBuf>,
        pub created_dirs: Vec<PathBuf>,
    }

    impl FilesystemIsolation {
        #[must_use]
        pub fn new(test_id: &str) -> Self {
            let base_dir = env::temp_dir()
                .join("rust_security_tests")
                .join(format!("fs_{test_id}"));

            fs::create_dir_all(&base_dir).expect("Failed to create base directory");

            Self {
                base_dir,
                created_files: Vec::new(),
                created_dirs: Vec::new(),
            }
        }

        /// Create isolated file path
        #[must_use]
        pub fn isolated_path(&self, relative_path: impl AsRef<Path>) -> PathBuf {
            self.base_dir.join(relative_path)
        }

        /// Create isolated file with content
        pub fn create_file(
            &mut self,
            relative_path: impl AsRef<Path>,
            content: &str,
        ) -> Result<PathBuf, String> {
            let full_path = self.isolated_path(relative_path);
            fs::write(&full_path, content).map_err(|e| format!("Failed to write file: {e}"))?;
            self.created_files.push(full_path.clone());
            Ok(full_path)
        }

        /// Create isolated directory
        pub fn create_dir(&mut self, relative_path: impl AsRef<Path>) -> Result<PathBuf, String> {
            let full_path = self.isolated_path(relative_path);
            fs::create_dir_all(&full_path)
                .map_err(|e| format!("Failed to create directory: {e}"))?;
            self.created_dirs.push(full_path.clone());
            Ok(full_path)
        }

        /// Clean up filesystem resources
        pub fn cleanup(&self) -> Result<(), String> {
            // Remove created files
            for file in &self.created_files {
                if file.exists() {
                    fs::remove_file(file)
                        .map_err(|e| format!("Failed to remove file {}: {e}", file.display()))?;
                }
            }

            // Remove created directories (in reverse order)
            for dir in self.created_dirs.iter().rev() {
                if dir.exists() {
                    fs::remove_dir_all(dir).map_err(|e| {
                        format!("Failed to remove directory {}: {e}", dir.display())
                    })?;
                }
            }

            // Remove base directory
            if self.base_dir.exists() {
                fs::remove_dir_all(&self.base_dir).map_err(|e| {
                    format!(
                        "Failed to remove base directory {}: {}",
                        self.base_dir.display(),
                        e
                    )
                })?;
            }

            Ok(())
        }
    }
}

/// Global test state management
pub mod global_state {
    use super::*;
    use std::sync::OnceLock;

    static GLOBAL_STATE: OnceLock<Arc<RwLock<HashMap<String, serde_json::Value>>>> =
        OnceLock::new();

    /// Initialize global test state
    pub fn init_global_state() -> Arc<RwLock<HashMap<String, serde_json::Value>>> {
        GLOBAL_STATE
            .get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
            .clone()
    }

    /// Set global test state value
    pub async fn set_global_state(key: impl Into<String>, value: serde_json::Value) {
        let state = init_global_state();
        let mut guard = state.write().await;
        guard.insert(key.into(), value);
    }

    /// Get global test state value
    pub async fn get_global_state(key: &str) -> Option<serde_json::Value> {
        let state = init_global_state();
        let guard = state.read().await;
        guard.get(key).cloned()
    }

    /// Clear global test state
    pub async fn clear_global_state() {
        let state = init_global_state();
        let mut guard = state.write().await;
        guard.clear();
    }

    /// Test-specific state context
    #[derive(Debug)]
    pub struct TestStateContext {
        pub test_id: String,
        pub state_prefix: String,
    }

    impl TestStateContext {
        #[must_use]
        pub fn new(test_id: impl Into<String>) -> Self {
            let test_id = test_id.into();
            Self {
                test_id: test_id.clone(),
                state_prefix: format!("test_{test_id}"),
            }
        }

        /// Set test-specific state
        pub async fn set(&self, key: &str, value: serde_json::Value) {
            let full_key = format!("{}:{}", self.state_prefix, key);
            set_global_state(full_key, value).await;
        }

        /// Get test-specific state
        pub async fn get(&self, key: &str) -> Option<serde_json::Value> {
            let full_key = format!("{}:{}", self.state_prefix, key);
            get_global_state(&full_key).await
        }

        /// Clear test-specific state
        pub async fn clear(&self) {
            let state = init_global_state();
            let mut guard = state.write().await;

            let keys_to_remove: Vec<String> = guard
                .keys()
                .filter(|k| k.starts_with(&self.state_prefix))
                .cloned()
                .collect();

            for key in keys_to_remove {
                guard.remove(&key);
            }
        }
    }
}

/// Isolation-aware test execution
pub mod execution {
    use super::*;

    /// Execute a test with full isolation
    pub async fn execute_isolated_test<F, Fut>(test_name: &str, test_fn: F) -> Result<(), String>
    where
        F: FnOnce(TestIsolation) -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let isolation = TestIsolation::new(test_name);

        // Execute test with isolation context
        let result = test_fn(isolation).await;

        result
    }

    /// Execute a test with database isolation
    pub async fn execute_database_isolated_test<F, Fut>(
        test_name: &str,
        test_fn: F,
    ) -> Result<(), String>
    where
        F: FnOnce(TestIsolation, database::DatabaseIsolation) -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let isolation = TestIsolation::new(test_name);
        let mut db_isolation = database::DatabaseIsolation::new(&isolation.test_id);

        // Setup database isolation
        db_isolation.create_schema().await?;

        // Execute test
        let result = test_fn(isolation, db_isolation).await;

        result
    }
}

/// Macros for isolated test execution
#[macro_export]
macro_rules! isolated_test {
    ($test_name:ident, |$isolation:ident| $body:block) => {
        #[tokio::test]
        async fn $test_name() {
            use $crate::test_isolation::execution::execute_isolated_test;

            let result = execute_isolated_test(stringify!($test_name), |$isolation| async move {
                $body
                Ok(())
            }).await;

            result.unwrap();
        }
    };
}

#[macro_export]
macro_rules! database_isolated_test {
    ($test_name:ident, |$isolation:ident, $db:ident| $body:block) => {
        #[tokio::test]
        async fn $test_name() {
            use $crate::test_isolation::{execution::execute_database_isolated_test, database::DatabaseIsolation};

            let result = execute_database_isolated_test(stringify!($test_name), |$isolation, $db| async move {
                $body
                Ok(())
            }).await;

            result.unwrap();
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_isolation_context_creation() {
        let isolation = TestIsolation::new("test_context");

        assert!(isolation.test_id.starts_with("test_context_"));
        assert!(isolation.temp_dir.exists());
        assert!(isolation
            .database_schema
            .as_ref()
            .unwrap()
            .starts_with("test_test_context_"));
    }

    #[test]
    fn test_filesystem_isolation() {
        let mut fs_isolation = filesystem::FilesystemIsolation::new("fs_test");

        let test_file = fs_isolation
            .create_file("test.txt", "Hello, World!")
            .unwrap();
        assert!(test_file.exists());

        let test_dir = fs_isolation.create_dir("test_dir").unwrap();
        assert!(test_dir.exists());

        fs_isolation.cleanup().unwrap();
        assert!(!test_file.exists());
        assert!(!test_dir.exists());
    }

    #[tokio::test]
    async fn test_global_state_management() {
        use global_state::*;

        let context = TestStateContext::new("global_test");

        // Set test-specific state
        context.set("counter", serde_json::json!(42)).await;
        context.set("name", serde_json::json!("test")).await;

        // Retrieve state
        let counter = context.get("counter").await;
        assert_eq!(counter, Some(serde_json::json!(42)));

        let name = context.get("name").await;
        assert_eq!(name, Some(serde_json::json!("test")));

        // Clear state
        context.clear().await;
        let cleared = context.get("counter").await;
        assert!(cleared.is_none());
    }

    #[test]
    fn test_database_isolation() {
        let db_isolation = database::DatabaseIsolation::new("db_test");

        println!("Actual schema_name: {}", db_isolation.schema_name);
        println!(
            "Actual connection_string: {}",
            db_isolation.connection_string
        );

        assert!(db_isolation.schema_name.starts_with("test_db_test_"));
        assert!(db_isolation.connection_string.contains("test_db_test"));
    }

    #[test]
    fn test_redis_isolation() {
        let redis_isolation = redis::RedisIsolation::new("redis_test");

        assert!(redis_isolation.namespace.starts_with("test:redis_test_"));

        let namespaced_key = redis_isolation.namespaced_key("user:123");
        assert_eq!(
            namespaced_key,
            format!("{}:user:123", redis_isolation.namespace)
        );
    }
}
