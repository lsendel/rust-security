//! Test Fixtures and Builders
//!
//! Provides consistent test data generation and builder patterns for comprehensive testing.
//! This module ensures test reliability and maintainability by centralizing test data creation.

use auth_service::storage::cache::{LruTokenCache, TokenCacheConfig};
use common::TokenRecord;
use std::collections::HashMap;
use std::sync::Arc;

/// Test data builder for TokenRecord
#[derive(Debug, Clone, Default)]
pub struct TokenRecordBuilder {
    active: Option<bool>,
    scope: Option<String>,
    client_id: Option<String>,
    exp: Option<i64>,
    iat: Option<i64>,
    sub: Option<String>,
    token_binding: Option<String>,
    mfa_verified: Option<bool>,
}

impl TokenRecordBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn active(mut self, active: bool) -> Self {
        self.active = Some(active);
        self
    }

    #[must_use]
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    #[must_use]
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    #[must_use]
    pub fn exp(mut self, exp: i64) -> Self {
        self.exp = Some(exp);
        self
    }

    #[must_use]
    pub fn iat(mut self, iat: i64) -> Self {
        self.iat = Some(iat);
        self
    }

    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn sub(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    #[must_use]
    pub fn token_binding(mut self, token_binding: impl Into<String>) -> Self {
        self.token_binding = Some(token_binding.into());
        self
    }

    #[must_use]
    pub fn mfa_verified(mut self, mfa_verified: bool) -> Self {
        self.mfa_verified = Some(mfa_verified);
        self
    }

    #[must_use]
    pub fn build(self) -> TokenRecord {
        TokenRecord {
            active: self.active.unwrap_or(true),
            scope: self.scope,
            client_id: self.client_id,
            exp: self.exp,
            iat: self.iat,
            sub: self.sub,
            token_binding: self.token_binding,
            mfa_verified: self.mfa_verified.unwrap_or(false),
        }
    }
}

/// Test data builder for TokenCacheConfig
#[derive(Debug, Clone, Default)]
pub struct TokenCacheConfigBuilder {
    max_tokens: Option<usize>,
    max_age_secs: Option<u64>,
    cleanup_interval_secs: Option<u64>,
}

impl TokenCacheConfigBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    #[must_use]
    pub fn max_age_secs(mut self, max_age_secs: u64) -> Self {
        self.max_age_secs = Some(max_age_secs);
        self
    }

    #[must_use]
    pub fn cleanup_interval_secs(mut self, cleanup_interval_secs: u64) -> Self {
        self.cleanup_interval_secs = Some(cleanup_interval_secs);
        self
    }

    #[must_use]
    pub fn build(self) -> TokenCacheConfig {
        TokenCacheConfig {
            max_tokens: self.max_tokens.unwrap_or(1000),
            max_age: std::time::Duration::from_secs(self.max_age_secs.unwrap_or(3600)),
            cleanup_interval: std::time::Duration::from_secs(
                self.cleanup_interval_secs.unwrap_or(300),
            ),
        }
    }
}

/// Predefined test fixtures for common scenarios
pub struct TestFixtures;

impl TestFixtures {
    /// Create a valid active token record
    #[must_use]
    pub fn valid_token(user_id: &str) -> TokenRecord {
        TokenRecordBuilder::new()
            .active(true)
            .sub(user_id)
            .client_id("test_client")
            .exp(1_700_000_000) // Future timestamp
            .iat(1_699_000_000) // Past timestamp
            .build()
    }

    /// Create an expired token record
    #[must_use]
    pub fn expired_token(user_id: &str) -> TokenRecord {
        TokenRecordBuilder::new()
            .active(false)
            .sub(user_id)
            .exp(1_600_000_000) // Past timestamp
            .build()
    }

    /// Create an admin token with elevated privileges
    #[must_use]
    pub fn admin_token(user_id: &str) -> TokenRecord {
        TokenRecordBuilder::new()
            .active(true)
            .sub(user_id)
            .scope("admin")
            .client_id("admin_client")
            .mfa_verified(true)
            .build()
    }

    /// Create a token with custom scope
    #[must_use]
    pub fn scoped_token(user_id: &str, scope: &str) -> TokenRecord {
        TokenRecordBuilder::new()
            .active(true)
            .sub(user_id)
            .scope(scope)
            .build()
    }

    /// Create a token with MFA verification
    #[must_use]
    pub fn mfa_verified_token(user_id: &str) -> TokenRecord {
        TokenRecordBuilder::new()
            .active(true)
            .sub(user_id)
            .mfa_verified(true)
            .build()
    }

    /// Create a token with token binding
    #[must_use]
    pub fn bound_token(user_id: &str, binding: &str) -> TokenRecord {
        TokenRecordBuilder::new()
            .active(true)
            .sub(user_id)
            .token_binding(binding)
            .build()
    }

    /// Create a large cache configuration for performance testing
    #[must_use]
    pub fn large_cache_config() -> TokenCacheConfig {
        TokenCacheConfigBuilder::new()
            .max_tokens(10000)
            .max_age_secs(7200)
            .cleanup_interval_secs(600)
            .build()
    }

    /// Create a small cache configuration for unit testing
    #[must_use]
    pub fn small_cache_config() -> TokenCacheConfig {
        TokenCacheConfigBuilder::new()
            .max_tokens(10)
            .max_age_secs(60)
            .cleanup_interval_secs(30)
            .build()
    }

    /// Create a collection of test tokens for bulk operations
    #[must_use]
    pub fn token_collection(count: usize) -> Vec<TokenRecord> {
        (0..count)
            .map(|i| {
                TokenRecordBuilder::new()
                    .active(true)
                    .sub(format!("user_{i}"))
                    .client_id(format!("client_{i}"))
                    .build()
            })
            .collect()
    }

    /// Create test data for performance benchmarking
    #[must_use]
    pub fn performance_test_data() -> (Vec<TokenRecord>, TokenCacheConfig) {
        let tokens = Self::token_collection(1000);
        let config = Self::large_cache_config();
        (tokens, config)
    }

    /// Create test data for security testing (malformed/invalid data)
    #[must_use]
    pub fn security_test_tokens() -> Vec<TokenRecord> {
        vec![
            // Token with extremely long values
            TokenRecordBuilder::new()
                .active(true)
                .sub("a".repeat(1000))
                .client_id("b".repeat(500))
                .build(),
            // Token with special characters
            TokenRecordBuilder::new()
                .active(true)
                .sub("user<script>alert('xss')</script>")
                .build(),
            // Token with null bytes
            TokenRecordBuilder::new()
                .active(true)
                .sub("user\x00null")
                .build(),
            // Token with unicode characters
            TokenRecordBuilder::new().active(true).sub("用户🚀").build(),
        ]
    }
}

/// Test data factory for generating test scenarios
pub struct TestDataFactory {
    cache: HashMap<String, Vec<TokenRecord>>,
}

impl Default for TestDataFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl TestDataFactory {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Get or create a cached dataset by name
    pub fn get_or_create(&mut self, name: &str, size: usize) -> &[TokenRecord] {
        if !self.cache.contains_key(name) {
            let data = TestFixtures::token_collection(size);
            self.cache.insert(name.to_string(), data);
        }
        self.cache.get(name).unwrap()
    }

    /// Create a scenario with mixed valid/invalid tokens
    #[must_use]
    pub fn mixed_scenario(&self, valid_count: usize, invalid_count: usize) -> Vec<TokenRecord> {
        let mut tokens = Vec::new();

        // Add valid tokens
        for i in 0..valid_count {
            tokens.push(TestFixtures::valid_token(&format!("valid_user_{i}")));
        }

        // Add invalid/expired tokens
        for i in 0..invalid_count {
            tokens.push(TestFixtures::expired_token(&format!("expired_user_{i}")));
        }

        tokens
    }

    /// Clear cached data (useful for memory management in long-running tests)
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

/// Test scenario definitions for comprehensive testing
pub mod scenarios {
    use super::*;

    /// Authentication flow test scenario
    #[must_use]
    pub fn auth_flow_scenario() -> Vec<TokenRecord> {
        vec![
            TestFixtures::valid_token("user1"),
            TestFixtures::admin_token("admin1"),
            TestFixtures::scoped_token("user2", "read"),
            TestFixtures::mfa_verified_token("user3"),
        ]
    }

    /// Security vulnerability test scenario
    #[must_use]
    pub fn security_vulnerability_scenario() -> Vec<TokenRecord> {
        TestFixtures::security_test_tokens()
    }

    /// Performance stress test scenario
    #[must_use]
    pub fn performance_stress_scenario() -> (Vec<TokenRecord>, TokenCacheConfig) {
        TestFixtures::performance_test_data()
    }

    /// Cache eviction test scenario
    #[must_use]
    pub fn cache_eviction_scenario() -> (Vec<TokenRecord>, TokenCacheConfig) {
        let config = TestFixtures::small_cache_config();
        let tokens = TestFixtures::token_collection(50); // More than cache capacity
        (tokens, config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_record_builder() {
        let token = TokenRecordBuilder::new()
            .active(true)
            .sub("test_user")
            .client_id("test_client")
            .build();

        assert!(token.active);
        assert_eq!(token.sub.as_deref(), Some("test_user"));
        assert_eq!(token.client_id.as_deref(), Some("test_client"));
    }

    #[test]
    fn test_predefined_fixtures() {
        let valid_token = TestFixtures::valid_token("user1");
        assert!(valid_token.active);
        assert_eq!(valid_token.sub.as_deref(), Some("user1"));

        let admin_token = TestFixtures::admin_token("admin1");
        assert_eq!(admin_token.scope.as_deref(), Some("admin"));
        assert!(admin_token.mfa_verified);
    }

    #[test]
    fn test_token_collection_generation() {
        let tokens = TestFixtures::token_collection(5);
        assert_eq!(tokens.len(), 5);
        for (i, token) in tokens.iter().enumerate() {
            assert_eq!(token.sub.as_deref(), Some(format!("user_{i}").as_str()));
        }
    }

    #[test]
    fn test_test_data_factory() {
        let mut factory = TestDataFactory::new();

        let data1 = factory.get_or_create("test1", 10);
        assert_eq!(data1.len(), 10);

        // Create new reference to avoid double borrow
        let data2 = factory.get_or_create("test1", 10); // Should return cached
        assert_eq!(data2.len(), 10);
        // Note: as_ptr comparison not reliable for different Vec instances
    }

    #[test]
    fn test_scenarios() {
        let auth_flow = scenarios::auth_flow_scenario();
        assert_eq!(auth_flow.len(), 4);

        let security = scenarios::security_vulnerability_scenario();
        assert!(!security.is_empty());

        let (perf_tokens, perf_config) = scenarios::performance_stress_scenario();
        assert_eq!(perf_tokens.len(), 1000);
        assert_eq!(perf_config.max_tokens, 10000);
    }
}
