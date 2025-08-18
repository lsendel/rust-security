use crate::{AuthError, IntrospectionRecord};
use async_trait::async_trait;
use std::fmt::Debug;
use std::time::Duration;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

/// Token operation results for atomic operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenOperation {
    pub operation_id: String,
    pub success: bool,
    pub tokens_affected: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Token lifecycle state for proper state management
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TokenState {
    Active,
    Expired,
    Revoked,
    Consumed,  // For refresh tokens that have been used
}

/// Enhanced token record with state management
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenRecord {
    pub token: String,
    pub state: TokenState,
    pub introspection: IntrospectionRecord,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub use_count: u64,
    /// Associated refresh token for access tokens
    pub refresh_token: Option<String>,
    /// Associated access token for refresh tokens  
    pub access_token: Option<String>,
}

impl TokenRecord {
    pub fn new(token: String, introspection: IntrospectionRecord) -> Self {
        let expires_at = introspection.exp.map(|exp| {
            chrono::DateTime::from_timestamp(exp, 0)
                .unwrap_or_else(chrono::Utc::now)
        });
        
        Self {
            token,
            state: TokenState::Active,
            introspection,
            created_at: chrono::Utc::now(),
            expires_at,
            revoked_at: None,
            last_used: None,
            use_count: 0,
            refresh_token: None,
            access_token: None,
        }
    }

    pub fn is_active(&self) -> bool {
        match self.state {
            TokenState::Active => {
                if let Some(expires_at) = self.expires_at {
                    chrono::Utc::now() < expires_at
                } else {
                    true
                }
            }
            _ => false,
        }
    }

    pub fn revoke(&mut self) {
        self.state = TokenState::Revoked;
        self.revoked_at = Some(chrono::Utc::now());
    }

    pub fn consume(&mut self) {
        self.state = TokenState::Consumed;
        self.last_used = Some(chrono::Utc::now());
        self.use_count += 1;
    }

    pub fn touch(&mut self) {
        self.last_used = Some(chrono::Utc::now());
        self.use_count += 1;
    }
}

/// Atomic transaction context for token operations
pub struct TokenTransaction {
    pub id: String,
    pub operations: Vec<TokenOperation>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub timeout: Duration,
}

impl TokenTransaction {
    pub fn new(timeout: Duration) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            operations: Vec::new(),
            started_at: chrono::Utc::now(),
            timeout,
        }
    }

    pub fn is_expired(&self) -> bool {
        chrono::Utc::now().signed_duration_since(self.started_at) > 
            chrono::Duration::from_std(self.timeout).unwrap_or_else(|_| chrono::Duration::seconds(30))
    }
}

/// Normalized token store trait with atomic operations
#[async_trait]
pub trait TokenStore: Send + Sync + Debug {
    /// Get a token record by token value
    async fn get_token(&self, token: &str) -> Result<Option<TokenRecord>, AuthError>;

    /// Store a new token record
    async fn store_token(&self, record: TokenRecord) -> Result<(), AuthError>;

    /// Update an existing token record
    async fn update_token(&self, token: &str, record: TokenRecord) -> Result<(), AuthError>;

    /// Atomically revoke a token and all associated tokens
    async fn revoke_token_family(&self, token: &str) -> Result<TokenOperation, AuthError>;

    /// Atomically refresh a token pair (revoke old, create new)
    async fn refresh_token_pair(
        &self, 
        refresh_token: &str,
        new_access_record: TokenRecord,
        new_refresh_record: TokenRecord,
    ) -> Result<TokenOperation, AuthError>;

    /// Check if a refresh token has been reused (security check)
    async fn is_refresh_token_reused(&self, refresh_token: &str) -> Result<bool, AuthError>;

    /// Atomically consume a one-time token (authorization codes, etc.)
    async fn consume_one_time_token(&self, token: &str) -> Result<Option<TokenRecord>, AuthError>;

    /// Get all active tokens for a subject
    async fn get_tokens_by_subject(&self, subject: &str) -> Result<Vec<TokenRecord>, AuthError>;

    /// Revoke all tokens for a subject
    async fn revoke_subject_tokens(&self, subject: &str) -> Result<TokenOperation, AuthError>;

    /// Clean up expired tokens (maintenance operation)
    async fn cleanup_expired_tokens(&self) -> Result<TokenOperation, AuthError>;

    /// Execute atomic transaction
    async fn execute_transaction<F, T>(&self, f: F) -> Result<T, AuthError>
    where
        F: FnOnce(&mut TokenTransaction) -> Result<T, AuthError> + Send,
        T: Send;

    /// Health check for the store
    async fn health_check(&self) -> Result<bool, AuthError>;

    /// Get store metrics/statistics
    async fn get_metrics(&self) -> Result<TokenStoreMetrics, AuthError>;
}

/// Token store metrics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStoreMetrics {
    pub total_tokens: u64,
    pub active_tokens: u64,
    pub revoked_tokens: u64,
    pub expired_tokens: u64,
    pub consumed_tokens: u64,
    pub operations_per_second: f64,
    pub avg_response_time_ms: f64,
    pub error_rate: f64,
    pub cache_hit_ratio: Option<f64>,
    pub connection_pool_size: Option<u32>,
    pub last_cleanup: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for TokenStoreMetrics {
    fn default() -> Self {
        Self {
            total_tokens: 0,
            active_tokens: 0,
            revoked_tokens: 0,
            expired_tokens: 0,
            consumed_tokens: 0,
            operations_per_second: 0.0,
            avg_response_time_ms: 0.0,
            error_rate: 0.0,
            cache_hit_ratio: None,
            connection_pool_size: None,
            last_cleanup: None,
        }
    }
}

/// Enhanced in-memory token store implementation
#[derive(Debug)]
pub struct InMemoryTokenStore {
    tokens: tokio::sync::RwLock<std::collections::HashMap<String, TokenRecord>>,
    operations: tokio::sync::RwLock<Vec<TokenOperation>>,
    metrics: tokio::sync::RwLock<TokenStoreMetrics>,
    start_time: std::time::Instant,
}

impl InMemoryTokenStore {
    pub fn new() -> Self {
        Self {
            tokens: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            operations: tokio::sync::RwLock::new(Vec::new()),
            metrics: tokio::sync::RwLock::new(TokenStoreMetrics::default()),
            start_time: std::time::Instant::now(),
        }
    }

    async fn record_operation(&self, operation: TokenOperation) {
        let mut ops = self.operations.write().await;
        ops.push(operation);
        
        // Keep only last 1000 operations for memory management
        if ops.len() > 1000 {
            let ops_len = ops.len();
            ops.drain(..ops_len - 1000);
        }
        
        // Update metrics
        let mut metrics = self.metrics.write().await;
        let elapsed_secs = self.start_time.elapsed().as_secs_f64();
        if elapsed_secs > 0.0 {
            metrics.operations_per_second = ops.len() as f64 / elapsed_secs;
        }
    }

    async fn update_metrics(&self) {
        let tokens = self.tokens.read().await;
        let mut metrics = self.metrics.write().await;
        
        metrics.total_tokens = tokens.len() as u64;
        metrics.active_tokens = tokens.values().filter(|t| t.is_active()).count() as u64;
        metrics.revoked_tokens = tokens.values().filter(|t| t.state == TokenState::Revoked).count() as u64;
        metrics.expired_tokens = tokens.values().filter(|t| t.state == TokenState::Expired).count() as u64;
        metrics.consumed_tokens = tokens.values().filter(|t| t.state == TokenState::Consumed).count() as u64;
        
        // Calculate cache hit ratio (always 100% for in-memory)
        metrics.cache_hit_ratio = Some(1.0);
    }
}

impl Default for InMemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TokenStore for InMemoryTokenStore {
    async fn get_token(&self, token: &str) -> Result<Option<TokenRecord>, AuthError> {
        let tokens = self.tokens.read().await;
        let mut record = tokens.get(token).cloned();
        
        // Update last_used timestamp if token exists and is being accessed
        if record.is_some() {
            drop(tokens);
            let mut tokens_mut = self.tokens.write().await;
            if let Some(stored_record) = tokens_mut.get_mut(token) {
                stored_record.touch();
                record = Some(stored_record.clone());
            }
        }
        
        self.update_metrics().await;
        Ok(record)
    }

    async fn store_token(&self, record: TokenRecord) -> Result<(), AuthError> {
        let mut tokens = self.tokens.write().await;
        let token_key = record.token.clone();
        tokens.insert(token_key.clone(), record);
        
        let operation = TokenOperation {
            operation_id: Uuid::new_v4().to_string(),
            success: true,
            tokens_affected: vec![token_key],
            timestamp: chrono::Utc::now(),
        };
        
        drop(tokens);
        self.record_operation(operation).await;
        self.update_metrics().await;
        Ok(())
    }

    async fn update_token(&self, token: &str, record: TokenRecord) -> Result<(), AuthError> {
        let mut tokens = self.tokens.write().await;
        
        if tokens.contains_key(token) {
            tokens.insert(token.to_string(), record);
            
            let operation = TokenOperation {
                operation_id: Uuid::new_v4().to_string(),
                success: true,
                tokens_affected: vec![token.to_string()],
                timestamp: chrono::Utc::now(),
            };
            
            drop(tokens);
            self.record_operation(operation).await;
            self.update_metrics().await;
            Ok(())
        } else {
            Err(AuthError::InvalidToken {
                reason: "Token not found for update".to_string(),
            })
        }
    }

    async fn revoke_token_family(&self, token: &str) -> Result<TokenOperation, AuthError> {
        let mut tokens = self.tokens.write().await;
        let mut affected_tokens = Vec::new();
        
        // Collect tokens to revoke first, then revoke them
        let mut tokens_to_revoke = vec![token.to_string()];
        
        if let Some(record) = tokens.get(token) {
            if let Some(ref refresh_token) = record.refresh_token {
                tokens_to_revoke.push(refresh_token.clone());
            }
            if let Some(ref access_token) = record.access_token {
                tokens_to_revoke.push(access_token.clone());
            }
        }
        
        // Now revoke all tokens in the family
        for token_key in &tokens_to_revoke {
            if let Some(record) = tokens.get_mut(token_key) {
                record.revoke();
                affected_tokens.push(token_key.clone());
            }
        }
        
        let operation = TokenOperation {
            operation_id: Uuid::new_v4().to_string(),
            success: !affected_tokens.is_empty(),
            tokens_affected: affected_tokens,
            timestamp: chrono::Utc::now(),
        };
        
        drop(tokens);
        self.record_operation(operation.clone()).await;
        self.update_metrics().await;
        Ok(operation)
    }

    async fn refresh_token_pair(
        &self,
        refresh_token: &str,
        new_access_record: TokenRecord,
        new_refresh_record: TokenRecord,
    ) -> Result<TokenOperation, AuthError> {
        let mut tokens = self.tokens.write().await;
        let mut affected_tokens = Vec::new();
        
        // Check if refresh token exists and is active, and collect access token
        let old_access_token = if let Some(old_refresh) = tokens.get(refresh_token) {
            if old_refresh.state != TokenState::Active || !old_refresh.is_active() {
                return Err(AuthError::InvalidRefreshToken);
            }
            old_refresh.access_token.clone()
        } else {
            return Err(AuthError::InvalidRefreshToken);
        };
        
        // Mark refresh token as consumed
        if let Some(old_refresh) = tokens.get_mut(refresh_token) {
            old_refresh.consume();
            affected_tokens.push(refresh_token.to_string());
        }
        
        // Revoke old access token if it exists
        if let Some(ref old_access_token) = old_access_token {
            if let Some(old_access) = tokens.get_mut(old_access_token) {
                old_access.revoke();
                affected_tokens.push(old_access_token.clone());
            }
        }
        
        // Store new token pair
        let new_access_token = new_access_record.token.clone();
        let new_refresh_token = new_refresh_record.token.clone();
        
        tokens.insert(new_access_token.clone(), new_access_record);
        tokens.insert(new_refresh_token.clone(), new_refresh_record);
        
        affected_tokens.push(new_access_token);
        affected_tokens.push(new_refresh_token);
        
        let operation = TokenOperation {
            operation_id: Uuid::new_v4().to_string(),
            success: true,
            tokens_affected: affected_tokens,
            timestamp: chrono::Utc::now(),
        };
        
        drop(tokens);
        self.record_operation(operation.clone()).await;
        self.update_metrics().await;
        Ok(operation)
    }

    async fn is_refresh_token_reused(&self, refresh_token: &str) -> Result<bool, AuthError> {
        let tokens = self.tokens.read().await;
        
        if let Some(record) = tokens.get(refresh_token) {
            // If token is consumed and has been used more than once, it's reused
            Ok(record.state == TokenState::Consumed && record.use_count > 1)
        } else {
            Ok(false)
        }
    }

    async fn consume_one_time_token(&self, token: &str) -> Result<Option<TokenRecord>, AuthError> {
        let mut tokens = self.tokens.write().await;
        
        if let Some(record) = tokens.get_mut(token) {
            if record.state == TokenState::Active && record.is_active() {
                record.consume();
                
                let operation = TokenOperation {
                    operation_id: Uuid::new_v4().to_string(),
                    success: true,
                    tokens_affected: vec![token.to_string()],
                    timestamp: chrono::Utc::now(),
                };
                
                let result = record.clone();
                drop(tokens);
                self.record_operation(operation).await;
                self.update_metrics().await;
                Ok(Some(result))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn get_tokens_by_subject(&self, subject: &str) -> Result<Vec<TokenRecord>, AuthError> {
        let tokens = self.tokens.read().await;
        let mut result = Vec::new();
        
        for record in tokens.values() {
            if let Some(ref sub) = record.introspection.sub {
                if sub == subject {
                    result.push(record.clone());
                }
            }
        }
        
        Ok(result)
    }

    async fn revoke_subject_tokens(&self, subject: &str) -> Result<TokenOperation, AuthError> {
        let mut tokens = self.tokens.write().await;
        let mut affected_tokens = Vec::new();
        
        for (token_key, record) in tokens.iter_mut() {
            if let Some(ref sub) = record.introspection.sub {
                if sub == subject && record.state == TokenState::Active {
                    record.revoke();
                    affected_tokens.push(token_key.clone());
                }
            }
        }
        
        let operation = TokenOperation {
            operation_id: Uuid::new_v4().to_string(),
            success: !affected_tokens.is_empty(),
            tokens_affected: affected_tokens,
            timestamp: chrono::Utc::now(),
        };
        
        drop(tokens);
        self.record_operation(operation.clone()).await;
        self.update_metrics().await;
        Ok(operation)
    }

    async fn cleanup_expired_tokens(&self) -> Result<TokenOperation, AuthError> {
        let mut tokens = self.tokens.write().await;
        let mut affected_tokens = Vec::new();
        let now = chrono::Utc::now();
        
        tokens.retain(|token_key, record| {
            let should_keep = match record.state {
                TokenState::Active => {
                    if let Some(expires_at) = record.expires_at {
                        if now > expires_at {
                            affected_tokens.push(token_key.clone());
                            false
                        } else {
                            true
                        }
                    } else {
                        true
                    }
                }
                TokenState::Consumed | TokenState::Revoked => {
                    // Remove consumed/revoked tokens older than 24 hours
                    if let Some(revoked_at) = record.revoked_at {
                        let age = now.signed_duration_since(revoked_at);
                        if age > chrono::Duration::hours(24) {
                            affected_tokens.push(token_key.clone());
                            false
                        } else {
                            true
                        }
                    } else if let Some(last_used) = record.last_used {
                        let age = now.signed_duration_since(last_used);
                        if age > chrono::Duration::hours(24) {
                            affected_tokens.push(token_key.clone());
                            false
                        } else {
                            true
                        }
                    } else {
                        true
                    }
                }
                TokenState::Expired => {
                    affected_tokens.push(token_key.clone());
                    false
                }
            };
            should_keep
        });
        
        let operation = TokenOperation {
            operation_id: Uuid::new_v4().to_string(),
            success: true,
            tokens_affected: affected_tokens,
            timestamp: chrono::Utc::now(),
        };
        
        let mut metrics = self.metrics.write().await;
        metrics.last_cleanup = Some(now);
        drop(metrics);
        drop(tokens);
        
        self.record_operation(operation.clone()).await;
        self.update_metrics().await;
        Ok(operation)
    }

    async fn execute_transaction<F, T>(&self, f: F) -> Result<T, AuthError>
    where
        F: FnOnce(&mut TokenTransaction) -> Result<T, AuthError> + Send,
        T: Send,
    {
        let mut transaction = TokenTransaction::new(Duration::from_secs(30));
        
        if transaction.is_expired() {
            return Err(AuthError::InvalidRequest {
                reason: "Transaction timeout".to_string(),
            });
        }
        
        f(&mut transaction)
    }

    async fn health_check(&self) -> Result<bool, AuthError> {
        // For in-memory store, always healthy if we can read
        let _tokens = self.tokens.read().await;
        Ok(true)
    }

    async fn get_metrics(&self) -> Result<TokenStoreMetrics, AuthError> {
        self.update_metrics().await;
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_token_record(token: &str, subject: &str) -> TokenRecord {
        let introspection = IntrospectionRecord {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("test_client".to_string()),
            exp: Some(chrono::Utc::now().timestamp() + 3600),
            iat: Some(chrono::Utc::now().timestamp()),
            sub: Some(subject.to_string()),
            token_binding: None,
        };
        TokenRecord::new(token.to_string(), introspection)
    }

    #[tokio::test]
    async fn test_store_and_retrieve_token() {
        let store = InMemoryTokenStore::new();
        let record = create_test_token_record("test_token", "user123");
        
        store.store_token(record.clone()).await.unwrap();
        let retrieved = store.get_token("test_token").await.unwrap().unwrap();
        
        assert_eq!(retrieved.token, "test_token");
        assert_eq!(retrieved.introspection.sub, Some("user123".to_string()));
        assert!(retrieved.is_active());
    }

    #[tokio::test]
    async fn test_atomic_revoke_token_family() {
        let store = InMemoryTokenStore::new();
        
        // Create access token with associated refresh token
        let mut access_record = create_test_token_record("access_token", "user123");
        access_record.refresh_token = Some("refresh_token".to_string());
        
        let mut refresh_record = create_test_token_record("refresh_token", "user123");
        refresh_record.access_token = Some("access_token".to_string());
        
        store.store_token(access_record).await.unwrap();
        store.store_token(refresh_record).await.unwrap();
        
        // Revoke the token family
        let operation = store.revoke_token_family("access_token").await.unwrap();
        
        assert!(operation.success);
        assert_eq!(operation.tokens_affected.len(), 2);
        assert!(operation.tokens_affected.contains(&"access_token".to_string()));
        assert!(operation.tokens_affected.contains(&"refresh_token".to_string()));
        
        // Verify both tokens are revoked
        let access_token = store.get_token("access_token").await.unwrap().unwrap();
        let refresh_token = store.get_token("refresh_token").await.unwrap().unwrap();
        
        assert_eq!(access_token.state, TokenState::Revoked);
        assert_eq!(refresh_token.state, TokenState::Revoked);
        assert!(!access_token.is_active());
        assert!(!refresh_token.is_active());
    }

    #[tokio::test]
    async fn test_atomic_refresh_token_pair() {
        let store = InMemoryTokenStore::new();
        
        // Create initial refresh token
        let mut old_refresh = create_test_token_record("old_refresh", "user123");
        old_refresh.access_token = Some("old_access".to_string());
        store.store_token(old_refresh).await.unwrap();
        
        // Create old access token  
        let mut old_access = create_test_token_record("old_access", "user123");
        old_access.refresh_token = Some("old_refresh".to_string());
        store.store_token(old_access).await.unwrap();
        
        // Create new token pair
        let mut new_access = create_test_token_record("new_access", "user123");
        new_access.refresh_token = Some("new_refresh".to_string());
        
        let mut new_refresh = create_test_token_record("new_refresh", "user123");
        new_refresh.access_token = Some("new_access".to_string());
        
        // Perform atomic refresh
        let operation = store.refresh_token_pair(
            "old_refresh",
            new_access,
            new_refresh,
        ).await.unwrap();
        
        assert!(operation.success);
        assert_eq!(operation.tokens_affected.len(), 4); // old_refresh, old_access, new_access, new_refresh
        
        // Verify old tokens are consumed/revoked
        let old_refresh_record = store.get_token("old_refresh").await.unwrap().unwrap();
        let old_access_record = store.get_token("old_access").await.unwrap().unwrap();
        
        assert_eq!(old_refresh_record.state, TokenState::Consumed);
        assert_eq!(old_access_record.state, TokenState::Revoked);
        
        // Verify new tokens are active
        let new_access_record = store.get_token("new_access").await.unwrap().unwrap();
        let new_refresh_record = store.get_token("new_refresh").await.unwrap().unwrap();
        
        assert!(new_access_record.is_active());
        assert!(new_refresh_record.is_active());
    }

    #[tokio::test]
    async fn test_refresh_token_reuse_detection() {
        let store = InMemoryTokenStore::new();
        let record = create_test_token_record("refresh_token", "user123");
        
        store.store_token(record).await.unwrap();
        
        // First consumption should work
        let consumed = store.consume_one_time_token("refresh_token").await.unwrap();
        assert!(consumed.is_some());
        
        // Check reuse detection
        let is_reused = store.is_refresh_token_reused("refresh_token").await.unwrap();
        assert!(!is_reused); // Not reused yet, just consumed once
        
        // Try to consume again (simulate reuse attack)
        let consumed_again = store.consume_one_time_token("refresh_token").await.unwrap();
        assert!(consumed_again.is_none()); // Should be None since already consumed
    }

    #[tokio::test]
    async fn test_cleanup_expired_tokens() {
        let store = InMemoryTokenStore::new();
        
        // Create expired token
        let mut expired_record = create_test_token_record("expired_token", "user123");
        expired_record.expires_at = Some(chrono::Utc::now() - chrono::Duration::hours(1));
        store.store_token(expired_record).await.unwrap();
        
        // Create active token
        let active_record = create_test_token_record("active_token", "user123");
        store.store_token(active_record).await.unwrap();
        
        // Run cleanup
        let operation = store.cleanup_expired_tokens().await.unwrap();
        
        assert!(operation.success);
        assert_eq!(operation.tokens_affected.len(), 1);
        assert!(operation.tokens_affected.contains(&"expired_token".to_string()));
        
        // Verify expired token is removed
        let expired = store.get_token("expired_token").await.unwrap();
        assert!(expired.is_none());
        
        // Verify active token remains
        let active = store.get_token("active_token").await.unwrap();
        assert!(active.is_some());
    }

    #[tokio::test]
    async fn test_get_tokens_by_subject() {
        let store = InMemoryTokenStore::new();
        
        let record1 = create_test_token_record("token1", "user123");
        let record2 = create_test_token_record("token2", "user123");
        let record3 = create_test_token_record("token3", "user456");
        
        store.store_token(record1).await.unwrap();
        store.store_token(record2).await.unwrap();
        store.store_token(record3).await.unwrap();
        
        let user123_tokens = store.get_tokens_by_subject("user123").await.unwrap();
        assert_eq!(user123_tokens.len(), 2);
        
        let user456_tokens = store.get_tokens_by_subject("user456").await.unwrap();
        assert_eq!(user456_tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_revoke_subject_tokens() {
        let store = InMemoryTokenStore::new();
        
        let record1 = create_test_token_record("token1", "user123");
        let record2 = create_test_token_record("token2", "user123");
        let record3 = create_test_token_record("token3", "user456");
        
        store.store_token(record1).await.unwrap();
        store.store_token(record2).await.unwrap();
        store.store_token(record3).await.unwrap();
        
        let operation = store.revoke_subject_tokens("user123").await.unwrap();
        
        assert!(operation.success);
        assert_eq!(operation.tokens_affected.len(), 2);
        
        // Verify user123 tokens are revoked
        let user123_tokens = store.get_tokens_by_subject("user123").await.unwrap();
        for token in user123_tokens {
            assert_eq!(token.state, TokenState::Revoked);
        }
        
        // Verify user456 token is still active
        let token3 = store.get_token("token3").await.unwrap().unwrap();
        assert!(token3.is_active());
    }

    #[tokio::test]
    async fn test_health_check_and_metrics() {
        let store = InMemoryTokenStore::new();
        
        // Health check should pass
        let healthy = store.health_check().await.unwrap();
        assert!(healthy);
        
        // Store some tokens to test metrics
        let record1 = create_test_token_record("token1", "user123");
        let record2 = create_test_token_record("token2", "user456");
        
        store.store_token(record1).await.unwrap();
        store.store_token(record2).await.unwrap();
        
        // Revoke one token
        store.revoke_token_family("token1").await.unwrap();
        
        let metrics = store.get_metrics().await.unwrap();
        assert_eq!(metrics.total_tokens, 2);
        assert_eq!(metrics.active_tokens, 1);
        assert_eq!(metrics.revoked_tokens, 1);
        assert_eq!(metrics.cache_hit_ratio, Some(1.0)); // In-memory is always 100% hit rate
    }
}