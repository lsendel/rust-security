//! Database Connections
//!
//! Unified connection factory and management

use super::config::UnifiedDatabaseConfig;
use super::error::{DatabaseError, DatabaseResult};
use redis::Client as RedisClient;
use std::sync::Arc;

/// Database connections container
pub struct DatabaseConnections {
    /// PostgreSQL connection string
    postgres_url: Option<String>,
    
    /// Redis client
    redis_client: Option<Arc<RedisClient>>,
    
    /// Configuration reference
    config: UnifiedDatabaseConfig,
}

impl DatabaseConnections {
    /// Create new database connections
    pub fn new(config: UnifiedDatabaseConfig) -> Self {
        Self {
            postgres_url: None,
            redis_client: None,
            config,
        }
    }
    
    /// Get PostgreSQL connection URL
    pub fn postgres_url(&self) -> Option<&str> {
        self.postgres_url.as_deref()
    }
    
    /// Get Redis client
    pub fn redis_client(&self) -> Option<&RedisClient> {
        self.redis_client.as_deref()
    }
    
    /// Get configuration
    pub fn config(&self) -> &UnifiedDatabaseConfig {
        &self.config
    }
}

/// Connection factory for creating database connections
pub struct ConnectionFactory {
    config: UnifiedDatabaseConfig,
}

impl ConnectionFactory {
    /// Create new connection factory
    pub fn new(config: &UnifiedDatabaseConfig) -> DatabaseResult<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }
    
    /// Create all configured database connections
    pub async fn create_connections(&self) -> DatabaseResult<DatabaseConnections> {
        let mut connections = DatabaseConnections::new(self.config.clone());
        
        // Create PostgreSQL connection
        if let Some(pg_config) = self.config.postgres_config() {
            connections.postgres_url = Some(pg_config.url.clone());
        }
        
        // Create Redis connection
        if let Some(redis_config) = self.config.redis_config() {
            let client = self.create_redis_client(redis_config).await?;
            connections.redis_client = Some(Arc::new(client));
        }
        
        Ok(connections)
    }
    
    /// Create Redis client
    async fn create_redis_client(&self, redis_config: &crate::redis_config::UnifiedRedisConfig) -> DatabaseResult<RedisClient> {
        let client = RedisClient::open(redis_config.url.as_str())
            .map_err(|e| DatabaseError::ConnectionError(format!("Redis connection failed: {}", e)))?;
        
        // Test the connection
        let mut conn = client.get_multiplexed_async_connection().await
            .map_err(|e| DatabaseError::ConnectionError(format!("Redis connection test failed: {}", e)))?;
        
        // Use INFO command to verify connection
        let _: String = redis::cmd("INFO").query_async(&mut conn).await
            .map_err(|e| DatabaseError::ConnectionError(format!("Redis info failed: {}", e)))?;
        
        Ok(client)
    }
    
    /// Test all connections
    pub async fn test_connections(&self) -> DatabaseResult<ConnectionTestResults> {
        let mut results = ConnectionTestResults::default();
        
        // Test PostgreSQL connection
        if let Some(pg_config) = self.config.postgres_config() {
            match self.test_postgres_connection(pg_config).await {
                Ok(_) => results.postgres_success = true,
                Err(e) => {
                    results.postgres_success = false;
                    results.postgres_error = Some(e.to_string());
                }
            }
        }
        
        // Test Redis connection
        if let Some(redis_config) = self.config.redis_config() {
            match self.test_redis_connection(redis_config).await {
                Ok(_) => results.redis_success = true,
                Err(e) => {
                    results.redis_success = false;
                    results.redis_error = Some(e.to_string());
                }
            }
        }
        
        Ok(results)
    }
    
    /// Test PostgreSQL connection
    async fn test_postgres_connection(&self, pg_config: &super::config::PostgresConfig) -> DatabaseResult<()> {
        use sqlx::postgres::PgConnectOptions;
        use sqlx::{Connection, PgConnection};
        
        let connect_options: PgConnectOptions = pg_config.url.parse()
            .map_err(|e| DatabaseError::ConnectionError(format!("Invalid PostgreSQL URL: {}", e)))?;
        
        let mut conn = PgConnection::connect_with(&connect_options).await
            .map_err(|e| DatabaseError::ConnectionError(format!("PostgreSQL connection failed: {}", e)))?;
        
        // Test query
        sqlx::query("SELECT 1").execute(&mut conn).await
            .map_err(|e| DatabaseError::ConnectionError(format!("PostgreSQL test query failed: {}", e)))?;
        
        Ok(())
    }
    
    /// Test Redis connection
    async fn test_redis_connection(&self, redis_config: &crate::redis_config::UnifiedRedisConfig) -> DatabaseResult<()> {
        let client = RedisClient::open(redis_config.url.as_str())
            .map_err(|e| DatabaseError::ConnectionError(format!("Redis client creation failed: {}", e)))?;
        
        let mut conn = client.get_multiplexed_async_connection().await
            .map_err(|e| DatabaseError::ConnectionError(format!("Redis connection failed: {}", e)))?;
        
        // Test with INFO command
        let _: String = redis::cmd("INFO").query_async(&mut conn).await
            .map_err(|e| DatabaseError::ConnectionError(format!("Redis info failed: {}", e)))?;
        
        Ok(())
    }
    
    /// Get connection health status
    pub async fn health_status(&self) -> DatabaseResult<ConnectionHealth> {
        let mut health = ConnectionHealth::default();
        
        // Check PostgreSQL
        if let Some(pg_config) = self.config.postgres_config() {
            health.postgres_configured = true;
            health.postgres_healthy = self.test_postgres_connection(pg_config).await.is_ok();
        }
        
        // Check Redis
        if let Some(redis_config) = self.config.redis_config() {
            health.redis_configured = true;
            health.redis_healthy = self.test_redis_connection(redis_config).await.is_ok();
        }
        
        Ok(health)
    }
}

/// Connection test results
#[derive(Debug, Default)]
pub struct ConnectionTestResults {
    pub postgres_success: bool,
    pub postgres_error: Option<String>,
    pub redis_success: bool,
    pub redis_error: Option<String>,
}

impl ConnectionTestResults {
    /// Check if all configured connections are successful
    pub fn all_successful(&self) -> bool {
        (!self.postgres_configured() || self.postgres_success) &&
        (!self.redis_configured() || self.redis_success)
    }
    
    /// Check if PostgreSQL is configured
    pub fn postgres_configured(&self) -> bool {
        self.postgres_success || self.postgres_error.is_some()
    }
    
    /// Check if Redis is configured
    pub fn redis_configured(&self) -> bool {
        self.redis_success || self.redis_error.is_some()
    }
    
    /// Get summary of results
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        
        if self.postgres_configured() {
            if self.postgres_success {
                parts.push("PostgreSQL: OK".to_string());
            } else {
                parts.push(format!("PostgreSQL: FAILED ({})", 
                    self.postgres_error.as_ref().unwrap_or(&"Unknown error".to_string())));
            }
        }
        
        if self.redis_configured() {
            if self.redis_success {
                parts.push("Redis: OK".to_string());
            } else {
                parts.push(format!("Redis: FAILED ({})", 
                    self.redis_error.as_ref().unwrap_or(&"Unknown error".to_string())));
            }
        }
        
        if parts.is_empty() {
            "No databases configured".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Connection health status
#[derive(Debug, Default)]
pub struct ConnectionHealth {
    pub postgres_configured: bool,
    pub postgres_healthy: bool,
    pub redis_configured: bool,
    pub redis_healthy: bool,
}

impl ConnectionHealth {
    /// Check if all configured databases are healthy
    pub fn all_healthy(&self) -> bool {
        (!self.postgres_configured || self.postgres_healthy) &&
        (!self.redis_configured || self.redis_healthy)
    }
    
    /// Get unhealthy databases
    pub fn unhealthy_databases(&self) -> Vec<&str> {
        let mut unhealthy = Vec::new();
        
        if self.postgres_configured && !self.postgres_healthy {
            unhealthy.push("PostgreSQL");
        }
        
        if self.redis_configured && !self.redis_healthy {
            unhealthy.push("Redis");
        }
        
        unhealthy
    }
}