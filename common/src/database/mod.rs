//! Unified Database Operations Module
//!
//! This module consolidates all database operations to eliminate duplication across
//! the rust-security codebase. It provides unified connection management, repository
//! patterns, and storage abstractions for PostgreSQL, Redis, and other databases.

pub mod connections;
pub mod config;
pub mod pools;
pub mod repositories;
pub mod migrations;
pub mod error;

// Re-export main types for convenience
pub use config::{DatabaseConfig, UnifiedDatabaseConfig, PoolConfig};
pub use connections::{DatabaseConnections, ConnectionFactory};
pub use error::{DatabaseError, DatabaseResult};
pub use pools::{DatabasePools, PoolManager};
pub use repositories::{Repository, RepositoryManager};

/// Database operations manager that coordinates all database-related functionality
pub struct DatabaseOperations {
    config: UnifiedDatabaseConfig,
    connections: DatabaseConnections,
    pools: DatabasePools,
    repositories: RepositoryManager,
}

impl DatabaseOperations {
    /// Create new database operations instance
    pub async fn new(config: UnifiedDatabaseConfig) -> DatabaseResult<Self> {
        // Initialize connection factory
        let connection_factory = ConnectionFactory::new(&config)?;
        
        // Create connections
        let connections = connection_factory.create_connections().await?;
        
        // Initialize pools
        let pools = DatabasePools::new(&config, &connections).await?;
        
        // Create repositories
        let repositories = RepositoryManager::new(&pools);
        
        Ok(Self {
            config,
            connections,
            pools,
            repositories,
        })
    }
    
    /// Get database pools
    pub fn pools(&self) -> &DatabasePools {
        &self.pools
    }
    
    /// Get repository manager
    pub fn repositories(&self) -> &RepositoryManager {
        &self.repositories
    }
    
    /// Get database connections
    pub fn connections(&self) -> &DatabaseConnections {
        &self.connections
    }
    
    /// Get configuration
    pub fn config(&self) -> &UnifiedDatabaseConfig {
        &self.config
    }
    
    /// Health check for all database connections
    pub async fn health_check(&self) -> DatabaseResult<()> {
        // Delegate to pools for proper separation of concerns
        let health_status = self.pools.health_check().await?;
        
        if !health_status.postgres_healthy && self.pools.postgresql().is_some() {
            return Err(DatabaseError::ConnectionError(
                health_status.postgres_error.unwrap_or_else(|| "PostgreSQL health check failed".to_string())
            ));
        }
        
        if !health_status.redis_healthy && self.pools.redis().is_some() {
            return Err(DatabaseError::ConnectionError(
                health_status.redis_error.unwrap_or_else(|| "Redis health check failed".to_string())
            ));
        }
        
        Ok(())
    }
    
    /// Run database migrations
    pub async fn run_migrations(&self) -> DatabaseResult<()> {
        if let Some(_pg_pool) = self.pools.postgresql() {
            // TODO: Implement embedded migrations without external directory
            // For now, just log that migration would run
            tracing::info!("Migrations would run here when implemented");
        }
        Ok(())
    }
}

/// Builder for database operations
pub struct DatabaseOperationsBuilder {
    config: Option<UnifiedDatabaseConfig>,
    enable_migrations: bool,
    enable_health_checks: bool,
}

impl DatabaseOperationsBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            config: None,
            enable_migrations: false,
            enable_health_checks: true,
        }
    }
    
    /// Set configuration
    pub fn with_config(mut self, config: UnifiedDatabaseConfig) -> Self {
        self.config = Some(config);
        self
    }
    
    /// Enable migrations
    pub fn with_migrations(mut self) -> Self {
        self.enable_migrations = true;
        self
    }
    
    /// Enable health checks
    pub fn with_health_checks(mut self, enabled: bool) -> Self {
        self.enable_health_checks = enabled;
        self
    }
    
    /// Build database operations
    pub async fn build(self) -> DatabaseResult<DatabaseOperations> {
        let config = self.config.ok_or_else(|| {
            DatabaseError::ConfigurationError("Database configuration is required".to_string())
        })?;
        
        let ops = DatabaseOperations::new(config).await?;
        
        if self.enable_migrations {
            ops.run_migrations().await?;
        }
        
        if self.enable_health_checks {
            ops.health_check().await?;
        }
        
        Ok(ops)
    }
}

impl Default for DatabaseOperationsBuilder {
    fn default() -> Self {
        Self::new()
    }
}