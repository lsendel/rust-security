use crate::repository::{DbError, InMemoryUserRepository, UserRepository};
use std::sync::Arc;

#[cfg(any(feature = "sqlite", feature = "postgres"))]
use crate::repository::{PostgresUserRepository, SqliteUserRepository};

#[cfg(any(feature = "sqlite", feature = "postgres"))]
use sqlx::{migrate::MigrateDatabase, AnyPool, Postgres, Sqlite};

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self { url: "sqlite::memory:".to_string(), max_connections: 10 }
    }
}

/// Database connection manager
pub struct Database {
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pool: Option<AnyPool>,
    repository: Arc<dyn UserRepository>,
}

impl Database {
    /// Create a new in-memory database (for development/testing)
    pub fn new_in_memory() -> Self {
        Self {
            #[cfg(any(feature = "sqlite", feature = "postgres"))]
            pool: None,
            repository: Arc::new(InMemoryUserRepository::new()),
        }
    }

    #[cfg(feature = "sqlite")]
    /// Create a new SQLite database connection
    pub async fn new_sqlite(config: DatabaseConfig) -> Result<Self, DbError> {
        // Normalize in-memory URL to a named shared in-memory DB so multiple connections share state
        let normalized_url = if config.url.contains(":memory:") {
            // Use a named shared in-memory database per sqlite docs
            "sqlite:file:memdb?mode=memory&cache=shared".to_string()
        } else {
            config.url.clone()
        };

        // Skip creation checks for in-memory SQLite URLs
        if !normalized_url.contains(":memory:") {
            // Create database if it doesn't exist (file-based SQLite)
            if !Sqlite::database_exists(&normalized_url).await.unwrap_or(false) {
                Sqlite::create_database(&normalized_url)
                    .await
                    .map_err(|e| DbError::Connection(e.to_string()))?;
            }
        }

        let sqlite_pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&normalized_url)
            .await
            .map_err(|e| DbError::Connection(e.to_string()))?;

        // Run migrations (SQLite-compatible migrations only)
        sqlx::migrate!("./migrations_sqlite")
            .run(&sqlite_pool)
            .await
            .map_err(|e| DbError::Connection(format!("Migration failed: {}", e)))?;

        Ok(Self { pool: None, repository: Arc::new(SqliteUserRepository::new(sqlite_pool)) })
    }

    #[cfg(feature = "postgres")]
    /// Create a new PostgreSQL database connection
    pub async fn new_postgres(config: DatabaseConfig) -> Result<Self, DbError> {
        // Create database if it doesn't exist
        if !Postgres::database_exists(&config.url).await.unwrap_or(false) {
            Postgres::create_database(&config.url)
                .await
                .map_err(|e| DbError::Connection(e.to_string()))?;
        }

        let pg_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&config.url)
            .await
            .map_err(|e| DbError::Connection(e.to_string()))?;

        // Run migrations (PostgreSQL-specific migrations)
        sqlx::migrate!("./migrations_postgres")
            .run(&pg_pool)
            .await
            .map_err(|e| DbError::Connection(format!("Migration failed: {}", e)))?;

        Ok(Self { pool: None, repository: Arc::new(PostgresUserRepository::new(pg_pool)) })
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    /// Create database from URL (auto-detect type)
    pub async fn from_url(url: &str) -> Result<Self, DbError> {
        let config = DatabaseConfig { url: url.to_string(), max_connections: 10 };

        if url.starts_with("sqlite:") {
            #[cfg(feature = "sqlite")]
            return Self::new_sqlite(config).await;
            #[cfg(not(feature = "sqlite"))]
            return Err(DbError::Connection("SQLite support not enabled".to_string()));
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            #[cfg(feature = "postgres")]
            return Self::new_postgres(config).await;
            #[cfg(not(feature = "postgres"))]
            return Err(DbError::Connection("PostgreSQL support not enabled".to_string()));
        } else {
            Err(DbError::Connection(format!("Unsupported database URL: {}", url)))
        }
    }

    /// Get the user repository
    pub fn user_repository(&self) -> Arc<dyn UserRepository> {
        self.repository.clone()
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    /// Get the database pool (if available)
    pub fn pool(&self) -> Option<&AnyPool> {
        self.pool.as_ref()
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    /// Close the database connection
    pub async fn close(&self) {
        if let Some(pool) = &self.pool {
            pool.close().await;
        }
    }
}

/// Initialize database from environment variables
pub async fn init_database() -> Result<Database, DbError> {
    if let Ok(database_url) = std::env::var("DATABASE_URL") {
        #[cfg(any(feature = "sqlite", feature = "postgres"))]
        {
            Database::from_url(&database_url).await
        }
        #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
        {
            tracing::warn!(
                "DATABASE_URL provided but no database features enabled, using in-memory storage"
            );
            Ok(Database::new_in_memory())
        }
    } else {
        tracing::info!("No DATABASE_URL provided, using in-memory storage");
        Ok(Database::new_in_memory())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_database() {
        let db = Database::new_in_memory();
        let repo = db.user_repository();

        // Test that we can get the repository
        assert!(repo.count().await.is_ok());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn test_sqlite_database() {
        let config = DatabaseConfig { url: "sqlite::memory:".to_string(), max_connections: 5 };

        let db = Database::new_sqlite(config).await;
        assert!(db.is_ok());

        let db = db.unwrap();
        let repo = db.user_repository();

        // Test basic operations
        assert!(repo.count().await.is_ok());
    }
}
