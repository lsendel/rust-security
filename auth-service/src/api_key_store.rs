use sqlx::{migrate::MigrateDatabase, Sqlite, SqlitePool};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiKeyError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("API key not found")]
    NotFound,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiKey {
    pub id: i64,
    pub hashed_key: String,
    pub prefix: String,
    pub client_id: String,
    pub permissions: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: String,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ApiKeyDetails {
    pub id: i64,
    pub prefix: String,
    pub client_id: String,
    pub permissions: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: String,
}


#[derive(Clone)]
pub struct ApiKeyStore {
    pool: SqlitePool,
}

impl ApiKeyStore {
    pub async fn new(database_url: &str) -> Result<Self, ApiKeyError> {
        if !Sqlite::database_exists(database_url).await.unwrap_or(false) {
            Sqlite::create_database(database_url).await?;
        }

        let pool = SqlitePool::connect(database_url).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self { pool })
    }

    pub async fn create_api_key(
        &self,
        client_id: &str,
        prefix: &str,
        hashed_key: &str,
        permissions: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<ApiKey, ApiKeyError> {
        let api_key = sqlx::query_as!(
            ApiKey,
            r#"
            INSERT INTO api_keys (client_id, prefix, hashed_key, permissions, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
            client_id,
            prefix,
            hashed_key,
            permissions,
            expires_at,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(api_key)
    }

    pub async fn get_api_key_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, ApiKeyError> {
        let api_key = sqlx::query_as!(
            ApiKey,
            r#"
            SELECT * FROM api_keys WHERE prefix = $1
            "#,
            prefix,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(api_key)
    }

    pub async fn list_api_keys(&self) -> Result<Vec<ApiKeyDetails>, ApiKeyError> {
        let keys = sqlx::query_as!(
            ApiKeyDetails,
            r#"
            SELECT id, prefix, client_id, permissions, created_at, expires_at, last_used_at, status
            FROM api_keys
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(keys)
    }

    pub async fn revoke_api_key(&self, prefix: &str) -> Result<(), ApiKeyError> {
        let result = sqlx::query!(
            r#"
            UPDATE api_keys
            SET status = 'revoked'
            WHERE prefix = $1
            "#,
            prefix,
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(ApiKeyError::NotFound);
        }

        Ok(())
    }

    pub async fn update_last_used(&self, key_id: i64) -> Result<(), ApiKeyError> {
        sqlx::query!(
            r#"
            UPDATE api_keys
            SET last_used_at = $1
            WHERE id = $2
            "#,
            chrono::Utc::now(),
            key_id,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_store() -> ApiKeyStore {
        ApiKeyStore::new("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn test_create_and_get_api_key() {
        let store = setup_store().await;
        let client_id = "test_client";
        let prefix = "test_";
        let hashed_key = "hashed_key";
        let permissions = Some("read,write");

        let created_key = store.create_api_key(client_id, prefix, hashed_key, permissions, None).await.unwrap();
        assert_eq!(created_key.client_id, client_id);
        assert_eq!(created_key.prefix, prefix);

        let fetched_key = store.get_api_key_by_prefix(prefix).await.unwrap().unwrap();
        assert_eq!(fetched_key.id, created_key.id);
        assert_eq!(fetched_key.client_id, client_id);
    }

    #[tokio::test]
    async fn test_list_api_keys() {
        let store = setup_store().await;
        store.create_api_key("client1", "prefix1_", "hash1", None, None).await.unwrap();
        store.create_api_key("client2", "prefix2_", "hash2", None, None).await.unwrap();

        let keys = store.list_api_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn test_revoke_api_key() {
        let store = setup_store().await;
        let prefix = "revoke_";
        store.create_api_key("client", prefix, "hash", None, None).await.unwrap();

        store.revoke_api_key(prefix).await.unwrap();

        let key = store.get_api_key_by_prefix(prefix).await.unwrap().unwrap();
        assert_eq!(key.status, "revoked");
    }

    #[tokio::test]
    async fn test_update_last_used() {
        let store = setup_store().await;
        let key = store.create_api_key("client", "last_used_", "hash", None, None).await.unwrap();
        assert!(key.last_used_at.is_none());

        store.update_last_used(key.id).await.unwrap();

        let updated_key = store.get_api_key_by_prefix("last_used_").await.unwrap().unwrap();
        assert!(updated_key.last_used_at.is_some());
    }
}
