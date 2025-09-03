//! Tests for the configuration module.

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_config_loader_initialization() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test.toml");

        // Create a minimal config file
        let config_content = r#"
            [server]
            host = "127.0.0.1"
            port = 8080
            bind_addr = "127.0.0.1:8080"
            max_connections = 1000
            request_timeout = "30s"
            shutdown_timeout = "30s"

            [database]
            url = "sqlite::memory:"

            [redis]
            url = "redis://localhost:6379"
            pool_size = 10
            connection_timeout = "5s"
            command_timeout = "1s"

            [jwt]
            secret = "test-jwt-secret-minimum-32-characters-long-for-security"
            algorithm = "HS256"
        "#;

        fs::write(&config_path, config_content).unwrap();

        let loader = ConfigLoader::new(config_path.to_str().unwrap().to_string());
        let result = loader.load().await;

        assert!(result.is_ok(), "Config loading should succeed");

        let config = loader.get_config().await;
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.database.url, "sqlite::memory:");
        assert_eq!(config.redis.url, "redis://localhost:6379");
    }

    #[tokio::test]
    async fn test_config_validation() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("invalid.toml");

        // Create config with validation errors
        let config_content = r#"
            [server]
            host = ""
            port = 0
            bind_addr = "invalid"
            max_connections = 1000
            request_timeout = "30s"
            shutdown_timeout = "30s"

            [database]
            url = ""

            [jwt]
            secret = "short"
            algorithm = "INVALID"
        "#;

        fs::write(&config_path, config_content).unwrap();

        let loader = ConfigLoader::new(config_path.to_str().unwrap().to_string());
        let result = loader.load().await;

        assert!(
            result.is_err(),
            "Config loading should fail due to validation errors"
        );
    }

    #[tokio::test]
    async fn test_config_with_environment_overrides() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("env.toml");

        let config_content = r#"
            [server]
            host = "127.0.0.1"
            port = 8080
        "#;

        fs::write(&config_path, config_content).unwrap();

        // Set environment variable
        std::env::set_var("AUTH_SERVER__PORT", "9090");

        let loader = ConfigLoader::new(config_path.to_str().unwrap().to_string());
        let result = loader.load().await;

        assert!(result.is_ok());

        let config = loader.get_config().await;
        assert_eq!(config.server.port, 9090); // Should be overridden by env var

        // Clean up
        std::env::remove_var("AUTH_SERVER__PORT");
    }

    #[tokio::test]
    async fn test_config_getters() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("getters.toml");

        let config_content = r#"
            [server]
            host = "127.0.0.1"
            port = 8080

            [database]
            url = "sqlite::memory:"

            [redis]
            url = "redis://localhost:6379"

            [jwt]
            secret = "test-jwt-secret-minimum-32-characters-long-for-security"
            algorithm = "HS256"
        "#;

        fs::write(&config_path, config_content).unwrap();

        let loader = ConfigLoader::new(config_path.to_str().unwrap().to_string());
        loader.load().await.unwrap();

        let server_config = loader.get_server_config().await;
        let db_config = loader.get_database_config().await;
        let redis_config = loader.get_redis_config().await;
        let jwt_config = loader.get_jwt_config().await;

        assert_eq!(server_config.host, "127.0.0.1");
        assert_eq!(server_config.port, 8080);
        assert_eq!(db_config.url, "sqlite::memory:");
        assert_eq!(redis_config.url, "redis://localhost:6379");
        assert_eq!(jwt_config.algorithm, "HS256");
    }

    #[test]
    fn test_config_value_retrieval() {
        let loader = ConfigLoader::new("nonexistent.toml");

        // Test with default config
        let port = loader.get_config_value("server.port");
        assert_eq!(port, Some("8080".to_string()));

        let host = loader.get_config_value("server.host");
        assert_eq!(host, Some("127.0.0.1".to_string()));

        let invalid = loader.get_config_value("nonexistent.key");
        assert_eq!(invalid, None);
    }

    #[test]
    fn test_default_service_config() {
        let config = ServiceConfig::default();

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.database.url, "sqlite::memory:");
        assert_eq!(config.redis.url, "redis://localhost:6379");
        assert!(config.features.mfa_enabled);
        assert!(config.monitoring.metrics_enabled);
    }
}
