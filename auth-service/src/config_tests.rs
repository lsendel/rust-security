#[cfg(test)]
mod tests {
    use crate::config_static::*;
    use std::env;

    #[test]
    fn test_environment_detection() {
        // Test production environment
        env::set_var("ENVIRONMENT", "production");
        assert_eq!(Environment::from_env(), Environment::Production);
        assert!(Environment::from_env().is_production());

        // Test development environment
        env::set_var("ENVIRONMENT", "development");
        assert_eq!(Environment::from_env(), Environment::Development);
        assert!(Environment::from_env().is_development());

        // Test staging environment
        env::set_var("ENVIRONMENT", "staging");
        assert_eq!(Environment::from_env(), Environment::Staging);

        // Test testing environment
        env::set_var("ENVIRONMENT", "testing");
        assert_eq!(Environment::from_env(), Environment::Testing);

        // Test default environment
        env::remove_var("ENVIRONMENT");
        assert_eq!(Environment::from_env(), Environment::Development);
    }

    #[test]
    fn test_static_config_loading() {
        env::set_var("ENVIRONMENT", "development");

        let config = &CONFIG;

        // Test server configuration
        assert!(!config.server.bind_addr.is_empty());
        assert!(!config.server.cors_allowed_origins.is_empty());
        assert!(config.server.request_body_limit_mb > 0);

        // Test security configuration
        assert!(!config.security.jwt_issuer.is_empty());
        assert!(!config.security.jwt_audience.is_empty());
        assert!(config.security.token_expiry_seconds > 0);
        assert!(!config.security.allowed_scopes.is_empty());

        // Test client configuration
        assert!(!config.clients.default_clients.is_empty());

        // Test OAuth configuration
        assert!(config.oauth.authorization_code_ttl_seconds > 0);
        assert!(!config.oauth.allowed_redirect_schemes.is_empty());
    }

    #[test]
    fn test_config_manager_initialization() {
        env::set_var("ENVIRONMENT", "testing");
        // Don't set JWT_SIGNING_KEY to test auto-generation in non-prod
        env::remove_var("JWT_SIGNING_KEY");

        let config_manager = ConfigManager::new();
        assert!(config_manager.is_ok());

        let manager = config_manager.unwrap();
        assert_eq!(manager.environment, Environment::Testing);
        assert!(!manager.runtime_secrets.jwt_signing_key.is_empty());
    }

    #[test]
    fn test_client_credential_validation() {
        env::set_var("ENVIRONMENT", "development");
        env::remove_var("JWT_SIGNING_KEY");

        let manager = ConfigManager::new().unwrap();

        // Test valid client credentials
        assert!(manager.validate_client_credentials("dev-client", "dev-secret"));

        // Test invalid client credentials
        assert!(!manager.validate_client_credentials("dev-client", "wrong-secret"));
        assert!(!manager.validate_client_credentials("nonexistent-client", "any-secret"));
    }

    #[test]
    fn test_feature_flags() {
        env::set_var("ENVIRONMENT", "development");
        env::remove_var("JWT_SIGNING_KEY");

        let manager = ConfigManager::new().unwrap();

        // Test development features
        assert!(manager.is_feature_enabled("oidc_google"));
        assert!(manager.is_feature_enabled("oidc_microsoft"));
        assert!(manager.is_feature_enabled("oidc_github"));
        assert!(manager.is_feature_enabled("webauthn"));
        assert!(manager.is_feature_enabled("mfa"));
        assert!(manager.is_feature_enabled("scim"));
        assert!(manager.is_feature_enabled("metrics"));

        // Test unknown feature
        assert!(!manager.is_feature_enabled("unknown_feature"));
    }

    #[test]
    fn test_production_config_security() {
        env::set_var("ENVIRONMENT", "production");

        let config = production_config();

        // Production should have stricter settings
        assert!(config.oauth.enforce_pkce);
        assert!(config.oauth.require_state_parameter);
        assert_eq!(config.oauth.allowed_redirect_schemes, vec!["https"]);

        // Production should not enable GitHub OAuth by default
        assert!(!config.features.enable_oidc_github);

        // Production should have conservative rate limits
        assert!(config.security.rate_limit_requests_per_minute <= 100);
    }

    #[test]
    fn test_development_config_convenience() {
        env::set_var("ENVIRONMENT", "development");

        let config = development_config();

        // Development should allow both HTTP and HTTPS
        assert!(config
            .oauth
            .allowed_redirect_schemes
            .contains(&"http".to_string()));
        assert!(config
            .oauth
            .allowed_redirect_schemes
            .contains(&"https".to_string()));

        // Development should enable all OAuth providers
        assert!(config.features.enable_oidc_github);
        assert!(config.features.enable_oidc_google);
        assert!(config.features.enable_oidc_microsoft);

        // Development should have longer token expiry for convenience
        assert!(config.security.token_expiry_seconds >= 7200); // At least 2 hours

        // Development should have localhost CORS origins
        assert!(config
            .server
            .cors_allowed_origins
            .iter()
            .any(|origin| origin.contains("localhost")));
    }

    #[test]
    fn test_testing_config_optimization() {
        env::set_var("ENVIRONMENT", "testing");

        let config = testing_config();

        // Testing should use random port
        assert!(config.server.bind_addr.contains(":0"));

        // Testing should have permissive CORS
        assert!(config
            .server
            .cors_allowed_origins
            .contains(&"*".to_string()));

        // Testing should have short timeouts
        assert!(config.server.health_check_timeout_seconds <= 5);

        // Testing should have high rate limits
        assert!(config.security.rate_limit_requests_per_minute >= 1000);

        // Testing should not require PKCE for simplicity
        assert!(!config.oauth.enforce_pkce);
    }

    #[test]
    fn test_client_info_structure() {
        let config = development_config();
        let clients = &config.clients.default_clients;

        for (client_id, client_info) in clients {
            // All clients should have proper structure
            assert!(!client_id.is_empty(), "Client ID should not be empty");
            assert!(
                !client_info.name.is_empty(),
                "Client name should not be empty"
            );
            assert!(
                client_info.secret_hash.starts_with("$2b$"),
                "Secret should be bcrypt hash"
            );
            assert!(!client_info.scopes.is_empty(), "Client should have scopes");
            assert!(
                !client_info.redirect_uris.is_empty(),
                "Client should have redirect URIs"
            );
            assert!(
                !client_info.grant_types.is_empty(),
                "Client should have grant types"
            );

            // Validate redirect URIs
            for uri in &client_info.redirect_uris {
                assert!(
                    uri.starts_with("http://") || uri.starts_with("https://"),
                    "Redirect URI should be HTTP or HTTPS: {}",
                    uri
                );
            }
        }
    }

    #[test]
    fn test_jwt_key_strength_validation() {
        // Test weak key rejection in production
        env::set_var("ENVIRONMENT", "production");
        env::set_var("JWT_SIGNING_KEY", "weak");

        let result = RuntimeSecrets::from_env();
        assert!(
            result.is_err(),
            "Weak JWT key should be rejected in production"
        );

        // Test strong key acceptance
        env::set_var(
            "JWT_SIGNING_KEY",
            "this-is-a-very-strong-cryptographic-key-that-meets-requirements",
        );
        let result = RuntimeSecrets::from_env();
        assert!(result.is_ok(), "Strong JWT key should be accepted");

        // Test development auto-generation
        env::set_var("ENVIRONMENT", "development");
        env::remove_var("JWT_SIGNING_KEY");

        let result = RuntimeSecrets::from_env();
        assert!(result.is_ok(), "Development should auto-generate JWT key");

        let secrets = result.unwrap();
        assert!(
            !secrets.jwt_signing_key.is_empty(),
            "Auto-generated key should not be empty"
        );
        assert!(
            secrets.jwt_signing_key.len() >= 32,
            "Auto-generated key should be at least 32 chars"
        );
    }

    #[test]
    fn test_environment_specific_security_policies() {
        // Production should have the strictest policies
        env::set_var("ENVIRONMENT", "production");
        let prod_config = production_config();

        // Staging should be similar to production but slightly relaxed
        env::set_var("ENVIRONMENT", "staging");
        let staging_config = staging_config();

        // Development should be most permissive
        env::set_var("ENVIRONMENT", "development");
        let dev_config = development_config();

        // Compare token expiry (production should be shortest)
        assert!(
            prod_config.security.token_expiry_seconds
                <= staging_config.security.token_expiry_seconds
        );
        assert!(
            staging_config.security.token_expiry_seconds
                <= dev_config.security.token_expiry_seconds
        );

        // Compare rate limits (production should be most restrictive)
        assert!(
            prod_config.security.rate_limit_requests_per_minute
                <= dev_config.security.rate_limit_requests_per_minute
        );

        // Production should not allow HTTP redirects
        assert!(!prod_config
            .oauth
            .allowed_redirect_schemes
            .contains(&"http".to_string()));

        // Development should allow HTTP redirects
        assert!(dev_config
            .oauth
            .allowed_redirect_schemes
            .contains(&"http".to_string()));
    }

    #[test]
    fn test_config_validation_ranges() {
        let config = development_config();

        // Test that numeric values are within reasonable ranges
        assert!(config.security.token_expiry_seconds >= 300); // At least 5 minutes
        assert!(config.security.token_expiry_seconds <= 86400 * 30); // At most 30 days

        assert!(config.security.rate_limit_requests_per_minute >= 1);
        assert!(config.security.rate_limit_requests_per_minute <= 10000);

        assert!(config.oauth.authorization_code_ttl_seconds >= 60); // At least 1 minute
        assert!(config.oauth.authorization_code_ttl_seconds <= 3600); // At most 1 hour

        assert!(config.server.request_body_limit_mb >= 1);
        assert!(config.server.request_body_limit_mb <= 100);
    }
}
