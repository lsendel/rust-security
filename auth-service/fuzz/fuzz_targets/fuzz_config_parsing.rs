#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use auth_service::config::AppConfig;
use std::collections::HashMap;

#[derive(Arbitrary, Debug)]
struct ConfigInput {
    bind_addr: String,
    redis_url: String,
    jwt_secret: String,
    token_expiry: u64,
    rate_limit: u32,
    client_id: String,
    client_secret: String,
    scope: String,
}

// Fuzz configuration parsing from environment variables
fuzz_target!(|input: ConfigInput| {
    // Test various configuration scenarios
    let env_vars = vec![
        ("BIND_ADDR", input.bind_addr.as_str()),
        ("REDIS_URL", input.redis_url.as_str()),
        ("JWT_SECRET", input.jwt_secret.as_str()),
        ("TOKEN_EXPIRY_SECONDS", &input.token_expiry.to_string()),
        ("RATE_LIMIT_REQUESTS_PER_MINUTE", &input.rate_limit.to_string()),
        ("CLIENT_CREDENTIALS", &format!("{}:{}", input.client_id, input.client_secret)),
        ("ALLOWED_SCOPES", input.scope.as_str()),
    ];
    
    // Set environment variables temporarily
    for (key, value) in &env_vars {
        std::env::set_var(key, value);
    }
    
    // Try to parse configuration - should handle all values gracefully
    let _ = AppConfig::from_env();
    
    // Clean up environment variables
    for (key, _) in &env_vars {
        std::env::remove_var(key);
    }
});

// Fuzz TOML configuration parsing
fuzz_target!(|data: &[u8]| {
    let toml_str = String::from_utf8_lossy(data);
    
    // Test TOML parsing - should never panic
    let _ = toml::from_str::<AppConfig>(&toml_str);
    let _ = toml::from_str::<serde_json::Value>(&toml_str);
    
    // Test with common TOML structures
    let structured_toml = format!(
        r#"
bind_addr = "{}"
redis_url = "{}"

[security]
jwt_access_token_ttl_seconds = 3600
enforce_pkce = true

[rate_limiting]
requests_per_minute = 60

[features]
mfa_enabled = true
"#,
        toml_str.lines().next().unwrap_or("localhost:8080"),
        toml_str.lines().nth(1).unwrap_or("redis://localhost")
    );
    
    let _ = toml::from_str::<AppConfig>(&structured_toml);
});

// Fuzz JSON configuration parsing
fuzz_target!(|data: &[u8]| {
    let json_str = String::from_utf8_lossy(data);
    
    // Test JSON parsing - should never panic
    let _ = serde_json::from_str::<AppConfig>(&json_str);
    let _ = serde_json::from_str::<serde_json::Value>(&json_str);
    
    // Test with structured JSON
    let base_value = json_str.chars().take(20).collect::<String>();
    let structured_json = serde_json::json!({
        "bind_addr": base_value,
        "redis_url": format!("redis://{}", base_value),
        "security": {
            "jwt_access_token_ttl_seconds": 3600,
            "enforce_pkce": true
        },
        "rate_limiting": {
            "requests_per_minute": 60
        },
        "features": {
            "mfa_enabled": true
        }
    });
    
    let _ = serde_json::from_value::<AppConfig>(structured_json);
});

// Fuzz YAML configuration parsing
fuzz_target!(|data: &[u8]| {
    let yaml_str = String::from_utf8_lossy(data);
    
    // Test YAML parsing - should never panic
    let _ = serde_yaml::from_str::<AppConfig>(&yaml_str);
    let _ = serde_yaml::from_str::<serde_json::Value>(&yaml_str);
    
    // Test with structured YAML
    let base_value = yaml_str.lines().next().unwrap_or("localhost:8080");
    let structured_yaml = format!(
        r#"
bind_addr: "{}"
redis_url: "redis://localhost:6379"
security:
  jwt_access_token_ttl_seconds: 3600
  enforce_pkce: true
rate_limiting:
  requests_per_minute: 60
features:
  mfa_enabled: true
"#,
        base_value
    );
    
    let _ = serde_yaml::from_str::<AppConfig>(&structured_yaml);
});

// Fuzz configuration validation
fuzz_target!(|input: ConfigInput| {
    // Create various invalid configurations to test validation
    let test_configs = vec![
        // Empty bind address
        AppConfig {
            bind_addr: "".to_string(),
            redis_url: Some(input.redis_url.clone()),
            client_credentials: HashMap::from([
                (input.client_id.clone(), input.client_secret.clone())
            ]),
            allowed_scopes: vec![input.scope.clone()],
            jwt_secret: input.jwt_secret.clone(),
            token_expiry_seconds: input.token_expiry,
            rate_limit_requests_per_minute: input.rate_limit,
            ..Default::default()
        },
        
        // Invalid TTL values
        AppConfig {
            bind_addr: input.bind_addr.clone(),
            security: auth_service::config::SecurityConfig {
                jwt_access_token_ttl_seconds: 0, // Invalid
                ..Default::default()
            },
            ..Default::default()
        },
        
        // Empty client credentials
        AppConfig {
            bind_addr: input.bind_addr.clone(),
            client_credentials: HashMap::new(), // Invalid
            ..Default::default()
        },
    ];
    
    for config in test_configs {
        // Test validation - should handle gracefully
        let _ = config.validate();
    }
});

// Fuzz malformed configuration formats
fuzz_target!(|data: &[u8]| {
    let config_str = String::from_utf8_lossy(data);
    
    // Test various malformed formats
    let malformed_configs = vec![
        // Malformed TOML
        format!("[section\n{}", config_str), // Missing bracket
        format!("key = {}", config_str), // Unquoted string value
        format!("= {}", config_str), // Missing key
        format!("{} =", config_str), // Missing value
        
        // Malformed JSON
        format!("{{\"key\": {}}}", config_str), // Invalid JSON value
        format!("{{\"key\": \"{}}\"", config_str), // Unterminated string
        format!("{{{}\"key\": \"value\"}}", config_str), // Invalid start
        format!("{{\"key\": \"value\"{}}}", config_str), // Invalid end
        
        // Malformed YAML
        format!("key: {}", config_str),
        format!("- {}", config_str),
        format!("  {}", config_str), // Invalid indentation start
        format!("{}: {{}}", config_str), // Mixed formats
    ];
    
    for malformed in malformed_configs {
        // These should all fail gracefully without panicking
        let _ = toml::from_str::<AppConfig>(&malformed);
        let _ = serde_json::from_str::<AppConfig>(&malformed);
        let _ = serde_yaml::from_str::<AppConfig>(&malformed);
    }
});

// Fuzz edge cases in configuration values
fuzz_target!(|data: &[u8]| {
    if data.len() >= 8 {
        let text = String::from_utf8_lossy(data);
        
        // Test various edge case values
        let edge_cases = vec![
            // Very long strings
            text.repeat(1000),
            
            // Special characters
            format!("{}!@#$%^&*()[]{{}}|\\:;\"'<>?,./", text),
            
            // Unicode characters
            format!("{}测试🔒Ñiño", text),
            
            // Null and control characters
            format!("{}\0\x01\x02\x03", text),
            
            // Path-like strings
            format!("../../{}", text),
            format!("/etc/passwd{}", text),
            format!("file://{}", text),
            format!("http://{}.evil.com", text),
            
            // SQL injection-like patterns
            format!("{}'; DROP TABLE users; --", text),
            format!("{} OR 1=1", text),
            
            // Script injection patterns
            format!("<script>{}</script>", text),
            format!("javascript:{}", text),
            
            // Environment variable patterns
            format!("${{{}}}", text),
            format!("$ENV[{}]", text),
        ];
        
        for edge_case in edge_cases {
            // Test as environment variable value
            std::env::set_var("TEST_CONFIG_VALUE", &edge_case);
            let _ = std::env::var("TEST_CONFIG_VALUE");
            std::env::remove_var("TEST_CONFIG_VALUE");
            
            // Test in various config formats
            let toml_config = format!("bind_addr = \"{}\"", edge_case.replace('"', "\\\""));
            let _ = toml::from_str::<serde_json::Value>(&toml_config);
            
            let json_config = serde_json::json!({"bind_addr": edge_case});
            let _ = serde_json::to_string(&json_config);
            
            let yaml_config = format!("bind_addr: \"{}\"", edge_case.replace('"', "\\\""));
            let _ = serde_yaml::from_str::<serde_json::Value>(&yaml_config);
        }
    }
});

// Fuzz configuration file loading simulation
fuzz_target!(|data: &[u8]| {
    let file_content = String::from_utf8_lossy(data);
    
    // Simulate loading different file types based on content
    let file_types = vec![
        ("config.toml", &file_content),
        ("config.json", &file_content),
        ("config.yaml", &file_content),
        ("config.yml", &file_content),
    ];
    
    for (filename, content) in file_types {
        // Test file type detection and parsing
        if filename.ends_with(".toml") {
            let _ = toml::from_str::<AppConfig>(content);
        } else if filename.ends_with(".json") {
            let _ = serde_json::from_str::<AppConfig>(content);
        } else if filename.ends_with(".yaml") || filename.ends_with(".yml") {
            let _ = serde_yaml::from_str::<AppConfig>(content);
        }
    }
});

// Implement Default for AppConfig for testing
impl Default for auth_service::config::AppConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".to_string(),
            redis_url: None,
            oidc_providers: auth_service::config::OidcProviders {
                google: None,
                microsoft: None,
                github: None,
            },
            security: auth_service::config::SecurityConfig::default(),
            rate_limiting: auth_service::config::RateLimitConfig::default(),
            monitoring: auth_service::config::MonitoringConfig::default(),
            features: auth_service::config::FeatureFlags::default(),
            oauth: auth_service::config::OAuthConfig::default(),
            scim: auth_service::config::ScimConfig::default(),
            store: auth_service::config::StoreConfig::default(),
            client_credentials: HashMap::new(),
            allowed_scopes: vec!["read".to_string()],
            jwt_secret: "test-secret".to_string(),
            token_expiry_seconds: 3600,
            rate_limit_requests_per_minute: 60,
        }
    }
}

// Default implementations for config structs
impl Default for auth_service::config::SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_access_token_ttl_seconds: 3600,
            jwt_refresh_token_ttl_seconds: 86400,
            rsa_key_size: 2048,
            enforce_pkce: true,
            require_state: true,
            max_token_binding_age_seconds: 300,
            token_binding_required: false,
            allowed_cors_origins: vec![],
            request_signature_required: false,
            request_signature_max_age_seconds: 300,
        }
    }
}

impl Default for auth_service::config::RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            burst_size: 10,
            per_ip_limit: Some(100),
            per_client_limit: Some(1000),
            cleanup_interval_seconds: 60,
        }
    }
}

impl Default for auth_service::config::MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            tracing_enabled: true,
            health_check_interval_seconds: 30,
            jaeger_endpoint: None,
        }
    }
}

impl Default for auth_service::config::FeatureFlags {
    fn default() -> Self {
        Self {
            mfa_enabled: false,
            scim_enabled: false,
            oidc_enabled: false,
            advanced_logging: false,
            performance_monitoring: false,
            threat_hunting: false,
            soar_integration: false,
        }
    }
}

impl Default for auth_service::config::OAuthConfig {
    fn default() -> Self {
        Self {
            authorization_code_ttl_seconds: 600,
            device_code_ttl_seconds: 600,
            pkce_required: true,
            refresh_token_rotation: true,
        }
    }
}

impl Default for auth_service::config::ScimConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:8080/scim/v2".to_string(),
            max_results: 100,
            case_exact: false,
        }
    }
}

impl Default for auth_service::config::StoreConfig {
    fn default() -> Self {
        Self {
            backend: auth_service::config::StoreBackend::Hybrid,
            connection_pool_size: 10,
            connection_timeout_seconds: 30,
            max_idle_connections: 5,
            database_url: None,
        }
    }
}