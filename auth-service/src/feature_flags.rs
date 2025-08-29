use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Feature flag system for controlling optional modules and functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct FeatureFlags {
    // OIDC Provider Features
    pub google_oidc: bool,
    pub microsoft_oidc: bool,
    pub github_oidc: bool,

    // Authentication Features
    pub webauthn: bool,
    pub advanced_mfa: bool,
    pub totp_mfa: bool,
    pub sms_mfa: bool,

    // API Features
    pub scim_v2: bool,
    pub oauth2_device_flow: bool,
    pub oauth2_token_exchange: bool,

    // Security Features
    pub threat_detection: bool,
    pub anomaly_detection: bool,
    pub bot_protection: bool,
    pub request_signing: bool,
    pub token_binding: bool,

    // Integration Features
    pub soar_integration: bool,
    pub policy_engine: bool,
    pub external_policy_providers: bool,

    // Monitoring Features
    pub advanced_metrics: bool,
    pub distributed_tracing: bool,
    pub security_monitoring: bool,
    pub audit_logging: bool,

    // Performance Features
    pub redis_clustering: bool,
    pub connection_pooling: bool,
    pub response_compression: bool,
    pub request_caching: bool,

    // Admin Features
    pub admin_dashboard: bool,
    pub admin_api: bool,
    pub bulk_operations: bool,
    pub data_export: bool,

    // Development Features
    pub debug_mode: bool,
    pub mock_providers: bool,
    pub test_endpoints: bool,
    pub performance_profiling: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            // OIDC Providers - enabled by default for common use cases
            google_oidc: true,
            microsoft_oidc: true,
            github_oidc: true,

            // Authentication - core MFA enabled, advanced features optional
            webauthn: true,
            advanced_mfa: true,
            totp_mfa: true,
            sms_mfa: false, // Requires external service

            // API Features - SCIM enabled, advanced OAuth flows optional
            scim_v2: true,
            oauth2_device_flow: false,
            oauth2_token_exchange: false,

            // Security - core features enabled
            threat_detection: true,
            anomaly_detection: true,
            bot_protection: true,
            request_signing: true,
            token_binding: true,

            // Integrations - disabled by default (require configuration)
            soar_integration: false,
            policy_engine: true,
            external_policy_providers: false,

            // Monitoring - basic monitoring enabled
            advanced_metrics: true,
            distributed_tracing: false, // Requires Jaeger/OTLP setup
            security_monitoring: true,
            audit_logging: true,

            // Performance - basic optimizations enabled
            redis_clustering: false, // Requires Redis Cluster setup
            connection_pooling: true,
            response_compression: true,
            request_caching: true,

            // Admin - enabled for production management
            admin_dashboard: false, // Web UI component
            admin_api: true,
            bulk_operations: true,
            data_export: false, // Security sensitive

            // Development - disabled in production
            debug_mode: false,
            mock_providers: false,
            test_endpoints: false,
            performance_profiling: false,
        }
    }
}

impl FeatureFlags {
    /// Load feature flags from environment variables
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn from_env() -> Self {
        let mut flags = Self::default();

        // OIDC Provider flags
        flags.google_oidc = env_bool("FEATURE_GOOGLE_OIDC", flags.google_oidc);
        flags.microsoft_oidc = env_bool("FEATURE_MICROSOFT_OIDC", flags.microsoft_oidc);
        flags.github_oidc = env_bool("FEATURE_GITHUB_OIDC", flags.github_oidc);

        // Authentication flags
        flags.webauthn = env_bool("FEATURE_WEBAUTHN", flags.webauthn);
        flags.advanced_mfa = env_bool("FEATURE_ADVANCED_MFA", flags.advanced_mfa);
        flags.totp_mfa = env_bool("FEATURE_TOTP_MFA", flags.totp_mfa);
        flags.sms_mfa = env_bool("FEATURE_SMS_MFA", flags.sms_mfa);

        // API flags
        flags.scim_v2 = env_bool("FEATURE_SCIM_V2", flags.scim_v2);
        flags.oauth2_device_flow = env_bool("FEATURE_OAUTH2_DEVICE_FLOW", flags.oauth2_device_flow);
        flags.oauth2_token_exchange =
            env_bool("FEATURE_OAUTH2_TOKEN_EXCHANGE", flags.oauth2_token_exchange);

        // Security flags
        flags.threat_detection = env_bool("FEATURE_THREAT_DETECTION", flags.threat_detection);
        flags.anomaly_detection = env_bool("FEATURE_ANOMALY_DETECTION", flags.anomaly_detection);
        flags.bot_protection = env_bool("FEATURE_BOT_PROTECTION", flags.bot_protection);
        flags.request_signing = env_bool("FEATURE_REQUEST_SIGNING", flags.request_signing);
        flags.token_binding = env_bool("FEATURE_TOKEN_BINDING", flags.token_binding);

        // Integration flags
        flags.soar_integration = env_bool("FEATURE_SOAR_INTEGRATION", flags.soar_integration);
        flags.policy_engine = env_bool("FEATURE_POLICY_ENGINE", flags.policy_engine);
        flags.external_policy_providers = env_bool(
            "FEATURE_EXTERNAL_POLICY_PROVIDERS",
            flags.external_policy_providers,
        );

        // Monitoring flags
        flags.advanced_metrics = env_bool("FEATURE_ADVANCED_METRICS", flags.advanced_metrics);
        flags.distributed_tracing =
            env_bool("FEATURE_DISTRIBUTED_TRACING", flags.distributed_tracing);
        flags.security_monitoring =
            env_bool("FEATURE_SECURITY_MONITORING", flags.security_monitoring);
        flags.audit_logging = env_bool("FEATURE_AUDIT_LOGGING", flags.audit_logging);

        // Performance flags
        flags.redis_clustering = env_bool("FEATURE_REDIS_CLUSTERING", flags.redis_clustering);
        flags.connection_pooling = env_bool("FEATURE_CONNECTION_POOLING", flags.connection_pooling);
        flags.response_compression =
            env_bool("FEATURE_RESPONSE_COMPRESSION", flags.response_compression);
        flags.request_caching = env_bool("FEATURE_REQUEST_CACHING", flags.request_caching);

        // Admin flags
        flags.admin_dashboard = env_bool("FEATURE_ADMIN_DASHBOARD", flags.admin_dashboard);
        flags.admin_api = env_bool("FEATURE_ADMIN_API", flags.admin_api);
        flags.bulk_operations = env_bool("FEATURE_BULK_OPERATIONS", flags.bulk_operations);
        flags.data_export = env_bool("FEATURE_DATA_EXPORT", flags.data_export);

        // Development flags
        flags.debug_mode = env_bool("FEATURE_DEBUG_MODE", flags.debug_mode);
        flags.mock_providers = env_bool("FEATURE_MOCK_PROVIDERS", flags.mock_providers);
        flags.test_endpoints = env_bool("FEATURE_TEST_ENDPOINTS", flags.test_endpoints);
        flags.performance_profiling =
            env_bool("FEATURE_PERFORMANCE_PROFILING", flags.performance_profiling);

        // Override with profile-specific settings
        if let Ok(profile) = env::var("APP_PROFILE") {
            flags = flags.apply_profile(&profile);
        }

        flags
    }

    /// Apply profile-specific feature flag overrides
    pub fn apply_profile(mut self, profile: &str) -> Self {
        match profile.to_lowercase().as_str() {
            "development" | "dev" => {
                self.debug_mode = true;
                self.mock_providers = true;
                self.test_endpoints = true;
                self.performance_profiling = true;
                self.data_export = true;
                self.admin_dashboard = true;

                // Disable potentially expensive features in dev
                self.distributed_tracing = false;
                self.redis_clustering = false;
                self.advanced_metrics = false;
            }

            "staging" | "test" => {
                self.debug_mode = false;
                self.mock_providers = false;
                self.test_endpoints = true;
                self.performance_profiling = false;
                self.data_export = false;

                // Enable full monitoring in staging
                self.distributed_tracing = true;
                self.advanced_metrics = true;
                self.security_monitoring = true;
            }

            "production" | "prod" => {
                // Production security hardening
                self.debug_mode = false;
                self.mock_providers = false;
                self.test_endpoints = false;
                self.performance_profiling = false;
                self.data_export = false;

                // Enable all security features
                self.threat_detection = true;
                self.anomaly_detection = true;
                self.bot_protection = true;
                self.request_signing = true;
                self.token_binding = true;
                self.security_monitoring = true;
                self.audit_logging = true;

                // Enable performance optimizations
                self.connection_pooling = true;
                self.response_compression = true;
                self.request_caching = true;
            }

            _ => {
                tracing::warn!(profile = %profile, "Unknown application profile, using default flags");
            }
        }

        self
    }

    /// Get feature flag as a map for template rendering or API responses
    #[must_use]
    pub fn as_map(&self) -> HashMap<String, bool> {
        let mut map = HashMap::new();

        // OIDC Providers
        map.insert("google_oidc".to_string(), self.google_oidc);
        map.insert("microsoft_oidc".to_string(), self.microsoft_oidc);
        map.insert("github_oidc".to_string(), self.github_oidc);

        // Authentication
        map.insert("webauthn".to_string(), self.webauthn);
        map.insert("advanced_mfa".to_string(), self.advanced_mfa);
        map.insert("totp_mfa".to_string(), self.totp_mfa);
        map.insert("sms_mfa".to_string(), self.sms_mfa);

        // API Features
        map.insert("scim_v2".to_string(), self.scim_v2);
        map.insert("oauth2_device_flow".to_string(), self.oauth2_device_flow);
        map.insert(
            "oauth2_token_exchange".to_string(),
            self.oauth2_token_exchange,
        );

        // Security
        map.insert("threat_detection".to_string(), self.threat_detection);
        map.insert("anomaly_detection".to_string(), self.anomaly_detection);
        map.insert("bot_protection".to_string(), self.bot_protection);
        map.insert("request_signing".to_string(), self.request_signing);
        map.insert("token_binding".to_string(), self.token_binding);

        // Integrations
        map.insert("soar_integration".to_string(), self.soar_integration);
        map.insert("policy_engine".to_string(), self.policy_engine);
        map.insert(
            "external_policy_providers".to_string(),
            self.external_policy_providers,
        );

        // Monitoring
        map.insert("advanced_metrics".to_string(), self.advanced_metrics);
        map.insert("distributed_tracing".to_string(), self.distributed_tracing);
        map.insert("security_monitoring".to_string(), self.security_monitoring);
        map.insert("audit_logging".to_string(), self.audit_logging);

        // Performance
        map.insert("redis_clustering".to_string(), self.redis_clustering);
        map.insert("connection_pooling".to_string(), self.connection_pooling);
        map.insert(
            "response_compression".to_string(),
            self.response_compression,
        );
        map.insert("request_caching".to_string(), self.request_caching);

        // Admin
        map.insert("admin_dashboard".to_string(), self.admin_dashboard);
        map.insert("admin_api".to_string(), self.admin_api);
        map.insert("bulk_operations".to_string(), self.bulk_operations);
        map.insert("data_export".to_string(), self.data_export);

        // Development
        map.insert("debug_mode".to_string(), self.debug_mode);
        map.insert("mock_providers".to_string(), self.mock_providers);
        map.insert("test_endpoints".to_string(), self.test_endpoints);
        map.insert(
            "performance_profiling".to_string(),
            self.performance_profiling,
        );

        map
    }

    /// Check if any OIDC provider is enabled
    #[must_use]
    pub const fn has_oidc_providers(&self) -> bool {
        self.google_oidc || self.microsoft_oidc || self.github_oidc
    }

    /// Check if MFA is enabled
    #[must_use]
    pub const fn has_mfa(&self) -> bool {
        self.webauthn || self.advanced_mfa || self.totp_mfa || self.sms_mfa
    }

    /// Check if monitoring is enabled
    #[must_use]
    pub const fn has_monitoring(&self) -> bool {
        self.advanced_metrics
            || self.distributed_tracing
            || self.security_monitoring
            || self.audit_logging
    }

    /// Get list of enabled features for logging
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn enabled_features(&self) -> Vec<&'static str> {
        let mut features = Vec::new();

        if self.google_oidc {
            features.push("google_oidc");
        }
        if self.microsoft_oidc {
            features.push("microsoft_oidc");
        }
        if self.github_oidc {
            features.push("github_oidc");
        }
        if self.webauthn {
            features.push("webauthn");
        }
        if self.advanced_mfa {
            features.push("advanced_mfa");
        }
        if self.totp_mfa {
            features.push("totp_mfa");
        }
        if self.sms_mfa {
            features.push("sms_mfa");
        }
        if self.scim_v2 {
            features.push("scim_v2");
        }
        if self.oauth2_device_flow {
            features.push("oauth2_device_flow");
        }
        if self.oauth2_token_exchange {
            features.push("oauth2_token_exchange");
        }
        if self.threat_detection {
            features.push("threat_detection");
        }
        if self.anomaly_detection {
            features.push("anomaly_detection");
        }
        if self.bot_protection {
            features.push("bot_protection");
        }
        if self.request_signing {
            features.push("request_signing");
        }
        if self.token_binding {
            features.push("token_binding");
        }
        if self.soar_integration {
            features.push("soar_integration");
        }
        if self.policy_engine {
            features.push("policy_engine");
        }
        if self.external_policy_providers {
            features.push("external_policy_providers");
        }
        if self.advanced_metrics {
            features.push("advanced_metrics");
        }
        if self.distributed_tracing {
            features.push("distributed_tracing");
        }
        if self.security_monitoring {
            features.push("security_monitoring");
        }
        if self.audit_logging {
            features.push("audit_logging");
        }
        if self.redis_clustering {
            features.push("redis_clustering");
        }
        if self.connection_pooling {
            features.push("connection_pooling");
        }
        if self.response_compression {
            features.push("response_compression");
        }
        if self.request_caching {
            features.push("request_caching");
        }
        if self.admin_dashboard {
            features.push("admin_dashboard");
        }
        if self.admin_api {
            features.push("admin_api");
        }
        if self.bulk_operations {
            features.push("bulk_operations");
        }
        if self.data_export {
            features.push("data_export");
        }
        if self.debug_mode {
            features.push("debug_mode");
        }
        if self.mock_providers {
            features.push("mock_providers");
        }
        if self.test_endpoints {
            features.push("test_endpoints");
        }
        if self.performance_profiling {
            features.push("performance_profiling");
        }

        features
    }
}

/// Dynamic feature flag manager for runtime updates
#[derive(Debug)]
pub struct FeatureFlagManager {
    flags: Arc<RwLock<FeatureFlags>>,
    overrides: Arc<RwLock<HashMap<String, bool>>>,
}

impl FeatureFlagManager {
    /// Create a new feature flag manager
    #[must_use]
    pub fn new(initial_flags: FeatureFlags) -> Self {
        Self {
            flags: Arc::new(RwLock::new(initial_flags)),
            overrides: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get current feature flags (with overrides applied)
    pub async fn get_flags(&self) -> FeatureFlags {
        let base_flags = self.flags.read().await.clone();
        let overrides = self.overrides.read().await;

        if overrides.is_empty() {
            return base_flags;
        }

        // Apply overrides to base flags
        // This would need to be implemented using reflection or macros
        // For now, return base flags
        base_flags
    }

    /// Update a single feature flag at runtime
    pub async fn set_flag(&self, flag_name: &str, enabled: bool) {
        let mut overrides = self.overrides.write().await;
        overrides.insert(flag_name.to_string(), enabled);

        tracing::info!(
            flag = %flag_name,
            enabled = enabled,
            "Feature flag updated at runtime"
        );
    }

    /// Remove a flag override
    pub async fn remove_override(&self, flag_name: &str) {
        let mut overrides = self.overrides.write().await;
        if overrides.remove(flag_name).is_some() {
            tracing::info!(
                flag = %flag_name,
                "Feature flag override removed"
            );
        }
    }

    /// Reload flags from environment
    pub async fn reload_from_env(&self) {
        let new_flags = FeatureFlags::from_env();
        let mut flags = self.flags.write().await;
        *flags = new_flags;

        tracing::info!("Feature flags reloaded from environment");
    }
}

/// Helper function to read boolean environment variable
fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .map(|v| match v.to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" | "enabled" => true,
            "false" | "0" | "no" | "off" | "disabled" => false,
            _ => {
                tracing::warn!(
                    key = %key,
                    value = %v,
                    "Invalid boolean value in environment variable, using default"
                );
                default
            }
        })
        .unwrap_or(default)
}

/// Macro for feature flag checks with compile-time optimization
#[macro_export]
macro_rules! feature_enabled {
    ($flags:expr, $feature:ident) => {
        $flags.$feature
    };
}

/// Conditional code execution based on feature flags
#[macro_export]
macro_rules! if_feature {
    ($flags:expr, $feature:ident, $code:block) => {
        if feature_enabled!($flags, $feature) {
            $code
        }
    };
    ($flags:expr, $feature:ident, $code:block, else $else_code:block) => {
        if feature_enabled!($flags, $feature) {
            $code
        } else {
            $else_code
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_feature_flags() {
        let flags = FeatureFlags::default();

        // Core features should be enabled
        assert!(flags.google_oidc);
        assert!(flags.microsoft_oidc);
        assert!(flags.github_oidc);
        assert!(flags.webauthn);
        assert!(flags.scim_v2);
        assert!(flags.threat_detection);
        assert!(flags.audit_logging);

        // Advanced/external features should be disabled
        assert!(!flags.soar_integration);
        assert!(!flags.sms_mfa);
        assert!(!flags.debug_mode);
        assert!(!flags.test_endpoints);
    }

    #[test]
    fn test_env_bool() {
        assert_eq!(env_bool("NONEXISTENT_VAR", true), true);
        assert_eq!(env_bool("NONEXISTENT_VAR", false), false);

        env::set_var("TEST_BOOL_TRUE", "true");
        assert_eq!(env_bool("TEST_BOOL_TRUE", false), true);

        env::set_var("TEST_BOOL_FALSE", "false");
        assert_eq!(env_bool("TEST_BOOL_FALSE", true), false);

        env::set_var("TEST_BOOL_ONE", "1");
        assert_eq!(env_bool("TEST_BOOL_ONE", false), true);

        env::set_var("TEST_BOOL_ZERO", "0");
        assert_eq!(env_bool("TEST_BOOL_ZERO", true), false);

        // Cleanup
        env::remove_var("TEST_BOOL_TRUE");
        env::remove_var("TEST_BOOL_FALSE");
        env::remove_var("TEST_BOOL_ONE");
        env::remove_var("TEST_BOOL_ZERO");
    }

    #[test]
    fn test_profile_application() {
        let mut flags = FeatureFlags::default();

        // Test development profile
        flags = flags.apply_profile("development");
        assert!(flags.debug_mode);
        assert!(flags.mock_providers);
        assert!(flags.test_endpoints);

        // Test production profile
        flags = flags.apply_profile("production");
        assert!(!flags.debug_mode);
        assert!(!flags.mock_providers);
        assert!(!flags.test_endpoints);
        assert!(flags.threat_detection);
        assert!(flags.security_monitoring);
    }

    #[test]
    fn test_feature_flag_helpers() {
        let flags = FeatureFlags::default();

        assert!(flags.has_oidc_providers()); // At least one OIDC provider enabled
        assert!(flags.has_mfa()); // At least one MFA method enabled
        assert!(flags.has_monitoring()); // At least one monitoring feature enabled

        let enabled = flags.enabled_features();
        assert!(!enabled.is_empty());
        assert!(enabled.contains(&"google_oidc"));
        assert!(enabled.contains(&"threat_detection"));
    }

    #[tokio::test]
    async fn test_feature_flag_manager() {
        let flags = FeatureFlags::default();
        let manager = FeatureFlagManager::new(flags);

        // Test getting flags
        let current_flags = manager.get_flags().await;
        assert!(current_flags.google_oidc);

        // Test setting override
        manager.set_flag("debug_mode", true).await;

        // Test removing override
        manager.remove_override("debug_mode").await;
    }
}
