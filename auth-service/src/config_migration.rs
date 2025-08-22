use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::config::AppConfig;
use crate::config_static::{ConfigManager, Environment};

/// Migration helper to transition from .env-based config to static Rust config
#[derive(Debug)]
pub struct ConfigMigration {
    pub legacy_config: Option<AppConfig>,
    pub static_config_manager: ConfigManager,
    pub migration_warnings: Vec<String>,
}

/// Migration report showing differences and recommendations
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationReport {
    pub environment: String,
    pub legacy_config_found: bool,
    pub differences: Vec<ConfigDifference>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigDifference {
    pub field: String,
    pub legacy_value: Option<String>,
    pub static_value: String,
    pub impact: String,
}

impl ConfigMigration {
    /// Create a new migration instance
    pub fn new() -> Result<Self> {
        let static_config_manager = ConfigManager::new()?;

        // Try to load legacy config
        let legacy_config = match AppConfig::from_env() {
            Ok(config) => {
                info!("Legacy configuration loaded successfully");
                Some(config)
            }
            Err(e) => {
                warn!("Could not load legacy configuration: {}", e);
                None
            }
        };

        Ok(ConfigMigration {
            legacy_config,
            static_config_manager,
            migration_warnings: Vec::new(),
        })
    }

    /// Generate a comprehensive migration report
    pub fn generate_report(&mut self) -> MigrationReport {
        let environment = format!("{:?}", self.static_config_manager.environment);
        let legacy_config_found = self.legacy_config.is_some();

        let mut differences = Vec::new();
        let mut warnings = Vec::new();
        let mut recommendations = Vec::new();

        if let Some(legacy_config) = &self.legacy_config {
            // Compare server configuration
            self.compare_server_config(legacy_config, &mut differences);

            // Compare security settings
            self.compare_security_config(legacy_config, &mut differences);

            // Compare client credentials
            self.compare_client_config(legacy_config, &mut differences, &mut warnings);

            // Compare feature flags
            self.compare_feature_config(legacy_config, &mut differences);

            // Generate recommendations
            self.generate_recommendations(&mut recommendations);
        } else {
            recommendations.push(
                "No legacy configuration found. Using static configuration directly.".to_string(),
            );
        }

        // Add migration warnings
        warnings.extend(self.migration_warnings.clone());

        MigrationReport {
            environment,
            legacy_config_found,
            differences,
            warnings,
            recommendations,
        }
    }

    fn compare_server_config(&self, legacy: &AppConfig, differences: &mut Vec<ConfigDifference>) {
        let static_config = self.static_config_manager.static_config;

        // Compare bind address
        if legacy.bind_addr != static_config.server.bind_addr {
            differences.push(ConfigDifference {
                field: "bind_addr".to_string(),
                legacy_value: Some(legacy.bind_addr.clone()),
                static_value: static_config.server.bind_addr.clone(),
                impact: "Server will bind to different address/port".to_string(),
            });
        }
    }

    fn compare_security_config(&self, legacy: &AppConfig, differences: &mut Vec<ConfigDifference>) {
        let static_config = self.static_config_manager.static_config;

        // Compare token expiry
        if legacy.token_expiry_seconds != static_config.security.token_expiry_seconds {
            differences.push(ConfigDifference {
                field: "token_expiry_seconds".to_string(),
                legacy_value: Some(legacy.token_expiry_seconds.to_string()),
                static_value: static_config.security.token_expiry_seconds.to_string(),
                impact: "JWT tokens will have different expiration time".to_string(),
            });
        }

        // Compare rate limiting
        if legacy.rate_limit_requests_per_minute
            != static_config.security.rate_limit_requests_per_minute
        {
            differences.push(ConfigDifference {
                field: "rate_limit_requests_per_minute".to_string(),
                legacy_value: Some(legacy.rate_limit_requests_per_minute.to_string()),
                static_value: static_config
                    .security
                    .rate_limit_requests_per_minute
                    .to_string(),
                impact: "Rate limiting behavior will change".to_string(),
            });
        }

        // Compare allowed scopes
        if legacy.allowed_scopes != static_config.security.allowed_scopes {
            differences.push(ConfigDifference {
                field: "allowed_scopes".to_string(),
                legacy_value: Some(legacy.allowed_scopes.join(",")),
                static_value: static_config.security.allowed_scopes.join(","),
                impact: "Available OAuth scopes will change".to_string(),
            });
        }
    }

    fn compare_client_config(
        &self,
        legacy: &AppConfig,
        differences: &mut Vec<ConfigDifference>,
        warnings: &mut Vec<String>,
    ) {
        let static_config = self.static_config_manager.static_config;

        // Compare number of clients
        let legacy_client_count = legacy.client_credentials.len();
        let static_client_count = static_config.clients.default_clients.len();

        if legacy_client_count != static_client_count {
            differences.push(ConfigDifference {
                field: "client_count".to_string(),
                legacy_value: Some(legacy_client_count.to_string()),
                static_value: static_client_count.to_string(),
                impact: "Number of configured OAuth clients will change".to_string(),
            });
        }

        // Check if legacy clients exist in static config
        for client_id in legacy.client_credentials.keys() {
            if !static_config
                .clients
                .default_clients
                .contains_key(client_id)
            {
                warnings.push(format!(
                    "Legacy client '{}' not found in static configuration",
                    client_id
                ));
            }
        }

        // Check for new clients in static config
        for client_id in static_config.clients.default_clients.keys() {
            if !legacy.client_credentials.contains_key(client_id) {
                differences.push(ConfigDifference {
                    field: format!("new_client_{}", client_id),
                    legacy_value: None,
                    static_value: format!("New client: {}", client_id),
                    impact: "New OAuth client will be available".to_string(),
                });
            }
        }
    }

    fn compare_feature_config(&self, _legacy: &AppConfig, differences: &mut Vec<ConfigDifference>) {
        let _static_config = self.static_config_manager.static_config;

        // Compare feature flags (legacy config doesn't have detailed feature flags, so we note the changes)
        differences.push(ConfigDifference {
            field: "feature_flags".to_string(),
            legacy_value: Some("Not explicitly configured".to_string()),
            static_value: "Explicitly configured: OIDC providers, WebAuthn, MFA, etc.".to_string(),
            impact: "Feature availability will be explicitly controlled".to_string(),
        });
    }

    fn generate_recommendations(&self, recommendations: &mut Vec<String>) {
        let env = self.static_config_manager.environment;

        match env {
            Environment::Production => {
                recommendations.push(
                    "✅ Production environment detected - using secure static configuration"
                        .to_string(),
                );
                recommendations.push(
                    "🔐 Ensure JWT_SIGNING_KEY environment variable is set with a strong key"
                        .to_string(),
                );
                recommendations
                    .push("🔒 Review client credentials and update production secrets".to_string());
                recommendations
                    .push("📊 Enable monitoring and audit logging in production".to_string());
            }
            Environment::Staging => {
                recommendations.push("🔧 Staging environment - configuration is production-like with testing accommodations".to_string());
                recommendations
                    .push("🌐 HTTP redirect URIs are allowed for testing purposes".to_string());
            }
            Environment::Development => {
                recommendations.push(
                    "🚀 Development environment - permissive settings for developer productivity"
                        .to_string(),
                );
                recommendations
                    .push("🔑 JWT key will be auto-generated if not provided".to_string());
                recommendations.push("🌐 CORS is configured for local development".to_string());
            }
            Environment::Testing => {
                recommendations
                    .push("🧪 Testing environment - optimized for automated tests".to_string());
                recommendations.push("⚡ Rate limits are high for test performance".to_string());
                recommendations
                    .push("🔓 Authentication requirements are relaxed for testing".to_string());
            }
        }

        recommendations.push(
            "📋 Remove .env files after migration to ensure static configuration is used"
                .to_string(),
        );
        recommendations.push(
            "🔄 Update deployment scripts to set only required environment variables".to_string(),
        );
        recommendations
            .push("📖 Update documentation to reflect new configuration approach".to_string());
    }

    /// Validate that the migration is safe to perform
    pub fn validate_migration(&mut self) -> Result<Vec<String>> {
        let mut validation_errors = Vec::new();

        // Check runtime secrets
        if self.static_config_manager.environment.is_production()
            && self
                .static_config_manager
                .runtime_secrets
                .jwt_signing_key
                .is_empty()
        {
            validation_errors.push("JWT_SIGNING_KEY is required in production".to_string());
        }

        // Check client configurations
        for (client_id, client_info) in &self
            .static_config_manager
            .static_config
            .clients
            .default_clients
        {
            if client_info.secret_hash.starts_with("$2b$12$placeholder") {
                validation_errors.push(format!(
                    "Client '{}' has placeholder hash - update with real bcrypt hash",
                    client_id
                ));
            }
        }

        // Check OIDC configurations
        if self
            .static_config_manager
            .static_config
            .features
            .enable_oidc_google
            && self
                .static_config_manager
                .runtime_secrets
                .oidc_google_client_secret
                .is_none()
        {
            self.migration_warnings.push(
                "Google OIDC is enabled but OIDC_GOOGLE_CLIENT_SECRET is not set".to_string(),
            );
        }

        if self
            .static_config_manager
            .static_config
            .features
            .enable_oidc_microsoft
            && self
                .static_config_manager
                .runtime_secrets
                .oidc_microsoft_client_secret
                .is_none()
        {
            self.migration_warnings.push(
                "Microsoft OIDC is enabled but OIDC_MICROSOFT_CLIENT_SECRET is not set".to_string(),
            );
        }

        Ok(validation_errors)
    }

    /// Generate environment variable documentation for the new system
    pub fn generate_env_documentation(&self) -> String {
        let env = self.static_config_manager.environment;
        let mut doc = String::new();

        doc.push_str(&format!(
            "# Environment Variables for {:?} Environment\n\n",
            env
        ));
        doc.push_str("After migrating to static configuration, only these environment variables are needed:\n\n");
        doc.push_str("## Required Variables\n");
        doc.push_str(
            "- `JWT_SIGNING_KEY`: JWT signing key (32+ characters, cryptographically secure)\n",
        );

        doc.push_str("\n## Optional Variables\n");
        doc.push_str("- `DATABASE_URL`: Database connection string (if using SQL store)\n");
        doc.push_str("- `REDIS_URL`: Redis connection string (for caching/sessions)\n");

        if self
            .static_config_manager
            .static_config
            .features
            .enable_oidc_google
        {
            doc.push_str("- `OIDC_GOOGLE_CLIENT_SECRET`: Google OAuth client secret\n");
        }

        if self
            .static_config_manager
            .static_config
            .features
            .enable_oidc_microsoft
        {
            doc.push_str("- `OIDC_MICROSOFT_CLIENT_SECRET`: Microsoft OAuth client secret\n");
        }

        if self
            .static_config_manager
            .static_config
            .features
            .enable_oidc_github
        {
            doc.push_str("- `OIDC_GITHUB_CLIENT_SECRET`: GitHub OAuth client secret\n");
        }

        doc.push_str("- `WEBHOOK_SIGNING_SECRET`: Secret for webhook signature validation\n");

        doc.push_str("\n## Removed Variables\n");
        doc.push_str("The following variables are no longer needed (now hardcoded in Rust):\n");
        doc.push_str("- `BIND_ADDR` (now in static config per environment)\n");
        doc.push_str("- `CLIENT_CREDENTIALS` (now in static config)\n");
        doc.push_str("- `ALLOWED_SCOPES` (now in static config)\n");
        doc.push_str("- `JWT_ISSUER` (now in static config)\n");
        doc.push_str("- `JWT_AUDIENCE` (now in static config)\n");
        doc.push_str("- `TOKEN_EXPIRY_SECONDS` (now in static config)\n");
        doc.push_str("- `RATE_LIMIT_REQUESTS_PER_MINUTE` (now in static config)\n");
        doc.push_str("- `CORS_ALLOWED_ORIGINS` (now in static config)\n");
        doc.push_str("- `REQUEST_BODY_LIMIT_MB` (now in static config)\n");
        doc.push_str("- `HEALTH_CHECK_TIMEOUT_SECONDS` (now in static config)\n");

        doc.push_str("\n## Environment Detection\n");
        doc.push_str(
            "Set `ENVIRONMENT` to one of: `development`, `testing`, `staging`, `production`\n",
        );
        doc.push_str(&format!("Current environment: {:?}\n", env));

        doc
    }
}

/// CLI utility to perform configuration migration
pub fn run_migration() -> Result<()> {
    info!("Starting configuration migration...");

    let mut migration = ConfigMigration::new()?;

    // Validate migration
    let validation_errors = migration.validate_migration()?;
    if !validation_errors.is_empty() {
        error!("Migration validation failed:");
        for error in &validation_errors {
            error!("  ❌ {}", error);
        }
        return Err(anyhow::anyhow!(
            "Migration validation failed with {} errors",
            validation_errors.len()
        ));
    }

    // Generate report
    let report = migration.generate_report();

    info!("=== Configuration Migration Report ===");
    info!("Environment: {}", report.environment);
    info!("Legacy config found: {}", report.legacy_config_found);
    info!("Differences found: {}", report.differences.len());
    info!("Warnings: {}", report.warnings.len());

    // Print differences
    if !report.differences.is_empty() {
        info!("\n📋 Configuration Differences:");
        for diff in &report.differences {
            info!(
                "  • {}: {} → {} ({})",
                diff.field,
                diff.legacy_value.as_deref().unwrap_or("N/A"),
                diff.static_value,
                diff.impact
            );
        }
    }

    // Print warnings
    if !report.warnings.is_empty() {
        warn!("\n⚠️  Migration Warnings:");
        for warning in &report.warnings {
            warn!("  • {}", warning);
        }
    }

    // Print recommendations
    info!("\n💡 Recommendations:");
    for rec in &report.recommendations {
        info!("  {}", rec);
    }

    // Generate documentation
    let env_doc = migration.generate_env_documentation();
    info!("\n📖 Environment Variables Documentation:\n{}", env_doc);

    info!("✅ Configuration migration analysis complete!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_creation() {
        let migration = ConfigMigration::new();
        assert!(migration.is_ok());
    }

    #[test]
    fn test_report_generation() {
        if let Ok(mut migration) = ConfigMigration::new() {
            let report = migration.generate_report();
            assert!(!report.environment.is_empty());
        }
    }

    #[test]
    fn test_validation() {
        if let Ok(mut migration) = ConfigMigration::new() {
            let validation_result = migration.validate_migration();
            assert!(validation_result.is_ok());
        }
    }
}
