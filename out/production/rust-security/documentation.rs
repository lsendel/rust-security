//! OpenAPI documentation generation and management

use crate::ApiVersion;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OpenAPI documentation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiConfig {
    /// API title
    pub title: String,
    /// API description
    pub description: String,
    /// Terms of service URL
    pub terms_of_service: Option<String>,
    /// Contact information
    pub contact: Option<ContactInfo>,
    /// License information
    pub license: Option<LicenseInfo>,
    /// Server configurations
    pub servers: Vec<ServerInfo>,
    /// Security schemes
    pub security_schemes: HashMap<String, SecurityScheme>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    pub name: String,
    pub email: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub name: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub url: String,
    pub description: String,
    pub variables: Option<HashMap<String, ServerVariable>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerVariable {
    pub default: String,
    pub description: Option<String>,
    pub enum_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SecurityScheme {
    Http {
        scheme: String,
        bearer_format: Option<String>,
    },
    ApiKey {
        name: String,
        location: ApiKeyLocation,
    },
    OAuth2 {
        flows: Box<OAuth2Flows>,
    },
    OpenIdConnect {
        open_id_connect_url: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiKeyLocation {
    Query,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Flows {
    pub authorization_code: Option<OAuth2Flow>,
    pub client_credentials: Option<OAuth2Flow>,
    pub implicit: Option<OAuth2Flow>,
    pub password: Option<OAuth2Flow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Flow {
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub refresh_url: Option<String>,
    pub scopes: HashMap<String, String>,
}

/// Documentation manager for handling versioned APIs
#[derive(Debug, Clone)]
pub struct DocumentationManager {
    configs: HashMap<ApiVersion, OpenApiConfig>,
    default_config: OpenApiConfig,
}

impl DocumentationManager {
    /// Create a new documentation manager
    pub fn new(default_config: OpenApiConfig) -> Self {
        Self {
            configs: HashMap::new(),
            default_config,
        }
    }

    /// Add version-specific configuration
    pub fn add_version_config(&mut self, version: ApiVersion, config: OpenApiConfig) {
        self.configs.insert(version, config);
    }

    /// Get configuration for version
    pub fn get_config(&self, version: &ApiVersion) -> &OpenApiConfig {
        self.configs.get(version).unwrap_or(&self.default_config)
    }

    /// Generate OpenAPI specification for version
    #[cfg(feature = "openapi")]
    pub fn generate_openapi_spec(&self, version: &ApiVersion) -> utoipa::openapi::OpenApi {
        let config = self.get_config(version);

        let mut openapi = utoipa::openapi::OpenApiBuilder::new().info(
            utoipa::openapi::InfoBuilder::new()
                .title(&config.title)
                .description(Some(&config.description))
                .version(version.to_string())
                .build(),
        );

        // Add servers
        for server in &config.servers {
            openapi = openapi.servers(Some(vec![utoipa::openapi::ServerBuilder::new()
                .url(&server.url)
                .description(Some(&server.description))
                .build()]));
        }

        openapi.build()
    }

    /// Generate API documentation in markdown format
    pub fn generate_markdown_docs(&self, version: &ApiVersion) -> String {
        let config = self.get_config(version);

        let mut docs = String::new();
        docs.push_str(&format!("# {} API Documentation\n\n", config.title));
        docs.push_str(&format!("**Version:** {}\n\n", version));
        docs.push_str(&format!("{}\n\n", config.description));

        // Add servers section
        if !config.servers.is_empty() {
            docs.push_str("## Servers\n\n");
            for server in &config.servers {
                docs.push_str(&format!("- **{}**: {}\n", server.description, server.url));
            }
            docs.push('\n');
        }

        // Add authentication section
        if !config.security_schemes.is_empty() {
            docs.push_str("## Authentication\n\n");
            for (name, scheme) in &config.security_schemes {
                docs.push_str(&format!("### {}\n\n", name));
                match scheme {
                    SecurityScheme::Http {
                        scheme,
                        bearer_format,
                    } => {
                        docs.push_str("- **Type**: HTTP\n");
                        docs.push_str(&format!("- **Scheme**: {}\n", scheme));
                        if let Some(format) = bearer_format {
                            docs.push_str(&format!("- **Bearer Format**: {}\n", format));
                        }
                    }
                    SecurityScheme::ApiKey { name, location } => {
                        docs.push_str("- **Type**: API Key\n");
                        docs.push_str(&format!("- **Name**: {}\n", name));
                        docs.push_str(&format!("- **Location**: {:?}\n", location));
                    }
                    SecurityScheme::OAuth2 { flows: _ } => {
                        docs.push_str("- **Type**: OAuth2\n");
                    }
                    SecurityScheme::OpenIdConnect {
                        open_id_connect_url,
                    } => {
                        docs.push_str("- **Type**: OpenID Connect\n");
                        docs.push_str(&format!("- **URL**: {}\n", open_id_connect_url));
                    }
                }
                docs.push('\n');
            }
        }

        docs
    }
}

/// Default OpenAPI configuration for Rust Security Platform
impl Default for OpenApiConfig {
    fn default() -> Self {
        Self {
            title: "Rust Security Platform API".to_string(),
            description:
                "Production-ready authentication and authorization platform built with Rust"
                    .to_string(),
            terms_of_service: Some("https://rust-security.example.com/terms".to_string()),
            contact: Some(ContactInfo {
                name: "Rust Security Team".to_string(),
                email: "support@rust-security.example.com".to_string(),
                url: Some("https://rust-security.example.com/contact".to_string()),
            }),
            license: Some(LicenseInfo {
                name: "MIT".to_string(),
                url: Some("https://opensource.org/licenses/MIT".to_string()),
            }),
            servers: vec![
                ServerInfo {
                    url: "https://api.rust-security.example.com".to_string(),
                    description: "Production server".to_string(),
                    variables: None,
                },
                ServerInfo {
                    url: "https://staging-api.rust-security.example.com".to_string(),
                    description: "Staging server".to_string(),
                    variables: None,
                },
            ],
            security_schemes: HashMap::from([
                (
                    "bearerAuth".to_string(),
                    SecurityScheme::Http {
                        scheme: "bearer".to_string(),
                        bearer_format: Some("JWT".to_string()),
                    },
                ),
                (
                    "apiKey".to_string(),
                    SecurityScheme::ApiKey {
                        name: "X-API-Key".to_string(),
                        location: ApiKeyLocation::Header,
                    },
                ),
                (
                    "oauth2".to_string(),
                    SecurityScheme::OAuth2 {
                        flows: Box::new(OAuth2Flows {
                            authorization_code: Some(OAuth2Flow {
                                authorization_url: Some(
                                    "https://auth.rust-security.example.com/oauth2/authorize"
                                        .to_string(),
                                ),
                                token_url: Some(
                                    "https://auth.rust-security.example.com/oauth2/token"
                                        .to_string(),
                                ),
                                refresh_url: Some(
                                    "https://auth.rust-security.example.com/oauth2/refresh"
                                        .to_string(),
                                ),
                                scopes: HashMap::from([
                                    ("read".to_string(), "Read access".to_string()),
                                    ("write".to_string(), "Write access".to_string()),
                                    ("admin".to_string(), "Administrative access".to_string()),
                                ]),
                            }),
                            client_credentials: Some(OAuth2Flow {
                                authorization_url: None,
                                token_url: Some(
                                    "https://auth.rust-security.example.com/oauth2/token"
                                        .to_string(),
                                ),
                                refresh_url: None,
                                scopes: HashMap::from([(
                                    "service".to_string(),
                                    "Service-to-service access".to_string(),
                                )]),
                            }),
                            implicit: None,
                            password: None,
                        }),
                    },
                ),
            ]),
        }
    }
}

/// Generate API schema documentation
pub fn generate_schema_docs() -> String {
    let mut docs = String::new();

    docs.push_str("# API Schema Documentation\n\n");
    docs.push_str(
        "This document describes the data schemas used by the Rust Security Platform API.\n\n",
    );

    // Common types
    docs.push_str("## Common Types\n\n");
    docs.push_str("### ApiResponse<T>\n\n");
    docs.push_str("Standard wrapper for all API responses.\n\n");
    docs.push_str("```json\n");
    docs.push_str("{\n");
    docs.push_str("  \"data\": T | null,\n");
    docs.push_str("  \"meta\": {\n");
    docs.push_str("    \"request_id\": \"uuid\",\n");
    docs.push_str("    \"timestamp\": \"iso8601\",\n");
    docs.push_str("    \"processing_time_ms\": number,\n");
    docs.push_str("    \"api_version\": \"string\",\n");
    docs.push_str("    \"pagination\": PaginationMetadata | null,\n");
    docs.push_str("    \"rate_limit\": RateLimitMetadata | null\n");
    docs.push_str("  },\n");
    docs.push_str("  \"error\": ApiErrorDetail | null\n");
    docs.push_str("}\n");
    docs.push_str("```\n\n");

    // Error types
    docs.push_str("### ApiErrorDetail\n\n");
    docs.push_str("Error information for failed requests.\n\n");
    docs.push_str("```json\n");
    docs.push_str("{\n");
    docs.push_str("  \"code\": \"string\",\n");
    docs.push_str("  \"message\": \"string\",\n");
    docs.push_str("  \"details\": object | null,\n");
    docs.push_str("  \"field_errors\": {\n");
    docs.push_str("    \"field_name\": [\"error1\", \"error2\"]\n");
    docs.push_str("  } | null,\n");
    docs.push_str("  \"help_url\": \"string\" | null\n");
    docs.push_str("}\n");
    docs.push_str("```\n\n");

    // Pagination
    docs.push_str("### PaginationMetadata\n\n");
    docs.push_str("Pagination information for list responses.\n\n");
    docs.push_str("```json\n");
    docs.push_str("{\n");
    docs.push_str("  \"page\": number,\n");
    docs.push_str("  \"per_page\": number,\n");
    docs.push_str("  \"total_items\": number,\n");
    docs.push_str("  \"total_pages\": number,\n");
    docs.push_str("  \"has_next\": boolean,\n");
    docs.push_str("  \"has_previous\": boolean\n");
    docs.push_str("}\n");
    docs.push_str("```\n\n");

    docs
}

/// Documentation utilities
pub mod utils {
    use super::*;

    /// Generate endpoint documentation
    pub fn document_endpoint(
        method: &str,
        path: &str,
        description: &str,
        request_schema: Option<&str>,
        response_schema: Option<&str>,
    ) -> String {
        let mut docs = String::new();

        docs.push_str(&format!("### {} {}\n\n", method.to_uppercase(), path));
        docs.push_str(&format!("{}\n\n", description));

        if let Some(request) = request_schema {
            docs.push_str("**Request Schema:**\n\n");
            docs.push_str("```json\n");
            docs.push_str(request);
            docs.push_str("\n```\n\n");
        }

        if let Some(response) = response_schema {
            docs.push_str("**Response Schema:**\n\n");
            docs.push_str("```json\n");
            docs.push_str(response);
            docs.push_str("\n```\n\n");
        }

        docs
    }

    /// Generate deprecation notice
    pub fn generate_deprecation_notice(
        version: &ApiVersion,
        sunset_date: &str,
        migration_guide: Option<&str>,
    ) -> String {
        let mut notice = String::new();

        notice.push_str(&format!(
            "**⚠️ DEPRECATED**: API version {} is deprecated.\n\n",
            version
        ));
        notice.push_str(&format!("**Sunset Date**: {}\n\n", sunset_date));

        if let Some(guide) = migration_guide {
            notice.push_str(&format!("**Migration Guide**: {}\n\n", guide));
        }

        notice.push_str("Please migrate to the latest API version before the sunset date.\n\n");

        notice
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_openapi_config() {
        let config = OpenApiConfig::default();
        assert_eq!(config.title, "Rust Security Platform API");
        assert!(!config.servers.is_empty());
        assert!(!config.security_schemes.is_empty());
    }

    #[test]
    fn test_documentation_manager() {
        let config = OpenApiConfig::default();
        let mut manager = DocumentationManager::new(config.clone());

        let v2_config = OpenApiConfig {
            title: "Rust Security Platform API v2".to_string(),
            ..config
        };

        manager.add_version_config(ApiVersion::new(2, 0, 0), v2_config);

        let v1_config = manager.get_config(&ApiVersion::new(1, 0, 0));
        let v2_config = manager.get_config(&ApiVersion::new(2, 0, 0));

        assert_eq!(v1_config.title, "Rust Security Platform API");
        assert_eq!(v2_config.title, "Rust Security Platform API v2");
    }

    #[test]
    fn test_markdown_generation() {
        let config = OpenApiConfig::default();
        let manager = DocumentationManager::new(config);

        let docs = manager.generate_markdown_docs(&ApiVersion::new(1, 0, 0));
        assert!(docs.contains("# Rust Security Platform API API Documentation"));
        assert!(docs.contains("**Version:** 1.0.0"));
    }

    #[test]
    fn test_schema_docs_generation() {
        let docs = generate_schema_docs();
        assert!(docs.contains("# API Schema Documentation"));
        assert!(docs.contains("ApiResponse<T>"));
        assert!(docs.contains("ApiErrorDetail"));
    }
}
