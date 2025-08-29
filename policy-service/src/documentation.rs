#![allow(clippy::needless_for_each)]

use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, Http, HttpAuthScheme, SecurityScheme},
    Modify, OpenApi,
};

use crate::{AuthorizeRequest, AuthorizeResponse};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Policy Service API",
        version = "1.0.0",
        description = "Enterprise Policy Engine Service powered by Cedar Policy language",
        contact(
            name = "Security Team",
            email = "security@example.com"
        ),
        license(
            name = "MIT OR Apache-2.0",
            url = "https://github.com/lsendel/rust-security"
        )
    ),
    servers(
        (url = "http://localhost:8081", description = "Local development server"),
        (url = "https://api.example.com", description = "Production server")
    ),
    paths(
        crate::authorize,
        crate::health_check,
        crate::get_metrics,
    ),
    components(
        schemas(
            AuthorizeRequest,
            AuthorizeResponse,
            HealthCheckResponse,
            ErrorResponse,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "authorization", description = "Authorization operations"),
        (name = "health", description = "Health check operations"),
        (name = "metrics", description = "Metrics operations")
    )
)]
pub struct ApiDoc;

pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-API-Key"))),
            );
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            );
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct HealthCheckResponse {
    pub status: String,
    pub version: String,
    pub timestamp: String,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub error: ErrorDetails,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ErrorDetails {
    #[schema(example = "invalid_input")]
    pub r#type: String,
    #[schema(example = "The provided input is invalid")]
    pub message: String,
    #[schema(example = 400)]
    pub status: u16,
}
