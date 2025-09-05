//! API documentation for MVP policy service

use utoipa::OpenApi;

/// OpenAPI documentation for MVP Policy Service
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::authorize,
        crate::handlers::health_check,
        crate::handlers::get_metrics,
    ),
    components(
        schemas(
            crate::models::AuthorizeRequest,
            crate::models::AuthorizeResponse,
            crate::models::PolicyConflict,
        )
    ),
    tags(
        (name = "authorization", description = "Policy authorization endpoints"),
        (name = "health", description = "Service health endpoints"),
        (name = "metrics", description = "Service metrics endpoints")
    ),
    info(
        title = "MVP Policy Service API",
        description = "A lightweight policy validation service with enhanced security for MVP deployment",
        version = "0.1.0",
        contact(
            name = "Security Team",
            email = "security@company.com"
        ),
        license(
            name = "MIT OR Apache-2.0"
        )
    ),
    servers(
        (url = "/", description = "Policy Service MVP")
    )
)]
pub struct ApiDoc;

/// Health check response model
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct HealthCheckResponse {
    pub status: String,
    pub service: String,
    pub version: String,
    pub timestamp: String,
}

/// Error response model
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub status: u16,
}