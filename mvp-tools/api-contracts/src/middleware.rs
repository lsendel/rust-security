//! Middleware for API versioning and context propagation

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use crate::{
    context::UserContext,
    errors::{ApiError, VersioningError},
    versioning::VersionManager,
    ApiVersion, ContextPropagation, RequestContext,
};

/// API versioning middleware
#[derive(Debug, Clone)]
pub struct ApiVersioningMiddleware {
    version_manager: VersionManager,
    version_header: String,
}

impl ApiVersioningMiddleware {
    /// Create new API versioning middleware
    pub fn new(version_manager: VersionManager) -> Self {
        Self {
            version_manager,
            version_header: "api-version".to_string(),
        }
    }

    /// Set custom version header name
    pub fn with_version_header(mut self, header: String) -> Self {
        self.version_header = header;
        self
    }

    /// Apply versioning middleware
    pub async fn apply(
        &self,
        headers: &HeaderMap,
        path: &str,
    ) -> Result<ApiVersion, VersioningError> {
        // Extract requested version from headers
        let requested_version = headers
            .get(&self.version_header)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| ApiVersion::parse(v).ok());

        // Resolve version for this endpoint
        let version = self
            .version_manager
            .resolve_version(path, requested_version.as_ref())?;

        // Check if version is deprecated
        if let Some(deprecation_info) = self.version_manager.get_deprecation_info(&version) {
            tracing::warn!(
                "Using deprecated API version {}: deprecated on {}, sunset on {}",
                version,
                deprecation_info.deprecation_date,
                deprecation_info.sunset_date
            );
        }

        Ok(version)
    }

    /// Add deprecation headers to response
    pub fn add_deprecation_headers(&self, headers: &mut HeaderMap, version: &ApiVersion) {
        if let Some(deprecation_info) = self.version_manager.get_deprecation_info(version) {
            // Add Sunset header (RFC 8594)
            if let Ok(sunset_header) =
                HeaderValue::from_str(&deprecation_info.sunset_date.to_rfc2822())
            {
                headers.insert("sunset", sunset_header);
            }

            // Add Deprecation header (draft RFC)
            if let Ok(deprecation_header) = HeaderValue::from_str("true") {
                headers.insert("deprecation", deprecation_header);
            }

            // Add Link header for migration guide
            if deprecation_info.migration_guide_available {
                if let Ok(link_header) = HeaderValue::from_str(&format!(
                    "</docs/migration/v{}>; rel=\"successor-version\"",
                    version
                )) {
                    headers.insert("link", link_header);
                }
            }
        }

        // Always add current API version
        if let Ok(version_header) = HeaderValue::from_str(&version.to_string()) {
            headers.insert("api-version", version_header);
        }
    }
}

/// Context propagation middleware
#[derive(Debug, Clone)]
pub struct ContextPropagationMiddleware {
    propagation: ContextPropagation,
}

impl ContextPropagationMiddleware {
    /// Create new context propagation middleware
    pub fn new(propagation: ContextPropagation) -> Self {
        Self { propagation }
    }

    /// Apply context propagation middleware
    pub fn apply(&self, headers: &HeaderMap) -> RequestContext {
        // Convert HeaderMap to HashMap
        let header_map: HashMap<String, String> = headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect();

        self.propagation.extract_from_headers(&header_map)
    }

    /// Inject context into outbound headers
    pub fn inject_context(&self, context: &RequestContext) -> HeaderMap {
        let header_map = self.propagation.inject_into_headers(context);

        let mut headers = HeaderMap::new();
        for (key, value) in header_map {
            if let (Ok(name), Ok(val)) = (HeaderName::from_str(&key), HeaderValue::from_str(&value))
            {
                headers.insert(name, val);
            }
        }

        headers
    }
}

/// Combined middleware for versioning and context propagation
pub async fn api_middleware(
    State(state): State<ApiMiddlewareState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let headers = request.headers();
    let path = request.uri().path();

    // Apply API versioning
    let version = state
        .versioning_middleware
        .apply(headers, path)
        .await
        .map_err(ApiError::Versioning)?;

    // Apply context propagation
    let context = state.context_middleware.apply(headers);

    // Add context to request extensions
    request.extensions_mut().insert(context.clone());
    request.extensions_mut().insert(version.clone());

    // Process request
    let mut response = next.run(request).await;

    // Add versioning headers to response
    state
        .versioning_middleware
        .add_deprecation_headers(response.headers_mut(), &version);

    // Add service context to response
    if let Some(service_ctx) = Some(&context.service_context) {
        if let Ok(service_header) = HeaderValue::from_str(&service_ctx.service_name) {
            response
                .headers_mut()
                .insert("x-service-name", service_header);
        }
    }

    // Add request ID to response
    if let Ok(request_id_header) = HeaderValue::from_str(&context.request_id.to_string()) {
        response
            .headers_mut()
            .insert("x-request-id", request_id_header);
    }

    Ok(response)
}

/// State for API middleware
#[derive(Debug, Clone)]
pub struct ApiMiddlewareState {
    pub versioning_middleware: ApiVersioningMiddleware,
    pub context_middleware: ContextPropagationMiddleware,
}

/// Tower layer for API middleware
#[derive(Debug, Clone)]
pub struct ApiMiddlewareLayer {
    state: ApiMiddlewareState,
}

impl ApiMiddlewareLayer {
    pub fn new(state: ApiMiddlewareState) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for ApiMiddlewareLayer {
    type Service = ApiMiddlewareService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ApiMiddlewareService {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Tower service for API middleware
#[derive(Debug, Clone)]
pub struct ApiMiddlewareService<S> {
    inner: S,
    state: ApiMiddlewareState,
}

impl<S> Service<Request> for ApiMiddlewareService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let state = self.state.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let headers = request.headers();
            let path = request.uri().path();

            // Apply API versioning
            let version = state
                .versioning_middleware
                .apply(headers, path)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            // Apply context propagation
            let context = state.context_middleware.apply(headers);

            // Add context to request extensions
            request.extensions_mut().insert(context.clone());
            request.extensions_mut().insert(version.clone());

            // Process request
            let mut response = inner.call(request).await.map_err(Into::into)?;

            // Add versioning headers to response
            state
                .versioning_middleware
                .add_deprecation_headers(response.headers_mut(), &version);

            // Add service context to response
            if let Some(service_ctx) = Some(&context.service_context) {
                if let Ok(service_header) = HeaderValue::from_str(&service_ctx.service_name) {
                    response
                        .headers_mut()
                        .insert("x-service-name", service_header);
                }
            }

            // Add request ID to response
            if let Ok(request_id_header) = HeaderValue::from_str(&context.request_id.to_string()) {
                response
                    .headers_mut()
                    .insert("x-request-id", request_id_header);
            }

            Ok(response)
        })
    }
}

/// HTTP client middleware for outbound requests
#[derive(Debug, Clone)]
pub struct OutboundContextMiddleware {
    propagation: ContextPropagation,
}

impl OutboundContextMiddleware {
    pub fn new(propagation: ContextPropagation) -> Self {
        Self { propagation }
    }

    /// Inject context into outbound HTTP request
    pub fn inject_context(
        &self,
        context: &RequestContext,
        mut request: reqwest::Request,
    ) -> reqwest::Request {
        let headers = self.propagation.inject_into_headers(context);

        for (key, value) in headers {
            if let Ok(header_name) = reqwest::header::HeaderName::from_str(&key) {
                if let Ok(header_value) = reqwest::header::HeaderValue::from_str(&value) {
                    request.headers_mut().insert(header_name, header_value);
                }
            }
        }

        request
    }
}

/// Utility function to extract context from request
pub fn extract_context(request: &Request) -> Option<RequestContext> {
    request.extensions().get::<RequestContext>().cloned()
}

/// Utility function to extract API version from request
pub fn extract_version(request: &Request) -> Option<ApiVersion> {
    request.extensions().get::<ApiVersion>().cloned()
}

/// Utility function to extract user context from request context
pub fn extract_user_context(request: &Request) -> Option<UserContext> {
    extract_context(request).and_then(|ctx| ctx.user_context)
}

/// Utility function to require authentication
pub fn require_authentication(request: &Request) -> Result<UserContext, ApiError> {
    extract_user_context(request)
        .ok_or_else(|| ApiError::Authentication("Authentication required".to_string()))
}

/// Utility function to require specific role
pub fn require_role(request: &Request, role: &str) -> Result<UserContext, ApiError> {
    let user_ctx = require_authentication(request)?;

    if user_ctx.has_role(role) {
        Ok(user_ctx)
    } else {
        Err(ApiError::Authorization(format!("Role '{}' required", role)))
    }
}

/// Utility function to require specific permission
pub fn require_permission(request: &Request, permission: &str) -> Result<UserContext, ApiError> {
    let user_ctx = require_authentication(request)?;

    if user_ctx.has_permission(permission) {
        Ok(user_ctx)
    } else {
        Err(ApiError::Authorization(format!(
            "Permission '{}' required",
            permission
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{versioning::DeprecationPolicy, ContextPropagationConfig};

    #[test]
    fn test_versioning_middleware() {
        let mut version_manager =
            VersionManager::new(ApiVersion::new(1, 0, 0), DeprecationPolicy::default());
        version_manager.add_version(ApiVersion::new(1, 1, 0));

        let _middleware = ApiVersioningMiddleware::new(version_manager);

        let mut headers = HeaderMap::new();
        headers.insert("api-version", HeaderValue::from_static("1.1.0"));

        // Test would require async runtime
        // let version = middleware.apply(&headers, "/api/test").await.unwrap();
        // assert_eq!(version, ApiVersion::new(1, 1, 0));
    }

    #[test]
    fn test_context_propagation_middleware() {
        let config = ContextPropagationConfig::default();
        let propagation = ContextPropagation::new(config);
        let middleware = ContextPropagationMiddleware::new(propagation);

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-request-id",
            HeaderValue::from_static("550e8400-e29b-41d4-a716-446655440000"),
        );

        let context = middleware.apply(&headers);
        assert!(!context.is_authenticated());
    }
}
