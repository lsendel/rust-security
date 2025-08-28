use axum::{
    extract::{Path, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use tower::ServiceBuilder;

/// API version enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApiVersion {
    V1,
    V2,
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => write!(f, "v1"),
            Self::V2 => write!(f, "v2"),
        }
    }
}

impl FromStr for ApiVersion {
    type Err = ApiVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "v1" | "1" | "1.0" => Ok(Self::V1),
            "v2" | "2" | "2.0" => Ok(Self::V2),
            _ => Err(ApiVersionError::UnsupportedVersion(s.to_string())),
        }
    }
}

/// API versioning errors
#[derive(Debug, thiserror::Error)]
pub enum ApiVersionError {
    #[error("Unsupported API version: {0}")]
    UnsupportedVersion(String),

    #[error("Missing API version header")]
    MissingVersion,

    #[error("API version {0} is deprecated. Please migrate to {1} before {2}")]
    DeprecatedVersion(String, String, String),
}

impl IntoResponse for ApiVersionError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            Self::UnsupportedVersion(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::MissingVersion => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::DeprecatedVersion(_, _, _) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
        };

        let body = Json(ApiErrorResponse {
            error: "API_VERSION_ERROR".to_string(),
            message: error_message,
            supported_versions: vec!["v1".to_string(), "v2".to_string()],
            deprecation_info: get_deprecation_info(),
        });

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub error: String,
    pub message: String,
    pub supported_versions: Vec<String>,
    pub deprecation_info: DeprecationInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeprecationInfo {
    pub deprecated_versions: Vec<DeprecatedVersion>,
    pub migration_guide_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecatedVersion {
    pub version: String,
    pub deprecation_date: String,
    pub sunset_date: String,
    pub replacement_version: String,
}

/// API version configuration
#[derive(Debug, Clone)]
pub struct ApiVersionConfig {
    pub current_version: ApiVersion,
    pub default_version: ApiVersion,
    pub deprecated_versions: Vec<DeprecatedVersion>,
    pub require_version_header: bool,
}

impl Default for ApiVersionConfig {
    fn default() -> Self {
        Self {
            current_version: ApiVersion::V2,
            default_version: ApiVersion::V1, // Conservative default
            deprecated_versions: vec![DeprecatedVersion {
                version: "v1".to_string(),
                deprecation_date: "2024-01-01".to_string(),
                sunset_date: "2024-07-01".to_string(),
                replacement_version: "v2".to_string(),
            }],
            require_version_header: false,
        }
    }
}

/// Extract API version from request
pub fn extract_api_version(
    headers: &HeaderMap,
    path: Option<&Path<String>>,
) -> Result<ApiVersion, ApiVersionError> {
    // 1. Try to get version from URL path (e.g., /v1/users, /v2/oauth/token)
    if let Some(path) = path {
        if let Some(version_str) = extract_version_from_path(&path.0) {
            return version_str.parse();
        }
    }

    // 2. Try to get version from Accept header (e.g., application/vnd.api+json;version=2)
    if let Some(accept) = headers.get("accept") {
        if let Ok(accept_str) = accept.to_str() {
            if let Some(version_str) = extract_version_from_accept(accept_str) {
                return version_str.parse();
            }
        }
    }

    // 3. Try to get version from API-Version header
    if let Some(version_header) = headers.get("api-version") {
        if let Ok(version_str) = version_header.to_str() {
            return version_str.parse();
        }
    }

    // 4. Try to get version from X-API-Version header (legacy support)
    if let Some(version_header) = headers.get("x-api-version") {
        if let Ok(version_str) = version_header.to_str() {
            return version_str.parse();
        }
    }

    // 5. Default to V1 for backward compatibility
    Ok(ApiVersion::V1)
}

/// Extract version from URL path
fn extract_version_from_path(path: &str) -> Option<&str> {
    if path.starts_with("/v1/") {
        Some("v1")
    } else if path.starts_with("/v2/") {
        Some("v2")
    } else {
        None
    }
}

/// Extract version from Accept header
fn extract_version_from_accept(accept: &str) -> Option<&str> {
    // Parse Accept header for version parameter
    // e.g., "application/vnd.api+json;version=2"
    for part in accept.split(';') {
        let part = part.trim();
        if let Some(version) = part.strip_prefix("version=") {
            return Some(version);
        }
    }
    None
}

/// API versioning middleware
pub async fn api_version_middleware(
    headers: HeaderMap,
    path: Path<String>,
    request: Request,
    next: Next,
) -> Result<Response, ApiVersionError> {
    let version = extract_api_version(&headers, Some(&path))?;

    // Check for deprecated versions and add deprecation headers
    let config = ApiVersionConfig::default();
    let mut response = next.run(request).await;

    // Add version headers to response
    response
        .headers_mut()
        .insert("api-version", version.to_string().parse().unwrap());

    response
        .headers_mut()
        .insert("api-supported-versions", "v1,v2".parse().unwrap());

    // Check if version is deprecated
    if let Some(deprecated) = config
        .deprecated_versions
        .iter()
        .find(|d| d.version == version.to_string())
    {
        response
            .headers_mut()
            .insert("deprecation", "true".parse().unwrap());

        response
            .headers_mut()
            .insert("sunset", deprecated.sunset_date.parse().unwrap());

        response.headers_mut().insert(
            "link",
            "<https://docs.example.com/api/migration>; rel=\"deprecation\"; type=\"text/html\"".to_string()
            .parse()
            .unwrap(),
        );

        tracing::warn!(
            version = %version,
            sunset_date = %deprecated.sunset_date,
            replacement = %deprecated.replacement_version,
            "Deprecated API version used"
        );
    }

    Ok(response)
}

/// Version-specific request/response transformations
pub trait ApiTransform {
    fn transform_request_v1_to_v2(&self, request: serde_json::Value) -> serde_json::Value;
    fn transform_response_v2_to_v1(&self, response: serde_json::Value) -> serde_json::Value;
}

/// OAuth token response versioning
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponseV1 {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponseV2 {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub expires_at: u64, // Added in V2
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,            // Added in V2
    pub token_binding: Option<TokenBinding>, // Added in V2
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenBinding {
    pub binding_type: String,
    pub binding_value: String,
}

/// SCIM user response versioning
#[derive(Debug, Serialize, Deserialize)]
pub struct ScimUserResponseV1 {
    pub id: String,
    pub user_name: String,
    pub active: bool,
    pub emails: Vec<ScimEmail>,
    pub meta: ScimMeta,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimUserResponseV2 {
    pub id: String,
    pub user_name: String,
    pub active: bool,
    pub emails: Vec<ScimEmail>,
    pub roles: Option<Vec<String>>,              // Added in V2
    pub groups: Option<Vec<ScimGroupRef>>,       // Added in V2
    pub enterprise_user: Option<EnterpriseUser>, // Added in V2
    pub meta: ScimMeta,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    pub primary: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimGroupRef {
    pub value: String,
    pub display: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnterpriseUser {
    pub department: Option<String>,
    pub manager: Option<ManagerRef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManagerRef {
    pub value: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScimMeta {
    pub resource_type: String,
    pub created: String,
    pub last_modified: String,
    pub version: String,
}

/// Version-aware router
pub fn versioned_routes() -> axum::Router {
    axum::Router::new()
        // V1 routes (legacy)
        .route("/v1/oauth/token", axum::routing::post(oauth_token_v1))
        .route(
            "/v1/oauth/introspect",
            axum::routing::post(oauth_introspect_v1),
        )
        .route("/v1/scim/Users", axum::routing::get(scim_users_v1))
        .route("/v1/scim/Users", axum::routing::post(scim_create_user_v1))
        // V2 routes (current)
        .route("/v2/oauth/token", axum::routing::post(oauth_token_v2))
        .route(
            "/v2/oauth/introspect",
            axum::routing::post(oauth_introspect_v2),
        )
        .route("/v2/scim/Users", axum::routing::get(scim_users_v2))
        .route("/v2/scim/Users", axum::routing::post(scim_create_user_v2))
        // Version-agnostic routes (auto-detect version)
        .route("/oauth/token", axum::routing::post(oauth_token_versioned))
        .route(
            "/oauth/introspect",
            axum::routing::post(oauth_introspect_versioned),
        )
        .route("/scim/Users", axum::routing::get(scim_users_versioned))
        .route(
            "/scim/Users",
            axum::routing::post(scim_create_user_versioned),
        )
        // Middleware for version detection and deprecation warnings
        .layer(ServiceBuilder::new().layer(axum::middleware::from_fn(api_version_middleware)))
}

// Placeholder handlers for different API versions
async fn oauth_token_v1() -> impl IntoResponse {
    Json(TokenResponseV1 {
        access_token: "example_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: None,
        scope: Some("read write".to_string()),
    })
}

async fn oauth_token_v2() -> impl IntoResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Json(TokenResponseV2 {
        access_token: "example_token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        expires_at: now + 3600,
        refresh_token: None,
        scope: Some("read write".to_string()),
        id_token: Some("example_id_token".to_string()),
        token_binding: Some(TokenBinding {
            binding_type: "client_certificate".to_string(),
            binding_value: "example_binding".to_string(),
        }),
    })
}

async fn oauth_introspect_v1() -> impl IntoResponse {
    "OAuth introspect V1"
}

async fn oauth_introspect_v2() -> impl IntoResponse {
    "OAuth introspect V2"
}

async fn scim_users_v1() -> impl IntoResponse {
    "SCIM users V1"
}

async fn scim_users_v2() -> impl IntoResponse {
    "SCIM users V2"
}

async fn scim_create_user_v1() -> impl IntoResponse {
    "SCIM create user V1"
}

async fn scim_create_user_v2() -> impl IntoResponse {
    "SCIM create user V2"
}

async fn oauth_token_versioned(headers: HeaderMap) -> impl IntoResponse {
    match extract_api_version(&headers, None) {
        Ok(ApiVersion::V1) => oauth_token_v1().await.into_response(),
        Ok(ApiVersion::V2) => oauth_token_v2().await.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn oauth_introspect_versioned(headers: HeaderMap) -> impl IntoResponse {
    match extract_api_version(&headers, None) {
        Ok(ApiVersion::V1) => oauth_introspect_v1().await.into_response(),
        Ok(ApiVersion::V2) => oauth_introspect_v2().await.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn scim_users_versioned(headers: HeaderMap) -> impl IntoResponse {
    match extract_api_version(&headers, None) {
        Ok(ApiVersion::V1) => scim_users_v1().await.into_response(),
        Ok(ApiVersion::V2) => scim_users_v2().await.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn scim_create_user_versioned(headers: HeaderMap) -> impl IntoResponse {
    match extract_api_version(&headers, None) {
        Ok(ApiVersion::V1) => scim_create_user_v1().await.into_response(),
        Ok(ApiVersion::V2) => scim_create_user_v2().await.into_response(),
        Err(e) => e.into_response(),
    }
}

/// Get deprecation information
#[must_use] pub fn get_deprecation_info() -> DeprecationInfo {
    DeprecationInfo {
        deprecated_versions: vec![DeprecatedVersion {
            version: "v1".to_string(),
            deprecation_date: "2024-01-01".to_string(),
            sunset_date: "2024-07-01".to_string(),
            replacement_version: "v2".to_string(),
        }],
        migration_guide_url: "https://docs.example.com/api/migration-guide".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn test_api_version_from_str() {
        assert_eq!("v1".parse::<ApiVersion>().unwrap(), ApiVersion::V1);
        assert_eq!("v2".parse::<ApiVersion>().unwrap(), ApiVersion::V2);
        assert_eq!("1".parse::<ApiVersion>().unwrap(), ApiVersion::V1);
        assert_eq!("2".parse::<ApiVersion>().unwrap(), ApiVersion::V2);

        assert!("v3".parse::<ApiVersion>().is_err());
        assert!("invalid".parse::<ApiVersion>().is_err());
    }

    #[test]
    fn test_extract_version_from_path() {
        assert_eq!(extract_version_from_path("/v1/oauth/token"), Some("v1"));
        assert_eq!(extract_version_from_path("/v2/scim/Users"), Some("v2"));
        assert_eq!(extract_version_from_path("/oauth/token"), None);
    }

    #[test]
    fn test_extract_version_from_accept() {
        assert_eq!(
            extract_version_from_accept("application/json;version=1"),
            Some("1")
        );
        assert_eq!(
            extract_version_from_accept("application/vnd.api+json;version=2"),
            Some("2")
        );
        assert_eq!(extract_version_from_accept("application/json"), None);
    }

    #[test]
    fn test_extract_api_version_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("api-version", HeaderValue::from_static("v2"));

        let version = extract_api_version(&headers, None).unwrap();
        assert_eq!(version, ApiVersion::V2);

        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("application/json;version=1"),
        );

        let version = extract_api_version(&headers, None).unwrap();
        assert_eq!(version, ApiVersion::V1);
    }
}
