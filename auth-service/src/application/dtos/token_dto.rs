//! Token Data Transfer Objects

/// Token introspection request DTO
#[derive(Debug, serde::Deserialize)]
pub struct TokenIntrospectionRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

/// Token introspection response DTO
#[derive(Debug, serde::Serialize)]
pub struct TokenIntrospectionResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
}
