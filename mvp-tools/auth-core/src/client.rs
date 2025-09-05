//! OAuth client configuration

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_secret: String,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
}
