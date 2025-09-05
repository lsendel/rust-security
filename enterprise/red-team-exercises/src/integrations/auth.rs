use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AuthMethod {
    ApiKey(String),
    BearerToken(String),
    BasicAuth { username: String, password: String },
    NoAuth,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IntegrationAuth {
    pub method: AuthMethod,
}
