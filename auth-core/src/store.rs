//! In-memory token storage

use std::collections::HashMap;

#[derive(Debug)]
pub struct MemoryStore {
    tokens: HashMap<String, TokenData>,
}

#[derive(Debug, Clone)]
pub struct TokenData {
    pub client_id: String,
    pub scope: Option<String>,
    pub expires_at: u64,
    pub active: bool,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self { tokens: HashMap::new() }
    }

    pub fn store_token(&mut self, token: &str, data: TokenData) {
        self.tokens.insert(token.to_string(), data);
    }

    pub fn get_token(&self, token: &str) -> Option<&TokenData> {
        self.tokens.get(token)
    }

    pub fn cleanup_expired(&mut self) {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        self.tokens.retain(|_, data| data.expires_at > now);
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}
