#![cfg(feature = "full-integration")]
use auth_service::storage::store::hybrid::TokenStore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn in_memory_set_and_get_active() {
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));
    let token = "tk_123";
    store.set_active(token, true, None).await.unwrap();
    assert!(store.get_active(token).await.unwrap());
}

#[tokio::test]
async fn in_memory_revoke() {
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));
    let token = "tk_456";
    store.set_active(token, true, None).await.unwrap();
    store.revoke(token).await.unwrap();
    assert!(!store.get_active(token).await.unwrap());
}
