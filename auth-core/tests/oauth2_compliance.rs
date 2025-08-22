#![cfg(feature = "compliance-tests")]

use auth_core::prelude::*;
use auth_core::{
    client::ClientConfig,
    server::{AppState, ServerConfig},
    store::MemoryStore,
};
use axum::body::to_bytes;
use axum::{extract::State, response::IntoResponse, Form};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_client_credentials_flow_rfc6749_section_4_4() {
    let mut clients = HashMap::new();
    clients.insert(
        "test_client".to_string(),
        ClientConfig {
            client_id: "test_client".into(),
            client_secret: "test_secret".into(),
            grant_types: vec!["client_credentials".into()],
            scopes: vec!["default".into()],
        },
    );
    let state = AppState {
        config: ServerConfig {
            clients,
            rate_limit: 100,
            cors_enabled: true,
            jwt_secret: None,
            protected_routes: vec![],
        },
        store: Arc::new(RwLock::new(MemoryStore::new())),
    };

    let req = TokenRequest {
        grant_type: "client_credentials".into(),
        client_id: "test_client".into(),
        client_secret: "test_secret".into(),
        scope: None,
    };
    let resp = auth_core::handler::token::client_credentials(State(state), Form(req))
        .await
        .expect("token issuance failed");
    let token_response: Value = serde_json::to_value(resp.0).unwrap();
    assert!(token_response.get("access_token").is_some());
    assert_eq!(token_response.get("token_type").unwrap(), "Bearer");
    assert!(token_response.get("expires_in").is_some());

    let access_token = token_response
        .get("access_token")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(access_token.starts_with("auth_core_"));
    assert!(access_token.len() > 32);

    // no runtime server spawned in this test
}

#[tokio::test]
async fn test_invalid_grant_type_error_rfc6749_section_5_2() {
    let mut clients = HashMap::new();
    clients.insert(
        "test_client".to_string(),
        ClientConfig {
            client_id: "test_client".into(),
            client_secret: "test_secret".into(),
            grant_types: vec!["client_credentials".into()],
            scopes: vec!["default".into()],
        },
    );
    let state = AppState {
        config: ServerConfig {
            clients,
            rate_limit: 100,
            cors_enabled: true,
            jwt_secret: None,
            protected_routes: vec![],
        },
        store: Arc::new(RwLock::new(MemoryStore::new())),
    };
    let bad = TokenRequest {
        grant_type: "authorization_code".into(),
        client_id: "test_client".into(),
        client_secret: "test_secret".into(),
        scope: None,
    };
    let res = auth_core::handler::token::client_credentials(State(state), Form(bad)).await;
    let err = res.err().expect("expected unsupported_grant_type error");
    let resp = err.into_response();
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v.get("error").unwrap(), "unsupported_grant_type");
}

#[tokio::test]
async fn test_invalid_client_error_rfc6749_section_5_2() {
    let mut clients = HashMap::new();
    clients.insert(
        "valid_client".to_string(),
        ClientConfig {
            client_id: "valid_client".into(),
            client_secret: "valid_secret".into(),
            grant_types: vec!["client_credentials".into()],
            scopes: vec!["default".into()],
        },
    );
    let state = AppState {
        config: ServerConfig {
            clients,
            rate_limit: 100,
            cors_enabled: true,
            jwt_secret: None,
            protected_routes: vec![],
        },
        store: Arc::new(RwLock::new(MemoryStore::new())),
    };
    let bad1 = TokenRequest {
        grant_type: "client_credentials".into(),
        client_id: "invalid_client".into(),
        client_secret: "valid_secret".into(),
        scope: None,
    };
    let res1 =
        auth_core::handler::token::client_credentials(State(state.clone()), Form(bad1)).await;
    assert!(matches!(
        res1,
        Err(auth_core::error::AuthError::InvalidClient)
    ));
    let bad2 = TokenRequest {
        grant_type: "client_credentials".into(),
        client_id: "valid_client".into(),
        client_secret: "invalid_secret".into(),
        scope: None,
    };
    let res2 =
        auth_core::handler::token::client_credentials(State(state.clone()), Form(bad2)).await;
    assert!(matches!(
        res2,
        Err(auth_core::error::AuthError::InvalidClient)
    ));
}

#[cfg(all(feature = "jwt", feature = "introspection"))]
#[tokio::test]
async fn test_token_introspection_rfc7662() {
    let server = AuthServer::minimal()
        .with_client("test_client", "test_secret")
        .build()
        .expect("Failed to build server");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let _router = server.into_make_service();
        drop(listener);
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    let token_response = client
        .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .expect("Failed to get token");

    let token_data: Value = token_response.json().await.unwrap();
    let access_token = token_data.get("access_token").unwrap().as_str().unwrap();

    let introspect_response = client
        .post(format!("http://127.0.0.1:{}/oauth/introspect", addr.port()))
        .form(&[
            ("token", access_token),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .expect("Failed to introspect token");

    assert_eq!(introspect_response.status(), 200);

    let introspect_data: Value = introspect_response.json().await.unwrap();
    assert_eq!(introspect_data.get("active").unwrap(), true);
    assert_eq!(introspect_data.get("client_id").unwrap(), "test_client");
    assert!(introspect_data.get("exp").is_some());
    assert_eq!(introspect_data.get("token_type").unwrap(), "Bearer");

    let invalid_introspect_response = client
        .post(format!("http://127.0.0.1:{}/oauth/introspect", addr.port()))
        .form(&[
            ("token", "invalid_token"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .expect("Failed to introspect invalid token");

    let invalid_introspect_data: Value = invalid_introspect_response.json().await.unwrap();
    assert_eq!(invalid_introspect_data.get("active").unwrap(), false);

    server_handle.abort();
}

#[tokio::test]
async fn test_bearer_token_usage_rfc6750() {
    let server = AuthServer::minimal()
        .with_client("test_client", "test_secret")
        .add_protected_route("/api/protected")
        .build()
        .expect("Failed to build server");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let _router = server.into_make_service();
        drop(listener);
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    let token_response = client
        .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .expect("Failed to get token");

    let token_data: Value = token_response.json().await.unwrap();
    let access_token = token_data.get("access_token").unwrap().as_str().unwrap();

    let protected_response = client
        .get(format!("http://127.0.0.1:{}/api/protected", addr.port()))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .expect("Failed to access protected resource");

    assert_eq!(protected_response.status(), 200);

    let unauthorized_response = client
        .get(format!("http://127.0.0.1:{}/api/protected", addr.port()))
        .send()
        .await
        .expect("Failed to access protected resource");

    assert_eq!(unauthorized_response.status(), 401);

    let auth_header = unauthorized_response.headers().get("WWW-Authenticate");
    assert!(auth_header.is_some());
    assert!(auth_header.unwrap().to_str().unwrap().contains("Bearer"));

    server_handle.abort();
}

#[tokio::test]
async fn test_scope_parameter_handling() {
    let server = AuthServer::minimal()
        .with_client("test_client", "test_secret")
        .with_scope("read")
        .with_scope("write")
        .build()
        .expect("Failed to build server");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let _router = server.into_make_service();
        drop(listener);
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    let response = client
        .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
            ("scope", "read"),
        ])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let token_data: Value = response.json().await.unwrap();
    assert_eq!(token_data.get("scope").unwrap(), "read");

    let response = client
        .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
            ("scope", "read write"),
        ])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let token_data: Value = response.json().await.unwrap();
    let returned_scope = token_data.get("scope").unwrap().as_str().unwrap();
    assert!(returned_scope.contains("read"));
    assert!(returned_scope.contains("write"));

    server_handle.abort();
}

#[tokio::test]
async fn test_token_expiration_handling() {
    let server = AuthServer::minimal()
        .with_client("test_client", "test_secret")
        .with_token_ttl(1)
        .build()
        .expect("Failed to build server");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let _router = server.into_make_service();
        drop(listener);
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    let token_response = client
        .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .expect("Failed to get token");

    let token_data: Value = token_response.json().await.unwrap();
    let access_token = token_data.get("access_token").unwrap().as_str().unwrap();

    let introspect_response = client
        .post(format!("http://127.0.0.1:{}/oauth/introspect", addr.port()))
        .form(&[
            ("token", access_token),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .expect("Failed to introspect token");

    let introspect_data: Value = introspect_response.json().await.unwrap();
    assert_eq!(introspect_data.get("active").unwrap(), true);

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let expired_introspect_response = client
        .post(format!("http://127.0.0.1:{}/oauth/introspect", addr.port()))
        .form(&[
            ("token", access_token),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .expect("Failed to introspect expired token");

    let expired_introspect_data: Value = expired_introspect_response.json().await.unwrap();
    assert_eq!(expired_introspect_data.get("active").unwrap(), false);

    server_handle.abort();
}

#[tokio::test]
async fn test_content_type_requirements() {
    let server = AuthServer::minimal()
        .with_client("test_client", "test_secret")
        .build()
        .expect("Failed to build server");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        let _router = server.into_make_service();
        drop(listener);
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = reqwest::Client::new();

    let response = client
        .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let get_response = client
        .get(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
        .send()
        .await
        .expect("Failed to send GET request");

    assert_eq!(get_response.status(), 405);

    server_handle.abort();
}
