#![cfg(feature = "compliance-tests")]

use auth_core::prelude::*;
use serde_json::Value;
use tower::ServiceExt; // oneshot
use axum::body::{to_bytes, Body};
use axum::http::Request;
use tower::ServiceExt; // for oneshot

#[tokio::test]
async fn test_client_credentials_flow_rfc6749_section_4_4() {
    let server = AuthServer::minimal()
        .with_client("test_client", "test_secret")
        .build()
        .expect("Failed to build server");

    // Build router and hit it directly (no network)
    let mut svc = server.into_router().into_service();
    let body = "grant_type=client_credentials&client_id=test_client&client_secret=test_secret";
    let request = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = svc.oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let token_response: Value = serde_json::from_slice(&bytes).expect("Failed to parse JSON");
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
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
        ])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);

    let error_response: Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(
        error_response.get("error").unwrap(),
        "unsupported_grant_type"
    );

    server_handle.abort();
}

#[tokio::test]
async fn test_invalid_client_error_rfc6749_section_5_2() {
    let server = AuthServer::minimal()
        .with_client("valid_client", "valid_secret")
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
            ("client_id", "invalid_client"),
            ("client_secret", "valid_secret"),
        ])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 401);

    let error_response: Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(error_response.get("error").unwrap(), "invalid_client");

    let response = client
        .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "valid_client"),
            ("client_secret", "invalid_secret"),
        ])
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 401);

    let error_response: Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(error_response.get("error").unwrap(), "invalid_client");

    server_handle.abort();
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
