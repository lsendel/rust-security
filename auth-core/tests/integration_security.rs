#![cfg(feature = "compliance-tests")]

use auth_core::prelude::*;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt; // oneshot

#[tokio::test]
async fn test_owasp_a1_injection_attacks() {
    let server = AuthServer::minimal()
        .with_client("test_client", "test_secret")
        .build()
        .expect("Failed to build server");

    let mut router = server.into_router().into_service();

    let sql_injection_payloads = vec![
        "'; DROP TABLE clients; --",
        "' OR '1'='1",
        "'; UPDATE clients SET client_secret = 'hacked'; --",
        "admin'/*",
        "' UNION SELECT * FROM clients --",
    ];

    for payload in sql_injection_payloads {
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret=test_secret",
            urlencoding::encode(payload)
        );
        let request = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();

        assert!(
            response.status() == StatusCode::UNAUTHORIZED,
            "SQL injection vulnerability with payload: {}",
            payload
        );

        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        let response_text = String::from_utf8_lossy(&bytes);
        let error_json: serde_json::Result<Value> = serde_json::from_str(&response_text);
        assert!(
            error_json.is_ok(),
            "Invalid JSON response to injection: {}",
            payload
        );
    }
}

#[tokio::test]
async fn test_owasp_a2_broken_authentication() {
    let server = AuthServer::minimal()
        .with_client("valid_client", "secure_secret")
        .build()
        .expect("Failed to build server");

    let mut router = server.into_router().into_service();

    let bypass_attempts = vec![
        ("", ""),
        ("valid_client\0", "secure_secret"),
        ("valid_client", "secure_secret\0"),
        ("VALID_CLIENT", "secure_secret"),
        ("valid_client", "SECURE_SECRET"),
        ("valid_client", "secure_secret"),
        ("valid_client", "secure_secret_extended"),
        ("valid_client", "different_secret"),
    ];

    for (client_id, client_secret) in bypass_attempts {
        let response = client
            .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .expect("Failed to send authentication bypass test");

        assert_eq!(
            response.status(),
            401,
            "Authentication bypass with: '{}'/'{}'",
            client_id,
            client_secret
        );
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_owasp_a3_sensitive_data_exposure() {
    let server = AuthServer::minimal()
        .with_client("test_client", "super_secret_password_123")
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

    let error_inducing_requests = vec![
        vec![
            ("grant_type", "invalid"),
            ("client_id", "test_client"),
            ("client_secret", "wrong"),
        ],
        vec![("grant_type", "client_credentials")],
        vec![
            ("grant_type", "client_credentials"),
            ("client_id", "nonexistent"),
            ("client_secret", "super_secret_password_123"),
        ],
    ];

    for form_data in error_inducing_requests {
        let response = client
            .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
            .form(&form_data)
            .send()
            .await
            .expect("Failed to send error test");

        let response_text = response.text().await.unwrap_or_default();

        assert!(
            !response_text.contains("super_secret_password_123"),
            "Client secret leaked in error response: {}",
            response_text
        );
        assert!(
            !response_text.contains("password"),
            "Password reference in error response: {}",
            response_text
        );
        assert!(
            !response_text.contains("secret"),
            "Secret reference in error response: {}",
            response_text
        );

        assert!(
            !response_text.contains("/src/"),
            "Source path leaked: {}",
            response_text
        );
        assert!(
            !response_text.contains("panic"),
            "Panic information leaked: {}",
            response_text
        );
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_owasp_a5_broken_access_control() {
    let server = AuthServer::minimal()
        .with_client("client_a", "secret_a")
        .with_client("client_b", "secret_b")
        .with_scope("read")
        .with_scope("write")
        .with_scope("admin")
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

    let escalation_attempts = vec![
        "admin",
        "read write admin",
        "read admin write",
        "*",
        "read,write,admin",
        "read;write;admin",
        "../admin",
        "scope injection admin",
    ];

    for scope_attempt in escalation_attempts {
        let response = client
            .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "client_a"),
                ("client_secret", "secret_a"),
                ("scope", scope_attempt),
            ])
            .send()
            .await
            .expect("Failed to send scope escalation test");

        if response.status() == 200 {
            let token_data: Value = response.json().await.unwrap();
            if let Some(granted_scope) = token_data.get("scope") {
                let granted_str = granted_scope.as_str().unwrap();
                assert!(
                    !granted_str.contains("admin"),
                    "Unauthorized admin scope granted for: {}",
                    scope_attempt
                );
            }
        }
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_owasp_a6_security_misconfiguration() {
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

    let body = "grant_type=client_credentials&client_id=test_client&client_secret=test_secret";
    let request = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();

    let headers = response.headers().clone();
    assert!(
        headers.contains_key("content-type"),
        "Missing Content-Type header"
    );
    assert!(
        !headers.contains_key("server")
            || !headers
                .get("server")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("auth-core"),
        "Server version information exposed"
    );

    let methods = vec!["GET", "PUT", "DELETE", "PATCH", "HEAD"];
    for method in methods {
        let request = Request::builder()
            .method(method)
            .uri("/oauth/token")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(request).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{} method should not be allowed",
            method
        );
    }
}

#[tokio::test]
async fn test_owasp_a10_insufficient_logging() {
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

    let security_events = vec![
        ("client_credentials", "invalid_client", "wrong_secret"),
        ("client_credentials", "test_client", "wrong_secret"),
        ("client_credentials", "test_client", "test_secret"),
        ("invalid_grant", "test_client", "test_secret"),
    ];

    for (grant_type, client_id, client_secret) in security_events {
        let response = client
            .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
            .form(&[
                ("grant_type", grant_type),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
            .send()
            .await
            .expect("Failed to send logging test");

        assert!(
            response.status().as_u16() < 500,
            "Server error during security event: {} {} {}",
            grant_type,
            client_id,
            client_secret
        );
    }

    server_handle.abort();
}

#[tokio::test]
async fn test_protocol_compliance_security() {
    let server = AuthServer::minimal()
        .with_client("protocol_client", "protocol_secret")
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
            ("client_id", "protocol_client"),
            ("client_secret", "protocol_secret"),
        ])
        .send()
        .await
        .expect("Failed to send protocol test");

    assert_eq!(response.status(), 200);

    let token_data: Value = response.json().await.unwrap();
    assert!(
        token_data.get("access_token").is_some(),
        "access_token is required per RFC 6749"
    );
    assert_eq!(token_data.get("token_type").unwrap(), "Bearer");
    assert!(
        token_data.get("expires_in").is_some(),
        "expires_in should be provided per RFC 6749"
    );

    let access_token = token_data.get("access_token").unwrap().as_str().unwrap();
    assert!(
        !access_token.contains("protocol_secret"),
        "Access token must not contain client secret"
    );
    assert!(
        !access_token.contains("protocol_client"),
        "Access token should not contain client_id directly"
    );

    server_handle.abort();
}

#[tokio::test]
async fn test_denial_of_service_protection() {
    let server = AuthServer::minimal()
        .with_client("dos_client", "dos_secret")
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

    let start = std::time::Instant::now();
    for _ in 0..50 {
        let response = client
            .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "dos_client"),
                ("client_secret", "dos_secret"),
            ])
            .send()
            .await;

        match response {
            Ok(resp) => assert!(resp.status().as_u16() < 500, "Server error during DoS test"),
            Err(_) => {
                break;
            }
        }
    }
    let duration = start.elapsed();
    assert!(
        duration.as_secs() < 30,
        "DoS test took too long: {:?}",
        duration
    );

    server_handle.abort();
}
