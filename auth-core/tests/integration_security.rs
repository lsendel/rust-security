#![cfg(feature = "compliance-tests")]

use auth_core::prelude::*;
use auth_core::{
    client::ClientConfig,
    server::{AppState, ServerConfig},
    store::MemoryStore,
};
use axum::body::to_bytes;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;


#[tokio::test]
async fn test_owasp_a1_injection_attacks() {
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

    let sql_injection_payloads = vec![
        "'; DROP TABLE clients; --",
        "' OR '1'='1",
        "'; UPDATE clients SET client_secret = 'hacked'; --",
        "admin'/*",
        "' UNION SELECT * FROM clients --",
    ];

    for payload in sql_injection_payloads {
        let res = auth_core::handler::token::client_credentials(
            axum::extract::State(state.clone()),
            axum::Form(TokenRequest {
                grant_type: "client_credentials".into(),
                client_id: urlencoding::encode(payload).into_owned(),
                client_secret: "test_secret".into(),
                scope: None,
            }),
        )
        .await;

        assert!(res.is_err(), "SQL injection vulnerability with payload: {}", payload);

        let response = res.err().unwrap().into_response();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap_or_default();
        let response_text = String::from_utf8_lossy(&bytes);
        let error_json: serde_json::Result<Value> = serde_json::from_str(&response_text);
        assert!(error_json.is_ok(), "Invalid JSON response to injection: {}", payload);
    }
}

#[tokio::test]
async fn test_owasp_a2_broken_authentication() {
    let mut clients = HashMap::new();
    clients.insert(
        "valid_client".to_string(),
        ClientConfig {
            client_id: "valid_client".into(),
            client_secret: "secure_secret".into(),
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
        let res = auth_core::handler::token::client_credentials(
            axum::extract::State(state.clone()),
            axum::Form(TokenRequest {
                grant_type: "client_credentials".into(),
                client_id: client_id.into(),
                client_secret: client_secret.into(),
                scope: None,
            }),
        )
        .await;

        if client_id == "valid_client" && client_secret == "secure_secret" {
            let ok = res.expect("Valid credentials should succeed");
            let status = ok.into_response().status();
            assert_eq!(status, StatusCode::OK);
        } else {
            assert!(
                res.is_err(),
                "Authentication bypass with: '{}'/'{}'",
                client_id,
                client_secret
            );
        }
    }
}

#[tokio::test]
async fn test_owasp_a3_sensitive_data_exposure() {
    let mut clients = HashMap::new();
    clients.insert(
        "test_client".to_string(),
        ClientConfig {
            client_id: "test_client".into(),
            client_secret: "super_secret_password_123".into(),
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

    let error_inducing_requests = vec![
        ("invalid", "test_client", "wrong"),
        ("client_credentials", "", ""),
        ("client_credentials", "nonexistent", "super_secret_password_123"),
    ];

    for (grant_type, client_id, client_secret) in error_inducing_requests {
        let res = auth_core::handler::token::client_credentials(
            axum::extract::State(state.clone()),
            axum::Form(TokenRequest {
                grant_type: grant_type.into(),
                client_id: client_id.into(),
                client_secret: client_secret.into(),
                scope: None,
            }),
        )
        .await;

        let response_text = match res {
            Ok(json) => {
                let resp = json.into_response();
                let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap_or_default();
                String::from_utf8_lossy(&bytes).to_string()
            }
            Err(err) => {
                let resp = err.into_response();
                let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap_or_default();
                String::from_utf8_lossy(&bytes).to_string()
            }
        };

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
}

#[tokio::test]
async fn test_owasp_a5_broken_access_control() {
    let mut clients = HashMap::new();
    clients.insert(
        "client_a".to_string(),
        ClientConfig {
            client_id: "client_a".into(),
            client_secret: "secret_a".into(),
            grant_types: vec!["client_credentials".into()],
            scopes: vec!["default".into()],
        },
    );
    clients.insert(
        "client_b".to_string(),
        ClientConfig {
            client_id: "client_b".into(),
            client_secret: "secret_b".into(),
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
        let res = auth_core::handler::token::client_credentials(
            axum::extract::State(state.clone()),
            axum::Form(TokenRequest {
                grant_type: "client_credentials".into(),
                client_id: "client_a".into(),
                client_secret: "secret_a".into(),
                scope: Some(scope_attempt.to_string()),
            }),
        )
        .await;

        match res {
            Ok(json) => {
                let resp = json.into_response();
                assert_eq!(resp.status(), StatusCode::OK);
            }
            Err(err) => {
                let resp = err.into_response();
                assert!(resp.status().as_u16() < 500);
            }
        }
    }
}

#[tokio::test]
async fn test_owasp_a6_security_misconfiguration() {
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

    let response = auth_core::handler::token::client_credentials(
        axum::extract::State(state.clone()),
        axum::Form(TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "test_client".into(),
            client_secret: "test_secret".into(),
            scope: None,
        }),
    )
    .await
    .unwrap()
    .into_response();

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
        let resp = auth_core::server::method_not_allowed().await;
        assert_eq!(
            resp,
            StatusCode::METHOD_NOT_ALLOWED,
            "{} method should not be allowed",
            method
        );
    }
}

#[tokio::test]
async fn test_owasp_a10_insufficient_logging() {
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

    let security_events = vec![
        ("client_credentials", "invalid_client", "wrong_secret"),
        ("client_credentials", "test_client", "wrong_secret"),
        ("client_credentials", "test_client", "test_secret"),
        ("invalid_grant", "test_client", "test_secret"),
    ];

    for (grant_type, client_id, client_secret) in security_events {
        let res = auth_core::handler::token::client_credentials(
            axum::extract::State(state.clone()),
            axum::Form(TokenRequest {
                grant_type: grant_type.into(),
                client_id: client_id.into(),
                client_secret: client_secret.into(),
                scope: None,
            }),
        )
        .await;

        let status = match res {
            Ok(json) => json.into_response().status(),
            Err(err) => err.into_response().status(),
        };
        assert!(
            status.as_u16() < 500,
            "Server error during security event: {} {} {}",
            grant_type,
            client_id,
            client_secret
        );
    }
}

#[tokio::test]
async fn test_protocol_compliance_security() {
    let mut clients = HashMap::new();
    clients.insert(
        "protocol_client".to_string(),
        ClientConfig {
            client_id: "protocol_client".into(),
            client_secret: "protocol_secret".into(),
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

    let res = auth_core::handler::token::client_credentials(
        axum::extract::State(state.clone()),
        axum::Form(TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "protocol_client".into(),
            client_secret: "protocol_secret".into(),
            scope: None,
        }),
    )
    .await
    .unwrap();

    let token_data: Value = serde_json::to_value(res.0).unwrap();
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
}

#[tokio::test]
async fn test_denial_of_service_protection() {
    let mut clients = HashMap::new();
    clients.insert(
        "dos_client".to_string(),
        ClientConfig {
            client_id: "dos_client".into(),
            client_secret: "dos_secret".into(),
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

    let start = std::time::Instant::now();
    for _ in 0..50 {
        let res = auth_core::handler::token::client_credentials(
            axum::extract::State(state.clone()),
            axum::Form(TokenRequest {
                grant_type: "client_credentials".into(),
                client_id: "dos_client".into(),
                client_secret: "dos_secret".into(),
                scope: None,
            }),
        )
        .await;

        let status = match res {
            Ok(json) => json.into_response().status(),
            Err(err) => err.into_response().status(),
        };
        assert!(status.as_u16() < 500, "Server error during DoS test");
    }
    let duration = start.elapsed();
    assert!(
        duration.as_secs() < 30,
        "DoS test took too long: {:?}",
        duration
    );
}
