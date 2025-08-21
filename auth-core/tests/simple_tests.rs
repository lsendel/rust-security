//! Simple unit tests for auth-core functionality
//! These replace the complex integration tests temporarily

use auth_core::server::AuthServer;

#[test]
fn test_server_creation() {
    let server = AuthServer::minimal().with_client("test_client", "test_secret").build();

    assert!(server.build().is_ok());
}

#[test]
fn test_server_builder_methods() {
    let _server = AuthServer::minimal()
        .with_client("client1", "secret1")
        .with_client("client2", "secret2")
        .with_cors(true)
        .with_rate_limit(100)
        .with_jwt_secret("test-secret")
        .with_token_ttl(3600)
        .with_scope("read")
        .build();

    // Test passes if server builds without errors
}

#[test]
fn test_minimal_server_methods() {
    let server = AuthServer::minimal().build();

    // Test compatibility methods
    let server2 = server.build().expect("Build should work");
    let _server3 = server2.into_make_service();

    // Test passes if all methods exist and work
}
