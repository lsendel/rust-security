use axum_integration_example::{
    create_app, AuthResponse, CreateUserRequest, LoginRequest, RegisterRequest, UserRole,
};
use http_body_util::BodyExt;
use serde_json::Value;
use std::collections::HashMap;
use tokio::net::TcpListener;
use tower::ServiceExt;

async fn spawn_app() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = create_app().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

#[tokio::test]
async fn test_user_registration_with_password() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test user registration
    let register_request = RegisterRequest {
        name: "John Doe".to_string(),
        email: "john@example.com".to_string(),
        password: "securepassword123".to_string(),
    };

    let response = client
        .post(format!("{}/auth/register", base))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 201);

    let auth_response: AuthResponse = response.json().await.unwrap();
    assert!(!auth_response.token.is_empty());
    assert_eq!(auth_response.user.name, "John Doe");
    assert_eq!(auth_response.user.email, "john@example.com");
    assert_eq!(auth_response.user.role, UserRole::User);
}

#[tokio::test]
async fn test_user_login_with_password() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // First register a user
    let register_request = RegisterRequest {
        name: "Jane Doe".to_string(),
        email: "jane@example.com".to_string(),
        password: "mypassword456".to_string(),
    };

    let response = client
        .post(format!("{}/auth/register", base))
        .json(&register_request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    // Now try to login
    let login_request = LoginRequest {
        email: "jane@example.com".to_string(),
        password: "mypassword456".to_string(),
    };

    let response =
        client.post(format!("{}/auth/login", base)).json(&login_request).send().await.unwrap();

    assert_eq!(response.status(), 200);

    let auth_response: AuthResponse = response.json().await.unwrap();
    assert!(!auth_response.token.is_empty());
    assert_eq!(auth_response.user.email, "jane@example.com");
}

#[tokio::test]
async fn test_login_with_wrong_password() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Register a user
    let register_request = RegisterRequest {
        name: "Test User".to_string(),
        email: "test@example.com".to_string(),
        password: "correctpassword".to_string(),
    };

    let response = client
        .post(format!("{}/auth/register", base))
        .json(&register_request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    // Try to login with wrong password
    let login_request = LoginRequest {
        email: "test@example.com".to_string(),
        password: "wrongpassword".to_string(),
    };

    let response =
        client.post(format!("{}/auth/login", base)).json(&login_request).send().await.unwrap();

    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn test_password_validation() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test password too short
    let register_request = RegisterRequest {
        name: "Test User".to_string(),
        email: "test@example.com".to_string(),
        password: "short".to_string(), // Less than 8 characters
    };

    let response = client
        .post(format!("{}/auth/register", base))
        .json(&register_request)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    let error_response: Value = response.json().await.unwrap();
    assert!(error_response.get("error").is_some());
}

#[tokio::test]
async fn test_duplicate_email_registration() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Register first user
    let register_request = RegisterRequest {
        name: "First User".to_string(),
        email: "duplicate@example.com".to_string(),
        password: "password123".to_string(),
    };

    let response = client
        .post(format!("{}/auth/register", base))
        .json(&register_request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);

    // Try to register second user with same email
    let register_request2 = RegisterRequest {
        name: "Second User".to_string(),
        email: "duplicate@example.com".to_string(),
        password: "differentpassword".to_string(),
    };

    let response = client
        .post(format!("{}/auth/register", base))
        .json(&register_request2)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    let error_response: Value = response.json().await.unwrap();
    assert!(error_response.get("error").unwrap().as_str().unwrap().contains("already exists"));
}

#[tokio::test]
async fn test_user_creation_with_password() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Create user with password
    let create_request = CreateUserRequest {
        name: "Admin User".to_string(),
        email: "admin@example.com".to_string(),
        password: Some("adminpassword123".to_string()),
        role: Some(UserRole::Admin),
    };

    let response =
        client.post(format!("{}/users", base)).json(&create_request).send().await.unwrap();

    assert_eq!(response.status(), 201);

    let user_response: Value = response.json().await.unwrap();
    assert_eq!(user_response.get("name").unwrap().as_str().unwrap(), "Admin User");
    assert_eq!(user_response.get("email").unwrap().as_str().unwrap(), "admin@example.com");
    assert_eq!(user_response.get("role").unwrap().as_str().unwrap(), "Admin");
    // Password hash should not be in response
    assert!(user_response.get("password_hash").is_none());
}

#[tokio::test]
async fn test_password_service() {
    use axum_integration_example::PasswordService;

    let password = "testpassword123";

    // Test password hashing
    let hash = PasswordService::hash_password(password).unwrap();
    assert!(!hash.is_empty());
    assert_ne!(hash, password); // Hash should be different from password

    // Test password verification
    let is_valid = PasswordService::verify_password(password, &hash).unwrap();
    assert!(is_valid);

    // Test wrong password
    let is_valid = PasswordService::verify_password("wrongpassword", &hash).unwrap();
    assert!(!is_valid);
}

#[tokio::test]
async fn test_jwt_service() {
    use axum_integration_example::{JwtService, UserRole};

    let jwt_service = JwtService::new("this-is-a-test-secret-with-enough-length".to_string(), Some(1)).unwrap();

    // Test token generation
    let token = jwt_service.generate_token(1, "test@example.com", UserRole::User).unwrap();
    assert!(!token.is_empty());

    // Test token validation
    let claims = jwt_service.validate_token(&token).unwrap();
    assert_eq!(claims.sub, 1);
    assert_eq!(claims.email, "test@example.com");
    assert_eq!(claims.role, UserRole::User);

    // Test invalid token
    let result = jwt_service.validate_token("invalid_token");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_input_validation() {
    use axum_integration_example::{CreateUserRequest, RegisterRequest, UserRole};

    // Test valid create user request
    let request = CreateUserRequest {
        name: "Valid User".to_string(),
        email: "valid@example.com".to_string(),
        password: Some("validpassword123".to_string()),
        role: Some(UserRole::User),
    };
    assert!(request.validate().is_ok());

    // Test invalid email
    let request = CreateUserRequest {
        name: "Valid User".to_string(),
        email: "invalid-email".to_string(),
        password: Some("validpassword123".to_string()),
        role: Some(UserRole::User),
    };
    assert!(request.validate().is_err());

    // Test register request validation
    let request = RegisterRequest {
        name: "Valid User".to_string(),
        email: "valid@example.com".to_string(),
        password: "validpassword123".to_string(),
    };
    assert!(request.validate().is_ok());

    // Test short password
    let request = RegisterRequest {
        name: "Valid User".to_string(),
        email: "valid@example.com".to_string(),
        password: "short".to_string(),
    };
    assert!(request.validate().is_err());
}
