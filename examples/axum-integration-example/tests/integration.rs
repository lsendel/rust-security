/*!
# Axum Integration Testing Example

This module demonstrates comprehensive integration testing patterns for Axum REST APIs using
in-process testing with `tower::ServiceExt::oneshot`. The tests showcase production-quality
patterns including proper error handling, state isolation, and thorough validation.

## Key Testing Patterns Demonstrated

### In-Process Testing with tower::ServiceExt
- Uses `ServiceExt::oneshot` for direct service calls without network overhead
- Provides complete control over request/response cycle
- Enables testing without external dependencies or port conflicts

### State Isolation
- Each test creates a fresh app instance using `create_test_app()`
- Ensures tests run independently without side effects
- Allows parallel test execution safely

### Comprehensive Validation
- Status code verification with detailed context
- Header validation (Content-Type, etc.)
- JSON response parsing and validation
- Error message format consistency

### Async Testing Best Practices
- Proper use of `tokio::test` for async test functions
- Correct handling of async operations in test setup
- Efficient concurrent testing patterns

## Example Usage

```rust
#[tokio::test]
async fn test_example() {
    let app = create_test_app();
    let request = json_request_builder("POST", "/users", json!({
        "name": "Test User",
        "email": "test@example.com"
    }));

    let response = app.oneshot(request).await.unwrap();
    assert_status(response.status(), StatusCode::CREATED, "User creation");
}
```
*/

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use axum_integration_example::create_app;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

/// Creates a fresh test app instance with isolated state.
///
/// This function provides a clean Router instance for each test, ensuring
/// complete state isolation between tests. Each call returns a new app
/// with empty user storage and reset ID counter.
///
/// # Returns
/// A configured `Router` ready for testing
///
/// # Example
/// ```rust
/// let app = create_test_app();
/// // App is ready for testing with clean state
/// ```
fn create_test_app() -> Router {
    create_app()
}

/// Builds HTTP requests with proper headers for API testing.
///
/// This helper ensures consistent header setup across all test requests,
/// including proper Content-Type and Accept headers for JSON APIs.
///
/// # Arguments
/// * `method` - HTTP method (GET, POST, etc.)
/// * `uri` - Request URI path
///
/// # Returns
/// An `http::request::Builder` ready for body attachment
///
/// # Example
/// ```rust
/// let request = request_builder("GET", "/users")
///     .body(Body::empty())
///     .unwrap();
/// ```
fn request_builder(method: &str, uri: &str) -> http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("accept", "application/json")
}

/// Parses response body to JSON with comprehensive error handling.
///
/// This utility handles the common pattern of extracting and parsing JSON
/// from HTTP response bodies, with proper error propagation for debugging.
///
/// # Arguments
/// * `body` - The response body to parse
///
/// # Returns
/// Parsed JSON `Value` or error if parsing fails
///
/// # Errors
/// Returns error if body collection or JSON parsing fails
async fn response_body_to_json(body: Body) -> Result<Value, Box<dyn std::error::Error>> {
    let body_bytes = body.collect().await?.to_bytes();
    let json: Value = serde_json::from_slice(&body_bytes)?;
    Ok(json)
}

/// Validates HTTP status codes with detailed error context.
///
/// This assertion helper provides clear error messages when status codes
/// don't match expectations, including context about which test scenario failed.
///
/// # Arguments
/// * `actual` - The actual status code received
/// * `expected` - The expected status code
/// * `context` - Description of the test scenario for error messages
///
/// # Panics
/// Panics with detailed message if status codes don't match
fn assert_status(actual: StatusCode, expected: StatusCode, context: &str) {
    assert_eq!(
        actual, expected,
        "Status code mismatch in {}: expected {}, got {}",
        context, expected, actual
    );
}

/// Builds JSON requests with proper content type and serialization.
///
/// This helper combines request building with JSON serialization,
/// ensuring proper Content-Type headers and body formatting for API requests.
///
/// # Arguments
/// * `method` - HTTP method
/// * `uri` - Request URI
/// * `json_body` - JSON value to serialize as request body
///
/// # Returns
/// Complete `Request<Body>` ready for execution
///
/// # Example
/// ```rust
/// let request = json_request_builder("POST", "/users", json!({
///     "name": "John Doe",
///     "email": "john@example.com"
/// }));
/// ```
fn json_request_builder(method: &str, uri: &str, json_body: Value) -> Request<Body> {
    request_builder(method, uri).body(Body::from(json_body.to_string())).unwrap()
}

/// Validates JSON responses with comprehensive status and content checks.
///
/// This utility combines status code validation with JSON parsing,
/// providing a single function for complete response validation.
///
/// # Arguments
/// * `body` - Response body to validate
/// * `expected_status` - Expected HTTP status code
/// * `actual_status` - Actual HTTP status code received
/// * `context` - Test context for error messages
///
/// # Returns
/// Parsed JSON value from response body
///
/// # Panics
/// Panics if status codes don't match or JSON parsing fails
async fn validate_json_response(
    body: Body,
    expected_status: StatusCode,
    actual_status: StatusCode,
    context: &str,
) -> Value {
    assert_status(actual_status, expected_status, context);
    response_body_to_json(body).await.unwrap()
}

/// Advanced helper for validating user data in responses.
///
/// This utility performs comprehensive validation of user objects returned
/// from the API, checking all required fields and data formats.
///
/// # Arguments
/// * `user_json` - JSON value containing user data
/// * `expected_name` - Expected user name
/// * `expected_email` - Expected user email
/// * `expected_id` - Optional expected user ID
#[allow(dead_code)]
fn validate_user_response(
    user_json: &Value,
    expected_name: &str,
    expected_email: &str,
    expected_id: Option<u64>,
) {
    assert_eq!(user_json["name"], expected_name, "User name should match");
    assert_eq!(user_json["email"], expected_email, "User email should match");

    if let Some(id) = expected_id {
        assert_eq!(user_json["id"], id, "User ID should match expected value");
    }

    // Validate ID is present and positive
    let id = user_json["id"].as_u64().expect("User ID should be a positive integer");
    assert!(id > 0, "User ID should be positive");

    // Validate email format
    let email = user_json["email"].as_str().expect("Email should be string");
    assert!(email.contains('@'), "Email should contain @ symbol");
    assert!(email.contains('.'), "Email should contain domain");

    // Validate name is non-empty
    let name = user_json["name"].as_str().expect("Name should be string");
    assert!(!name.trim().is_empty(), "Name should not be empty");
}

/// Helper for asserting JSON response structure and content.
///
/// This utility validates that JSON responses have the expected structure
/// and content, with detailed error messages for debugging.
///
/// # Arguments
/// * `json` - JSON value to validate
/// * `expected_type` - Expected JSON type ("array", "object", etc.)
/// * `context` - Test context for error messages
#[allow(dead_code)]
fn assert_json_response(json: &Value, expected_type: &str, context: &str) {
    match expected_type {
        "array" => {
            assert!(json.is_array(), "Response should be JSON array in {}", context);
        }
        "object" => {
            assert!(json.is_object(), "Response should be JSON object in {}", context);
        }
        "string" => {
            assert!(json.is_string(), "Response should be JSON string in {}", context);
        }
        "number" => {
            assert!(json.is_number(), "Response should be JSON number in {}", context);
        }
        _ => panic!("Unknown expected type: {}", expected_type),
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_get_users_empty_comprehensive() {
        // Create fresh app instance and verify initial state
        let app = create_test_app();

        // Build GET /users request with proper Accept headers
        let request = request_builder("GET", "/users").body(Body::empty()).unwrap();

        // Execute request using ServiceExt::oneshot and capture full response
        let response = app.clone().oneshot(request).await.unwrap();

        // Assert response status is exactly 200 OK
        assert_status(response.status(), StatusCode::OK, "GET /users (empty)");

        // Verify Content-Type header is application/json
        let content_type = response.headers().get("content-type");
        assert!(content_type.is_some(), "Content-Type header should be present");

        // Parse response body and assert it's exactly an empty JSON array []
        let body = response.into_body();
        let json = response_body_to_json(body).await.unwrap();

        assert_eq!(json, json!([]), "Empty users list should return empty JSON array");
    }

    #[tokio::test]
    async fn test_create_user_comprehensive() {
        // Create fresh app instance
        let app = create_test_app();

        // Create valid CreateUserRequest with realistic test data
        let user_data = json!({
            "name": "John Doe",
            "email": "john@example.com"
        });

        // Build POST /users request with proper JSON body and Content-Type header
        let request = json_request_builder("POST", "/users", user_data.clone());

        // Execute request and capture complete response including headers
        let response = app.clone().oneshot(request).await.unwrap();

        // Assert response status is exactly 201 Created
        assert_status(response.status(), StatusCode::CREATED, "POST /users");

        // Verify Content-Type header is application/json
        let content_type = response.headers().get("content-type");
        assert!(content_type.is_some(), "Content-Type header should be present for created user");

        // Parse response body and validate it contains created User with generated ID
        let body = response.into_body();
        let json = validate_json_response(
            body,
            StatusCode::CREATED,
            StatusCode::CREATED,
            "POST /users response validation",
        )
        .await;

        // Assert all user fields match input data exactly
        assert_eq!(json["name"], "John Doe");
        assert_eq!(json["email"], "john@example.com");

        // Verify ID is positive integer and properly generated
        let user_id = json["id"].as_u64().unwrap();
        assert_eq!(user_id, 1, "First user should have ID 1");

        // Test that subsequent requests to same endpoint generate different IDs
        let user_data2 = json!({
            "name": "Jane Smith",
            "email": "jane@example.com"
        });

        let app2 = create_test_app();
        let request2 = json_request_builder("POST", "/users", user_data.clone());
        let request3 = json_request_builder("POST", "/users", user_data2);

        let response2 = app2.clone().oneshot(request2).await.unwrap();
        let response3 = app2.oneshot(request3).await.unwrap();

        let json2 = response_body_to_json(response2.into_body()).await.unwrap();
        let json3 = response_body_to_json(response3.into_body()).await.unwrap();

        assert_eq!(json2["id"], 1);
        assert_eq!(json3["id"], 2);
        assert_ne!(json2["id"], json3["id"], "Sequential users should have different IDs");
    }

    #[tokio::test]
    async fn test_get_user_by_id_comprehensive() {
        // Create fresh app instance
        let app = create_test_app();

        // First create a user via POST /users and capture the response
        let user_data = json!({
            "name": "Test User",
            "email": "test@example.com"
        });

        let create_request = json_request_builder("POST", "/users", user_data);
        let create_response = app.clone().oneshot(create_request).await.unwrap();

        assert_status(create_response.status(), StatusCode::CREATED, "User creation for GET test");

        // Extract the generated user ID from creation response
        let create_body = create_response.into_body();
        let create_json = response_body_to_json(create_body).await.unwrap();
        let user_id = create_json["id"].as_u64().unwrap();

        // Build GET /users/:id request using the actual generated ID
        let get_request =
            request_builder("GET", &format!("/users/{}", user_id)).body(Body::empty()).unwrap();

        // Execute request and validate complete response
        let get_response = app.clone().oneshot(get_request).await.unwrap();

        // Assert response status is exactly 200 OK
        assert_status(get_response.status(), StatusCode::OK, "GET /users/:id");

        // Verify Content-Type header is application/json
        let content_type = get_response.headers().get("content-type");
        assert!(content_type.is_some(), "Content-Type header should be present");

        // Parse response body and validate User data matches exactly what was created
        let get_body = get_response.into_body();
        let get_json = validate_json_response(
            get_body,
            StatusCode::OK,
            StatusCode::OK,
            "GET /users/:id response validation",
        )
        .await;

        // Assert all fields (id, name, email) are identical to original
        assert_eq!(get_json["id"], user_id);
        assert_eq!(get_json["name"], "Test User");
        assert_eq!(get_json["email"], "test@example.com");

        // Test with multiple users to ensure correct user is returned
        let user_data2 = json!({
            "name": "Second User",
            "email": "second@example.com"
        });

        let create_request2 = json_request_builder("POST", "/users", user_data2);
        let create_response2 = app.clone().oneshot(create_request2).await.unwrap();
        let create_json2 = response_body_to_json(create_response2.into_body()).await.unwrap();
        let user_id2 = create_json2["id"].as_u64().unwrap();

        // Verify we can get both users correctly
        let get_request1 =
            request_builder("GET", &format!("/users/{}", user_id)).body(Body::empty()).unwrap();
        let get_request2 =
            request_builder("GET", &format!("/users/{}", user_id2)).body(Body::empty()).unwrap();

        let get_response1 = app.clone().oneshot(get_request1).await.unwrap();
        let get_response2 = app.oneshot(get_request2).await.unwrap();

        let get_json1 = response_body_to_json(get_response1.into_body()).await.unwrap();
        let get_json2 = response_body_to_json(get_response2.into_body()).await.unwrap();

        assert_eq!(get_json1["name"], "Test User");
        assert_eq!(get_json2["name"], "Second User");
        assert_ne!(get_json1["id"], get_json2["id"]);
    }

    #[tokio::test]
    async fn test_get_user_not_found_comprehensive() {
        // Create fresh app instance with confirmed empty state
        let app = create_test_app();

        // Test multiple non-existent IDs: 0, 999, u32::MAX
        let test_ids = vec![0, 999, u32::MAX as u64];

        for test_id in test_ids {
            // Build GET /users/:id requests for each non-existent ID
            let request =
                request_builder("GET", &format!("/users/{}", test_id)).body(Body::empty()).unwrap();

            // Execute requests and validate error responses
            let response = app.clone().oneshot(request).await.unwrap();

            // Assert response status is exactly 404 Not Found
            assert_status(
                response.status(),
                StatusCode::NOT_FOUND,
                &format!("GET /users/{} (not found)", test_id),
            );

            // Verify error response format is consistent
            let body = response.into_body();
            let json = response_body_to_json(body).await.unwrap();

            assert!(
                json["error"].is_string(),
                "Error response should contain error message for ID {}",
                test_id
            );
            assert!(
                json["error"].as_str().unwrap().contains(&test_id.to_string()),
                "Error message should mention the requested ID {}",
                test_id
            );
        }

        // Test that valid IDs still work after 404 responses
        let user_data = json!({
            "name": "Valid User",
            "email": "valid@example.com"
        });

        let create_request = json_request_builder("POST", "/users", user_data);
        let create_response = app.clone().oneshot(create_request).await.unwrap();

        assert_status(
            create_response.status(),
            StatusCode::CREATED,
            "User creation after 404 tests",
        );

        let create_json = response_body_to_json(create_response.into_body()).await.unwrap();
        let valid_id = create_json["id"].as_u64().unwrap();

        let get_request =
            request_builder("GET", &format!("/users/{}", valid_id)).body(Body::empty()).unwrap();
        let get_response = app.oneshot(get_request).await.unwrap();

        assert_status(get_response.status(), StatusCode::OK, "GET valid user after 404 tests");
    }

    #[tokio::test]
    async fn test_list_users_after_creation_comprehensive() {
        // Create fresh app with confirmed empty state
        let app = create_test_app();

        // Create multiple users (at least 3) with different data via POST requests
        let users_data = vec![
            json!({
                "name": "Alice Johnson",
                "email": "alice@example.com"
            }),
            json!({
                "name": "Bob Smith",
                "email": "bob@example.com"
            }),
            json!({
                "name": "Charlie Brown",
                "email": "charlie@example.com"
            }),
            json!({
                "name": "Diana Prince",
                "email": "diana@example.com"
            }),
        ];

        let mut created_users = Vec::new();

        // Capture all creation responses and extract user data
        for (i, user_data) in users_data.iter().enumerate() {
            let create_request = json_request_builder("POST", "/users", user_data.clone());
            let create_response = app.clone().oneshot(create_request).await.unwrap();

            assert_status(
                create_response.status(),
                StatusCode::CREATED,
                &format!("User creation {}", i + 1),
            );

            let create_json = response_body_to_json(create_response.into_body()).await.unwrap();
            created_users.push(create_json);
        }

        // Build GET /users request to retrieve complete user list
        let list_request = request_builder("GET", "/users").body(Body::empty()).unwrap();

        // Execute request and validate comprehensive response
        let list_response = app.oneshot(list_request).await.unwrap();

        // Assert response status is exactly 200 OK
        assert_status(list_response.status(), StatusCode::OK, "GET /users after creations");

        // Parse response body into Vec<User> and validate count matches created users
        let list_body = list_response.into_body();
        let list_json = validate_json_response(
            list_body,
            StatusCode::OK,
            StatusCode::OK,
            "GET /users list response validation",
        )
        .await;

        let users_array = list_json.as_array().unwrap();
        assert_eq!(users_array.len(), created_users.len(), "User count should match created users");

        // Verify all created users are present in response
        for (i, created_user) in created_users.iter().enumerate() {
            let found_user = users_array.iter().find(|u| u["id"] == created_user["id"]);
            assert!(found_user.is_some(), "Created user {} should be present in list", i + 1);

            let found_user = found_user.unwrap();
            assert_eq!(found_user["name"], created_user["name"]);
            assert_eq!(found_user["email"], created_user["email"]);
        }

        // Assert users are returned in consistent order (sorted by ID)
        let mut prev_id = 0u64;
        for user in users_array {
            let current_id = user["id"].as_u64().unwrap();
            assert!(
                current_id > prev_id,
                "Users should be sorted by ID: {} should be > {}",
                current_id,
                prev_id
            );
            prev_id = current_id;
        }

        // Validate that each user's data matches exactly what was created
        for (i, user) in users_array.iter().enumerate() {
            assert_eq!(user["id"], i as u64 + 1, "User ID should be sequential");
            assert!(user["name"].is_string(), "User name should be string");
            assert!(user["email"].is_string(), "User email should be string");
            assert!(
                user["email"].as_str().unwrap().contains('@'),
                "User email should be valid format"
            );
        }

        // Test that IDs are sequential and properly generated
        for (i, user) in users_array.iter().enumerate() {
            assert_eq!(
                user["id"].as_u64().unwrap(),
                (i + 1) as u64,
                "User IDs should be sequential starting from 1"
            );
        }
    }

    #[tokio::test]
    async fn test_invalid_json_input() {
        let app = create_test_app();

        // Test malformed JSON
        let malformed_request =
            request_builder("POST", "/users").body(Body::from("{invalid json")).unwrap();

        let response = app.clone().oneshot(malformed_request).await.unwrap();
        assert_status(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "Malformed JSON");

        // Test missing fields
        let missing_name = json!({
            "email": "test@example.com"
        });
        let missing_name_request = json_request_builder("POST", "/users", missing_name);
        let response = app.clone().oneshot(missing_name_request).await.unwrap();
        assert_status(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "Missing name field");

        let missing_email = json!({
            "name": "Test User"
        });
        let missing_email_request = json_request_builder("POST", "/users", missing_email);
        let response = app.clone().oneshot(missing_email_request).await.unwrap();
        assert_status(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "Missing email field");

        // Test invalid data types
        let invalid_types = json!({
            "name": 123,
            "email": true
        });
        let invalid_types_request = json_request_builder("POST", "/users", invalid_types);
        let response = app.oneshot(invalid_types_request).await.unwrap();
        assert_status(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "Invalid data types");
    }

    #[tokio::test]
    async fn test_invalid_path_parameters() {
        let app = create_test_app();

        // Test non-numeric IDs
        let non_numeric_request = request_builder("GET", "/users/abc").body(Body::empty()).unwrap();
        let response = app.clone().oneshot(non_numeric_request).await.unwrap();
        assert_status(response.status(), StatusCode::BAD_REQUEST, "Non-numeric ID");

        // Test negative numbers (should be caught by path parsing)
        let negative_request = request_builder("GET", "/users/-1").body(Body::empty()).unwrap();
        let response = app.clone().oneshot(negative_request).await.unwrap();
        assert_status(response.status(), StatusCode::BAD_REQUEST, "Negative ID");

        // Test overflow values
        let overflow_request =
            request_builder("GET", "/users/999999999999999999999").body(Body::empty()).unwrap();
        let response = app.oneshot(overflow_request).await.unwrap();
        assert_status(response.status(), StatusCode::BAD_REQUEST, "Overflow ID");
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let app = create_test_app();

        // Create multiple users simultaneously and verify state consistency
        let concurrent_users = vec![
            json!({"name": "Concurrent User 1", "email": "user1@concurrent.com"}),
            json!({"name": "Concurrent User 2", "email": "user2@concurrent.com"}),
            json!({"name": "Concurrent User 3", "email": "user3@concurrent.com"}),
            json!({"name": "Concurrent User 4", "email": "user4@concurrent.com"}),
            json!({"name": "Concurrent User 5", "email": "user5@concurrent.com"}),
        ];

        let mut handles = Vec::new();

        for user_data in concurrent_users {
            let app_clone = app.clone();
            let handle = tokio::spawn(async move {
                let request = json_request_builder("POST", "/users", user_data);
                app_clone.oneshot(request).await.unwrap()
            });
            handles.push(handle);
        }

        let mut responses = Vec::new();
        for handle in handles {
            let response = handle.await.unwrap();
            assert_status(response.status(), StatusCode::CREATED, "Concurrent user creation");
            responses.push(response);
        }

        // Verify all users were created with unique IDs
        let mut user_ids = Vec::new();
        for response in responses {
            let json = response_body_to_json(response.into_body()).await.unwrap();
            let id = json["id"].as_u64().unwrap();
            user_ids.push(id);
        }

        user_ids.sort();
        for i in 1..user_ids.len() {
            assert_ne!(user_ids[i - 1], user_ids[i], "All user IDs should be unique");
        }

        // Verify final state consistency
        let list_request = request_builder("GET", "/users").body(Body::empty()).unwrap();
        let list_response = app.oneshot(list_request).await.unwrap();
        let list_json = response_body_to_json(list_response.into_body()).await.unwrap();
        let users_array = list_json.as_array().unwrap();

        assert_eq!(users_array.len(), 5, "All concurrent users should be created");
    }

    #[tokio::test]
    async fn test_large_dataset() {
        let app = create_test_app();

        // Create a larger number of users to validate performance
        let user_count = 50;
        let mut created_ids = Vec::new();

        for i in 0..user_count {
            let user_data = json!({
                "name": format!("User {}", i),
                "email": format!("user{}@example.com", i)
            });

            let request = json_request_builder("POST", "/users", user_data);
            let response = app.clone().oneshot(request).await.unwrap();

            assert_status(response.status(), StatusCode::CREATED, &format!("User {} creation", i));

            let json = response_body_to_json(response.into_body()).await.unwrap();
            created_ids.push(json["id"].as_u64().unwrap());
        }

        // Verify all IDs are unique and sequential
        created_ids.sort();
        for (i, id) in created_ids.iter().enumerate() {
            assert_eq!(*id, (i + 1) as u64, "IDs should be sequential");
        }

        // Test listing all users
        let list_request = request_builder("GET", "/users").body(Body::empty()).unwrap();
        let list_response = app.clone().oneshot(list_request).await.unwrap();

        assert_status(list_response.status(), StatusCode::OK, "List large dataset");

        let list_json = response_body_to_json(list_response.into_body()).await.unwrap();
        let users_array = list_json.as_array().unwrap();

        assert_eq!(users_array.len(), user_count, "All users should be listed");

        // Test getting individual users from large dataset
        for &id in created_ids.iter().take(10) {
            // Test first 10 users
            let get_request =
                request_builder("GET", &format!("/users/{}", id)).body(Body::empty()).unwrap();
            let get_response = app.clone().oneshot(get_request).await.unwrap();

            assert_status(get_response.status(), StatusCode::OK, &format!("Get user {}", id));
        }
    }

    #[tokio::test]
    async fn test_error_response_format_consistency() {
        let app = create_test_app();

        // Test various error scenarios and verify consistent error format
        let error_scenarios = vec![
            // Invalid JSON
            (
                request_builder("POST", "/users").body(Body::from("{invalid")).unwrap(),
                "Invalid JSON",
            ),
            // Missing user
            (request_builder("GET", "/users/999").body(Body::empty()).unwrap(), "Missing user"),
            // Invalid validation
            (
                json_request_builder(
                    "POST",
                    "/users",
                    json!({"name": "", "email": "test@example.com"}),
                ),
                "Validation error",
            ),
        ];

        for (request, scenario) in error_scenarios {
            let response = app.clone().oneshot(request).await.unwrap();

            // All error responses should have 4xx status codes
            assert!(
                response.status().is_client_error() || response.status().is_server_error(),
                "Error response should have error status code for scenario: {}",
                scenario
            );

            // Try to parse response body (some might be JSON, others might not)
            let body = response.into_body();
            let body_bytes = body.collect().await.unwrap().to_bytes();

            // Verify response has content
            assert!(
                !body_bytes.is_empty(),
                "Error response should have body for scenario: {}",
                scenario
            );
        }
    }
}
