# Implementation Plan

- [x] 1. Set up project structure and dependencies
  - Add required dependencies to Cargo.toml: axum with macros, tokio with full features, tower with util feature, serde with derive, serde_json
  - Configure dev-dependencies for testing: tower with testing features, http-body-util for request building
  - Ensure proper feature flags are set for async testing and JSON handling
  - _Requirements: 1.1, 1.4_

- [x] 2. Implement complete data models with full validation
  - Create User struct with id: u32, name: String, email: String and full serde support
  - Create CreateUserRequest struct with name: String, email: String for input validation
  - Implement AppState struct with users: Arc<Mutex<HashMap<u32, User>>> and next_id: Arc<Mutex<u32>>
  - Add comprehensive Debug, Clone, Serialize, Deserialize derives
  - Include validation logic for email format and name length constraints
  - _Requirements: 3.1, 3.2, 3.5_

- [x] 3. Implement complete GET /users endpoint with full functionality
  - Create async list_users handler that extracts State<AppState>
  - Implement proper mutex locking with error handling for lock poisoning
  - Collect all users from HashMap into Vec<User> and sort by ID for consistent ordering
  - Return Json<Vec<User>> with proper content-type headers
  - Handle empty state gracefully returning empty array
  - Add proper error handling for any state access failures
  - _Requirements: 2.2, 3.4, 3.3_

- [x] 4. Implement complete POST /users endpoint with validation
  - Create async create_user handler accepting Json<CreateUserRequest>
  - Implement atomic ID generation with proper mutex handling
  - Validate input data (non-empty name, valid email format)
  - Create User instance with generated ID and validated request data
  - Store user in HashMap with proper error handling
  - Return (StatusCode::CREATED, Json<User>) tuple for 201 response
  - Handle all potential errors: JSON parsing, validation, state access
  - _Requirements: 2.3, 3.1, 3.2, 3.3_

- [x] 5. Implement complete GET /users/:id endpoint with error handling
  - Create async get_user handler that extracts Path<u32> for user ID
  - Extract State<AppState> and safely access users HashMap
  - Implement user lookup with proper Option handling
  - Return Json<User> with 200 status for found users
  - Return StatusCode::NOT_FOUND for missing users
  - Handle invalid ID formats and state access errors
  - Use proper Result<impl IntoResponse, impl IntoResponse> return type
  - _Requirements: 2.4, 2.5, 3.3_

- [x] 6. Create complete application factory with full router setup
  - Implement public create_app() function returning Router
  - Initialize AppState with empty HashMap and ID counter starting at 1
  - Set up complete Axum router with all three endpoints: GET /users, POST /users, GET /users/:id
  - Configure proper middleware stack including JSON parsing limits
  - Add request tracing and error handling middleware
  - Ensure router is fully configured and ready for both testing and production use
  - _Requirements: 1.1, 1.3, 1.2_

- [x] 7. Create production-ready binary entry point
  - Implement src/main.rs with complete tokio setup
  - Call create_app() and bind to configurable address (default 127.0.0.1:3000)
  - Add proper startup logging and graceful shutdown handling
  - Include error handling for server startup failures
  - Keep binary minimal but production-ready
  - _Requirements: 1.1_

- [x] 8. Create comprehensive integration test infrastructure
  - Create tests/integration.rs with complete test setup
  - Import all necessary dependencies: tower::ServiceExt, http::Request, http_body_util::BodyExt, serde_json
  - Create create_test_app() helper that returns fresh Router instance
  - Implement request_builder helper for constructing HTTP requests with proper headers
  - Create response_body_to_json helper for parsing response bodies
  - Add assert_status helper for comprehensive status code validation
  - Set up proper async test environment with tokio::test
  - _Requirements: 2.1, 2.6, 4.3, 4.2_

- [x] 9. Implement comprehensive test for empty user list endpoint
  - Write test_get_users_empty() with detailed validation
  - Create fresh app instance and verify initial state
  - Build GET /users request with proper Accept headers
  - Execute request using ServiceExt::oneshot and capture full response
  - Assert response status is exactly 200 OK
  - Verify Content-Type header is application/json
  - Parse response body and assert it's exactly an empty JSON array []
  - Validate response timing and ensure no side effects on app state
  - _Requirements: 2.2, 2.6, 2.7, 4.1, 4.4_

- [x] 10. Implement comprehensive test for user creation endpoint
  - Write test_create_user() with full request/response validation
  - Create valid CreateUserRequest with realistic test data
  - Build POST /users request with proper JSON body and Content-Type header
  - Execute request and capture complete response including headers
  - Assert response status is exactly 201 Created
  - Verify Content-Type header is application/json
  - Parse response body and validate it contains created User with generated ID
  - Assert all user fields match input data exactly
  - Verify ID is positive integer and properly generated
  - Test that subsequent requests to same endpoint generate different IDs
  - _Requirements: 2.3, 2.6, 2.7, 4.1, 4.4_

- [x] 11. Implement comprehensive test for getting existing user by ID
  - Write test_get_user_by_id() with multi-step validation
  - First create a user via POST /users and capture the response
  - Extract the generated user ID from creation response
  - Build GET /users/:id request using the actual generated ID
  - Execute request and validate complete response
  - Assert response status is exactly 200 OK
  - Verify Content-Type header is application/json
  - Parse response body and validate User data matches exactly what was created
  - Assert all fields (id, name, email) are identical to original
  - Test with multiple users to ensure correct user is returned
  - _Requirements: 2.4, 2.6, 2.7, 4.1, 4.4_

- [x] 12. Implement comprehensive test for non-existent user endpoint
  - Write test_get_user_not_found() with detailed error validation
  - Create fresh app instance with confirmed empty state
  - Test multiple non-existent IDs: 0, 999, u32::MAX
  - Build GET /users/:id requests for each non-existent ID
  - Execute requests and validate error responses
  - Assert response status is exactly 404 Not Found
  - Verify error response format is consistent
  - Test that valid IDs still work after 404 responses
  - Ensure no side effects on application state
  - _Requirements: 2.5, 2.6, 2.7, 4.1, 4.4_

- [x] 13. Implement comprehensive test for user list after multiple creations
  - Write test_list_users_after_creation() with full state validation
  - Create multiple users (at least 3) with different data via POST requests
  - Capture all creation responses and extract user data
  - Build GET /users request to retrieve complete user list
  - Execute request and validate comprehensive response
  - Assert response status is exactly 200 OK
  - Parse response body into Vec<User> and validate count matches created users
  - Verify all created users are present in response
  - Assert users are returned in consistent order (sorted by ID)
  - Validate that each user's data matches exactly what was created
  - Test that IDs are sequential and properly generated
  - _Requirements: 2.2, 4.1, 4.4_

- [x] 14. Implement comprehensive error handling and edge case tests
  - Write test_invalid_json_input() for POST endpoint error handling
  - Test malformed JSON, missing fields, invalid data types
  - Write test_invalid_path_parameters() for GET /:id endpoint
  - Test non-numeric IDs, negative numbers, overflow values
  - Write test_concurrent_operations() to validate thread safety
  - Create multiple users simultaneously and verify state consistency
  - Write test_large_dataset() to validate performance with many users
  - Verify all error responses have proper status codes and consistent format
  - _Requirements: 3.2, 3.3, 4.1, 3.5_

- [x] 15. Add comprehensive test utilities and documentation
  - Create detailed helper functions with full error handling
  - Implement json_request_builder for consistent request construction
  - Add validate_user_response for comprehensive user data validation
  - Create assert_json_response for detailed response validation
  - Add extensive documentation comments explaining tower::ServiceExt usage
  - Document oneshot pattern and why it's preferred for integration testing
  - Include examples of proper async test setup and execution
  - Add comments explaining state isolation and test independence
  - _Requirements: 4.2, 4.3, 4.5_

- [x] 16. Verify complete integration and add final validation
  - Run complete test suite and ensure all tests pass independently
  - Verify tests can run in parallel without interference
  - Add module-level documentation explaining the complete testing approach
  - Include comprehensive examples of all testing patterns used
  - Validate that the implementation covers all requirements completely
  - Ensure the example demonstrates production-quality integration testing
  - Add performance benchmarks for test execution time
  - _Requirements: 4.5, 2.7, 4.2_