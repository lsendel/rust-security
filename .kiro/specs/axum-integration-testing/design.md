# Design Document

## Overview

This design outlines a comprehensive example of integration testing for Axum REST APIs in Rust. The example demonstrates production-quality patterns including shared application state, proper error handling, and thorough integration testing using in-process testing techniques.

## Architecture

### Application Structure
- **Library crate** (`src/lib.rs`): Contains the main application logic, routes, and `create_app()` function
- **Binary crate** (`src/main.rs`): Simple entry point that calls the library's app creation function
- **Integration tests** (`tests/integration.rs`): Comprehensive test suite using tower's testing utilities

### State Management
- Uses `Arc<Mutex<HashMap<u32, User>>>` for thread-safe in-memory user storage
- Shared state is injected into Axum's application state for access across handlers
- Simple auto-incrementing ID generation for user creation

## Components and Interfaces

### Core Components

#### User Model
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: u32,
    pub name: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub name: String,
    pub email: String,
}
```

#### Application State
```rust
#[derive(Clone)]
pub struct AppState {
    pub users: Arc<Mutex<HashMap<u32, User>>>,
    pub next_id: Arc<Mutex<u32>>,
}
```

#### API Endpoints

1. **GET /users** - List all users
   - Returns: `Vec<User>` as JSON
   - Status: 200 OK

2. **POST /users** - Create new user
   - Input: `CreateUserRequest` as JSON
   - Returns: Created `User` as JSON
   - Status: 201 Created

3. **GET /users/:id** - Get user by ID
   - Input: Path parameter `id`
   - Returns: `User` as JSON (200) or error (404)
   - Status: 200 OK or 404 Not Found

### Route Handlers

#### List Users Handler
- Extracts shared state from Axum's state
- Locks the users HashMap and returns all values as a vector
- Always returns 200 OK with JSON array

#### Create User Handler
- Validates JSON input using Axum's JSON extractor
- Generates new ID atomically
- Stores user in shared HashMap
- Returns created user with 201 status

#### Get User Handler
- Extracts user ID from path parameters
- Looks up user in shared HashMap
- Returns user data or 404 if not found

## Data Models

### User Entity
- **id**: Unique identifier (u32, auto-generated)
- **name**: User's display name (String, required)
- **email**: User's email address (String, required)

### Request/Response Models
- **CreateUserRequest**: Input model for user creation (excludes ID)
- **User**: Complete user model for responses
- All models implement Serialize/Deserialize for JSON handling

## Error Handling

### HTTP Status Codes
- **200 OK**: Successful GET requests
- **201 Created**: Successful user creation
- **404 Not Found**: User not found by ID
- **400 Bad Request**: Invalid JSON input (handled by Axum)

### Error Response Format
- Uses Axum's built-in error handling for JSON parsing errors
- Custom 404 responses for missing users
- Consistent JSON error format where applicable

## Testing Strategy

### Integration Test Architecture
- **In-process testing**: Uses `tower::ServiceExt::oneshot` to call the app directly
- **No external dependencies**: All state is in-memory, no database or network calls
- **Isolated test cases**: Each test creates a fresh app instance
- **Async testing**: Uses `tokio::test` for proper async test execution

### Test Cases

#### Test 1: Empty User List
- **Setup**: Create fresh app with empty state
- **Action**: GET /users
- **Assertions**: 
  - Status code 200
  - Response body is empty JSON array
  - Content-Type is application/json

#### Test 2: Create User
- **Setup**: Create fresh app
- **Action**: POST /users with valid JSON
- **Assertions**:
  - Status code 201
  - Response contains created user with ID
  - User data matches input

#### Test 3: Get Created User
- **Setup**: Create app and add a user
- **Action**: GET /users/:id for the created user
- **Assertions**:
  - Status code 200
  - Response contains correct user data
  - All fields match expected values

#### Test 4: Get Non-existent User
- **Setup**: Create fresh app (no users)
- **Action**: GET /users/999 (non-existent ID)
- **Assertions**:
  - Status code 404
  - Appropriate error response

#### Test 5: List Users After Creation
- **Setup**: Create app and add multiple users
- **Action**: GET /users
- **Assertions**:
  - Status code 200
  - Response contains all created users
  - User count matches expected

### Testing Utilities

#### App Creation Helper
```rust
fn create_test_app() -> Router {
    create_app()
}
```

#### Request Building Helpers
- JSON request construction utilities
- Path parameter handling
- Header management for content types

#### Response Assertion Helpers
- Status code verification
- JSON body parsing and validation
- Content-Type header checking

### Test Execution Flow
1. Create fresh app instance for each test
2. Build HTTP request using tower's testing utilities
3. Execute request using `oneshot`
4. Assert response status, headers, and body
5. Parse JSON responses for detailed validation

## Implementation Notes

### Dependencies Required
- `axum` - Web framework with JSON support
- `tokio` - Async runtime for tests
- `tower` - Service utilities for testing
- `serde` - JSON serialization
- `serde_json` - JSON parsing in tests

### Key Testing Patterns
- **Service trait usage**: Leverages tower's Service trait for in-process testing
- **Oneshot requests**: Uses `ServiceExt::oneshot` for single request testing
- **Async test handling**: Proper use of `tokio::test` macro
- **State isolation**: Each test gets fresh application state
- **JSON handling**: Comprehensive JSON request/response testing

### Performance Considerations
- In-memory storage keeps tests fast
- No network I/O or external dependencies
- Minimal setup/teardown overhead
- Parallel test execution safe due to isolated state