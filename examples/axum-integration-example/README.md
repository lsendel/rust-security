# Axum Integration Testing Example

This project demonstrates comprehensive integration testing patterns for Axum REST APIs in Rust. It showcases production-quality testing techniques using in-process testing with `tower::ServiceExt::oneshot`.

## Features

### Complete REST API
- **GET /users** - List all users
- **POST /users** - Create a new user  
- **GET /users/:id** - Get user by ID

### Production-Ready Implementation
- Thread-safe in-memory storage with `Arc<Mutex<HashMap>>`
- Comprehensive input validation
- Proper error handling with detailed error messages
- Graceful shutdown support
- Configurable via environment variables

### Comprehensive Testing
- **Unit Tests** - Data model validation and business logic
- **Integration Tests** - Complete HTTP request/response testing
- **Error Handling Tests** - Invalid input and edge cases
- **Concurrent Testing** - Thread safety validation
- **Performance Tests** - Large dataset handling

## Key Testing Patterns Demonstrated

### In-Process Testing with tower::ServiceExt
```rust
let app = create_test_app();
let request = json_request_builder("POST", "/users", json!({
    "name": "John Doe",
    "email": "john@example.com"
}));

let response = app.oneshot(request).await.unwrap();
assert_eq!(response.status(), StatusCode::CREATED);
```

### State Isolation
- Each test creates a fresh app instance
- No shared state between tests
- Safe parallel test execution

### Comprehensive Validation
- Status code verification with context
- Header validation (Content-Type, etc.)
- JSON response parsing and validation
- Error message format consistency

## Running the Example

### Start the Server
```bash
cargo run -p axum-integration-example
```

The server will start on `http://127.0.0.1:3000` by default.

### Configure Bind Address
```bash
BIND_ADDR="127.0.0.1:8080" cargo run -p axum-integration-example
```

### Run Tests
```bash
# Run all tests
cargo test -p axum-integration-example

# Run only integration tests
cargo test -p axum-integration-example --test integration

# Run specific test
cargo test -p axum-integration-example test_create_user_comprehensive
```

## API Usage Examples

### Create a User
```bash
curl -X POST http://127.0.0.1:3000/users \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com"}'
```

### List All Users
```bash
curl http://127.0.0.1:3000/users
```

### Get User by ID
```bash
curl http://127.0.0.1:3000/users/1
```

## Project Structure

```
axum-integration-example/
├── src/
│   ├── lib.rs          # Core application logic and handlers
│   └── main.rs         # Binary entry point
├── tests/
│   └── integration.rs  # Comprehensive integration tests
├── Cargo.toml          # Dependencies and configuration
└── README.md           # This file
```

## Dependencies

### Core Dependencies
- `axum` - Web framework with JSON support
- `tokio` - Async runtime
- `tower` - Service utilities
- `serde` - JSON serialization
- `serde_json` - JSON handling

### Testing Dependencies
- `http` - HTTP types for testing
- `http-body-util` - Body utilities for request building
- `tower` (testing features) - Service testing utilities

## Testing Architecture

### Unit Tests (`src/lib.rs`)
- Data model validation
- Business logic testing
- State management verification

### Integration Tests (`tests/integration.rs`)
- Complete HTTP request/response cycles
- Multi-step workflows (create then retrieve)
- Error scenario validation
- Concurrent operation testing
- Large dataset performance testing

## Key Testing Utilities

### Helper Functions
- `create_test_app()` - Fresh app instances
- `json_request_builder()` - JSON request construction
- `response_body_to_json()` - Response parsing
- `assert_status()` - Status code validation
- `validate_json_response()` - Complete response validation

### Test Categories
1. **Basic CRUD Operations** - Standard create, read, list operations
2. **Error Handling** - Invalid input, missing resources, malformed requests
3. **Edge Cases** - Boundary values, concurrent access, large datasets
4. **Integration Workflows** - Multi-step operations, state consistency

## Best Practices Demonstrated

### Testing Best Practices
- State isolation between tests
- Comprehensive error scenario coverage
- Realistic test data and edge cases
- Clear test naming and documentation
- Proper async test handling

### API Design Best Practices
- RESTful endpoint design
- Consistent error response format
- Proper HTTP status codes
- Input validation and sanitization
- Thread-safe state management

### Code Organization
- Separation of concerns (handlers, models, state)
- Reusable application factory function
- Comprehensive error handling
- Production-ready configuration

This example serves as a complete reference for implementing and testing Axum REST APIs with production-quality patterns and comprehensive test coverage.