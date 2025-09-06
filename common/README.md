# Common Crate

Common types, utilities, and shared components for the Rust Security Platform.

## Overview

The `common` crate provides shared types, utilities, and components used across multiple services in the Rust Security Platform. This crate helps maintain consistency and reduce code duplication between services.

## Features

### Shared Types
- **Authentication Types**: User, Client, Token, Session types
- **Authorization Types**: Principal, Action, Resource, Context types
- **Security Types**: Error types, validation types, crypto types
- **API Types**: Request/response types, pagination types

### Utilities
- **Crypto Utilities**: Hashing, encryption, random generation
- **Validation Utilities**: Input validation, sanitization
- **Error Handling**: Common error types and handling patterns
- **Configuration**: Configuration utilities and validation

### Components
- **Database Abstractions**: Generic database interfaces
- **Cache Abstractions**: Generic caching interfaces
- **Rate Limiting**: Shared rate limiting components
- **Logging**: Shared logging utilities

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        COMMON CRATE                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Types     │  │  Utilities  │  │ Components  │         │
│  │             │  │             │  │             │         │
│  │ • Auth      │  │ • Crypto    │  │ • Database  │         │
│  │ • Authz     │  │ • Validation│  │ • Cache     │         │
│  │ • Security  │  │ • Error     │  │ • Rate      │         │
│  │ • API       │  │ • Config    │  │   Limiting  │         │
│  └─────────────┘  │ • Logging   │  │ • Logging   │         │
│                   └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

## Key Modules

### Authentication Types (`auth`)

Shared authentication-related types used across services:

```rust
// User types
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

// Client types
pub struct Client {
    pub id: String,
    pub secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<GrantType>,
}

// Token types
pub struct Token {
    pub value: String,
    pub user_id: String,
    pub client_id: String,
    pub scope: Vec<String>,
    pub expires_at: DateTime<Utc>,
}
```

### Authorization Types (`authz`)

Shared authorization-related types:

```rust
// Principal types
pub struct Principal {
    pub ty: String,
    pub id: String,
    pub attributes: HashMap<String, serde_json::Value>,
}

// Action types
pub struct Action {
    pub ty: String,
    pub id: String,
}

// Resource types
pub struct Resource {
    pub ty: String,
    pub id: String,
    pub attributes: HashMap<String, serde_json::Value>,
}
```

### Security Types (`security`)

Security-related types and utilities:

```rust
// Error types
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Invalid credentials for user {user_id}")]
    InvalidCredentials { user_id: String },
    
    #[error("Account {user_id} is locked until {unlock_time}")]
    AccountLocked { 
        user_id: String, 
        unlock_time: DateTime<Utc> 
    },
    
    #[error("Token expired at {expired_at}")]
    TokenExpired { 
        expired_at: DateTime<Utc>, 
        token_type: String 
    },
}

// Validation utilities
pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() < 8 {
        return Err(ValidationError::TooShort);
    }
    
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(ValidationError::MissingUppercase);
    }
    
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(ValidationError::MissingLowercase);
    }
    
    if !password.chars().any(|c| c.is_numeric()) {
        return Err(ValidationError::MissingNumber);
    }
    
    Ok(())
}
```

### Database Abstractions (`database`)

Generic database interfaces and utilities:

```rust
// Database connection traits
#[async_trait]
pub trait DatabaseConnection: Send + Sync {
    async fn execute(&self, query: &str, params: &[&dyn ToSql]) -> Result<u64, DatabaseError>;
    async fn query_one<T>(&self, query: &str, params: &[&dyn ToSql]) -> Result<T, DatabaseError>
    where
        T: FromRow;
    async fn query_all<T>(&self, query: &str, params: &[&dyn ToSql]) -> Result<Vec<T>, DatabaseError>
    where
        T: FromRow;
}

// Connection pool
pub struct DatabasePool {
    pool: PgPool,
}

impl DatabasePool {
    pub async fn new(config: &DatabaseConfig) -> Result<Self, DatabaseError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&config.url)
            .await?;
            
        Ok(Self { pool })
    }
}
```

### Cache Abstractions (`cache`)

Generic caching interfaces and implementations:

```rust
// Cache traits
#[async_trait]
pub trait Cache: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, CacheError>;
    async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError>;
    async fn delete(&self, key: &str) -> Result<(), CacheError>;
    async fn exists(&self, key: &str) -> Result<bool, CacheError>;
}

// Redis cache implementation
pub struct RedisCache {
    client: RedisClient,
}

impl RedisCache {
    pub async fn new(config: &RedisConfig) -> Result<Self, CacheError> {
        let client = RedisClient::new(config.url.clone());
        Ok(Self { client })
    }
}
```

## Configuration

### Environment Variables

The common crate uses several environment variables for configuration:

```bash
# Database configuration
DATABASE_URL=postgresql://user:pass@localhost:5432/auth_service
DATABASE_MAX_CONNECTIONS=10

# Redis configuration
REDIS_URL=redis://localhost:6379
REDIS_MAX_CONNECTIONS=10

# Security configuration
JWT_SECRET=your-super-secure-jwt-secret-key-32-chars-min
PASSWORD_MIN_LENGTH=8
```

### Configuration Structs

```rust
// Database configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}

// Redis configuration
#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}

// Security configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub password_min_length: usize,
    pub password_require_uppercase: bool,
    pub password_require_lowercase: bool,
    pub password_require_numbers: bool,
    pub password_require_special_chars: bool,
}
```

## Usage

### In Cargo.toml

```toml
[dependencies]
common = { path = "../common" }
```

### In Rust Code

```rust
// Import shared types
use common::auth::{User, Client, Token};
use common::authz::{Principal, Action, Resource};
use common::security::SecurityError;
use common::database::DatabasePool;
use common::cache::RedisCache;

// Use shared utilities
use common::crypto::{hash_password, verify_password};
use common::validation::validate_email;
use common::error::handle_error;

// Example usage
fn authenticate_user(username: &str, password: &str) -> Result<User, SecurityError> {
    // Validate input
    if !validate_email(username) {
        return Err(SecurityError::InvalidCredentials {
            user_id: username.to_string(),
        });
    }
    
    // Hash password for comparison
    let password_hash = hash_password(password)?;
    
    // Continue with authentication logic...
    Ok(User {
        id: "user123".to_string(),
        username: username.to_string(),
        // ... other fields
    })
}
```

## Testing

### Unit Tests

```bash
# Run unit tests
cargo test -p common --lib

# Run specific test
cargo test -p common test_password_validation
```

### Integration Tests

```bash
# Run integration tests
cargo test -p common --test '*'
```

## Performance

### Benchmarks

The common crate is designed for performance with:

- **Zero-copy operations** where possible
- **Efficient memory usage**
- **Async/await support** for non-blocking operations
- **Connection pooling** for database and cache operations

### Optimization Strategies

- **Lazy initialization** for expensive resources
- **Caching** for frequently accessed data
- **Batch operations** for bulk processing
- **Memory pooling** for temporary allocations

## Security

### Security Features

- **Input validation** for all external data
- **Password hashing** with Argon2
- **Secure random generation** for tokens and keys
- **Memory zeroing** for sensitive data
- **Constant-time comparisons** for security-critical operations

### Threat Protection

- **SQL injection prevention** with parameterized queries
- **XSS prevention** with proper output encoding
- **CSRF protection** with token validation
- **Rate limiting** for API endpoints

## Contributing

### Development Setup

```bash
# Run tests
cargo test -p common

# Run linter
cargo clippy -p common

# Format code
cargo fmt -p common
```

### Code Standards

- Follow Rust naming conventions
- Write comprehensive documentation
- Include tests for new functionality
- Maintain 80%+ test coverage
- Use error handling appropriately
- Follow security best practices

## Documentation

For comprehensive documentation, see:
- [API Reference](../docs/03-api-reference/README.md)
- [Architecture Documentation](../docs/02-core-concepts/components.md)

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.