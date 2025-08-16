# Design Document

## Overview

This design extends the existing Axum integration testing example with advanced production features including complete CRUD operations, database persistence with PostgreSQL/SQLite support, JWT authentication with role-based authorization, OpenAPI documentation generation, and comprehensive metrics/monitoring.

## Architecture

### Enhanced API Endpoints
- **GET /users** - List users with pagination and filtering
- **POST /users** - Create new users (authenticated)
- **GET /users/:id** - Get user by ID
- **PUT /users/:id** - Update existing user (authenticated, owner or admin)
- **DELETE /users/:id** - Delete user (authenticated, owner or admin)
- **POST /auth/login** - Authenticate and receive JWT token
- **POST /auth/register** - Register new user account
- **GET /health** - Health check endpoint
- **GET /metrics** - Prometheus metrics endpoint
- **GET /docs** - OpenAPI documentation (Swagger UI)

### Database Layer
- **Abstraction**: Repository pattern with trait-based database abstraction
- **PostgreSQL**: Production database with connection pooling
- **SQLite**: Development and testing database
- **Migrations**: Automatic schema management
- **Connection Management**: Pool-based connections with error handling

### Authentication & Authorization
- **JWT Tokens**: Stateless authentication with configurable expiration
- **Role-Based Access**: User roles (user, admin) with permission checking
- **Password Security**: Bcrypt hashing with salt
- **Token Validation**: Middleware for protected endpoints

## Components and Interfaces

### Enhanced Data Models

#### User Model (Extended)
```rust
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub role: UserRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    User,
    Admin,
}
```

#### Authentication Models
```rust
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserPublic,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i32,
    pub email: String,
    pub role: UserRole,
    pub exp: usize,
}
```

### Database Repository Pattern

#### Repository Trait
```rust
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(&self, user: CreateUserRequest, password_hash: String) -> Result<User, DbError>;
    async fn find_by_id(&self, id: i32) -> Result<Option<User>, DbError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DbError>;
    async fn list(&self, limit: i32, offset: i32) -> Result<Vec<User>, DbError>;
    async fn update(&self, id: i32, user: UpdateUserRequest) -> Result<Option<User>, DbError>;
    async fn delete(&self, id: i32) -> Result<bool, DbError>;
}
```

#### PostgreSQL Implementation
```rust
pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
```

#### SQLite Implementation
```rust
pub struct SqliteUserRepository {
    pool: SqlitePool,
}

impl SqliteUserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}
```

### Authentication Service

#### JWT Service
```rust
pub struct JwtService {
    secret: String,
    expiration: Duration,
}

impl JwtService {
    pub fn generate_token(&self, user: &User) -> Result<String, AuthError>;
    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError>;
}
```

#### Password Service
```rust
pub struct PasswordService;

impl PasswordService {
    pub fn hash_password(password: &str) -> Result<String, AuthError>;
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError>;
}
```

### Middleware Components

#### Authentication Middleware
```rust
pub async fn auth_middleware(
    State(jwt_service): State<Arc<JwtService>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode>;
```

#### Authorization Middleware
```rust
pub async fn require_role(
    required_role: UserRole,
) -> impl Fn(Request<Body>, Next) -> Pin<Box<dyn Future<Output = Result<Response, StatusCode>>>>;
```

#### Metrics Middleware
```rust
pub async fn metrics_middleware(
    req: Request<Body>,
    next: Next,
) -> Response;
```

## Data Models

### Database Schema

#### Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TYPE user_role AS ENUM ('user', 'admin');
CREATE INDEX idx_users_email ON users(email);
```

### Request/Response Models

#### Update User Request
```rust
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub email: Option<String>,
}
```

#### Paginated Response
```rust
#[derive(Debug, Serialize, ToSchema)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub page: i32,
    pub per_page: i32,
}
```

## Error Handling

### Enhanced Error Types
```rust
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Convert to appropriate HTTP status and JSON error response
    }
}
```

## OpenAPI Documentation

### Documentation Generation
- Use `utoipa` crate for automatic OpenAPI schema generation
- Document all endpoints with request/response schemas
- Include authentication security schemes
- Provide example requests and responses
- Generate interactive Swagger UI

### Schema Annotations
```rust
#[utoipa::path(
    post,
    path = "/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully", body = User),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 401, description = "Unauthorized", body = ErrorResponse)
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_user(/* ... */) -> impl IntoResponse {
    // Implementation
}
```

## Metrics and Monitoring

### Prometheus Metrics
- **Request Duration**: Histogram of response times by endpoint and method
- **Request Count**: Counter of requests by endpoint, method, and status code
- **Active Connections**: Gauge of current database connections
- **Error Rate**: Counter of errors by type and endpoint
- **Custom Business Metrics**: User creation rate, authentication attempts

### Health Checks
```rust
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub database: String,
    pub uptime: u64,
    pub version: String,
}
```

### Observability Stack
- **Metrics**: Prometheus metrics with custom collectors
- **Logging**: Structured logging with tracing and correlation IDs
- **Health Checks**: Deep health checks including database connectivity
- **Performance**: Request tracing and performance monitoring

## Testing Strategy

### Enhanced Test Coverage
- **Unit Tests**: Repository implementations, services, middleware
- **Integration Tests**: Complete API workflows with database
- **Authentication Tests**: Token generation, validation, role-based access
- **Database Tests**: Repository operations with test databases
- **Performance Tests**: Load testing with metrics validation

### Test Database Management
- **Isolated Test DBs**: Each test gets fresh database state
- **Transaction Rollback**: Tests run in transactions that rollback
- **Migration Testing**: Verify schema migrations work correctly
- **Connection Pool Testing**: Validate pool behavior under load

## Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost/dbname
DATABASE_MAX_CONNECTIONS=10

# Authentication
JWT_SECRET=your-secret-key
JWT_EXPIRATION_HOURS=24

# Server
BIND_ADDR=127.0.0.1:3000
LOG_LEVEL=info

# Metrics
METRICS_ENABLED=true
METRICS_PATH=/metrics
```

### Configuration Structure
```rust
#[derive(Debug, Clone)]
pub struct Config {
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub server: ServerConfig,
    pub metrics: MetricsConfig,
}
```

## Implementation Notes

### Dependencies Required
- `sqlx` - Database operations with compile-time checked queries
- `jsonwebtoken` - JWT token handling
- `bcrypt` - Password hashing
- `utoipa` - OpenAPI documentation generation
- `utoipa-swagger-ui` - Swagger UI serving
- `prometheus` - Metrics collection
- `tracing` - Structured logging and observability

### Security Considerations
- Password hashing with bcrypt and proper salt
- JWT secret management and rotation
- SQL injection prevention with parameterized queries
- Rate limiting on authentication endpoints
- CORS configuration for browser clients
- Input validation and sanitization

### Performance Optimizations
- Database connection pooling
- Query optimization with indexes
- Response caching where appropriate
- Async/await throughout the stack
- Efficient serialization with serde
- Metrics collection with minimal overhead