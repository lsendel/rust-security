# Technical Architecture

> Last Updated: 2025-08-16
> Version: 1.0.0
> Source: Codebase Analysis

## Detected Technologies

### Core Stack
- **Language**: Rust 1.70+ (Edition 2021)
- **Runtime**: Tokio 1.0 (async/await, multi-threaded)
- **Web Framework**: Axum 0.7 with tower middleware ecosystem
- **HTTP Client**: Reqwest 0.12 with rustls-tls
- **Serialization**: Serde 1.0 with JSON support
- **Configuration**: Environment variables with envy 0.4
- **Logging**: Tracing 0.1 with structured logging
- **UUID Generation**: UUID 1.0 with v4 support
- **Error Handling**: Thiserror 1.0 and anyhow 1.0

### Authentication & Security
- **JWT**: jsonwebtoken 9.0 with RS256 algorithm
- **Cryptography**: RSA 0.9 for key generation
- **Password Hashing**: Argon2 0.5 with salt generation
- **HMAC**: hmac 0.12 for request signing
- **Hashing**: SHA1 0.10, SHA2 0.10
- **Encryption**: AES-GCM 0.10 for symmetric encryption
- **Random Generation**: rand 0.8, getrandom 0.2
- **Encoding**: base64 0.21, data-encoding 2.6

### Data Storage
- **In-Memory**: HashMap with RwLock synchronization
- **Redis**: redis 0.32 with async support and connection manager
- **Time Management**: once_cell 1.0 for lazy statics
- **Collections**: Standard library HashMap, HashSet

### Authorization & Policies
- **Cedar Engine**: cedar-policy for attribute-based access control
- **Policy Language**: Cedar DSL for fine-grained authorization
- **Entity Management**: JSON-based entity definitions

### API & Documentation
- **OpenAPI**: utoipa 4.0 with axum integration
- **Swagger UI**: utoipa-swagger-ui 6.0 (optional)
- **Request Validation**: validator 0.20 with derive macros
- **CORS**: tower-http 0.6 CORS middleware

### Development & Testing
- **Testing**: Built-in Rust test framework with tokio-test
- **HTTP Testing**: reqwest for integration tests
- **Mocking**: In-memory implementations for testing
- **Coverage**: Compatible with tarpaulin

### Infrastructure & Deployment
- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Kubernetes with security policies
- **Service Mesh**: Ready for Istio/Linkerd integration
- **TLS**: axum-server 0.7 with rustls support
- **Certificate Management**: rcgen 0.13 for self-signed certs

### Monitoring & Observability
- **Metrics**: prometheus 0.13 for custom metrics
- **Health Checks**: Custom health endpoint implementation
- **Distributed Tracing**: OpenTelemetry (optional feature)
- **Jaeger Integration**: opentelemetry-jaeger (optional)
- **Request IDs**: tower-http request ID propagation

### Security Hardening
- **Secret Management**: secrecy 0.10 for sensitive data
- **Rate Limiting**: Custom implementation with sliding windows
- **Input Sanitization**: Custom validation functions
- **Security Headers**: Comprehensive header middleware
- **Audit Logging**: Structured audit events

## Dependencies

### Major Libraries and Their Purposes

#### Web Framework Stack
- **axum**: Modern async web framework with excellent type safety
- **tower**: Middleware ecosystem for composable services
- **tower-http**: HTTP-specific middleware (CORS, tracing, limits)
- **hyper**: Low-level HTTP implementation

#### Security Libraries
- **argon2**: Industry-standard password hashing
- **jsonwebtoken**: JWT token creation and validation
- **rsa**: RSA key pair generation and operations
- **hmac**: HMAC-based request signing
- **validator**: Input validation with derive macros

#### Data Handling
- **serde**: Serialization/deserialization framework
- **redis**: Redis client with async support
- **uuid**: UUID generation for tokens and IDs
- **chrono**: Date/time handling with serialization

#### Development Tools
- **anyhow**: Error handling for applications
- **thiserror**: Error handling for libraries
- **tracing**: Structured, async-aware logging
- **once_cell**: Thread-safe lazy initialization

## Development Setup

### Inferred from Config Files

#### Build Configuration
```toml
# Cargo workspace with multiple services
[workspace]
members = ["auth-service", "policy-service"]
resolver = "2"

# Rust toolchain pinned for consistency
channel = "stable"
components = ["rustfmt", "clippy"]
```

#### Feature Flags
- `docs`: Enables Swagger UI documentation
- `vault`: HashiCorp Vault integration (optional)
- `aws`: AWS Secrets Manager integration (optional)
- `tracing`: Distributed tracing support (optional)

#### Development Dependencies
- Comprehensive integration test suite
- HTTP client testing with reqwest
- Async test support with tokio-test
- JSON assertion helpers

## Architecture Patterns

### Pattern: Microservices Architecture
- **Implementation**: Separate auth-service and policy-service
- **Communication**: HTTP APIs with JSON payloads
- **Rationale**: Separation of concerns, independent scaling

### Pattern: Hexagonal Architecture
- **Implementation**: Clear separation of domain, application, and infrastructure layers
- **Ports**: Trait-based abstractions for storage and external services
- **Adapters**: Redis and in-memory implementations

### Pattern: Middleware Pipeline
- **Implementation**: Tower middleware for cross-cutting concerns
- **Components**: Security headers, rate limiting, request IDs, CORS
- **Rationale**: Composable, reusable, and testable middleware

### Pattern: Configuration as Code
- **Implementation**: Environment variable-based configuration
- **Validation**: Startup-time configuration validation
- **Rationale**: 12-factor app compliance, secure defaults

### Pattern: Error Handling Strategy
- **Implementation**: Result-based error handling with custom error types
- **Propagation**: ? operator with From trait implementations
- **Rationale**: Explicit error handling, no panics in production

### Pattern: Async/Await Throughout
- **Implementation**: Full async stack from HTTP handlers to storage
- **Runtime**: Tokio multi-threaded runtime
- **Rationale**: High concurrency, efficient resource usage

## Recommendations

### Technical Debt
- **Token Storage Optimization**: Implement connection pooling for Redis
- **Caching Layer**: Add caching for frequently accessed policies
- **Metrics Enhancement**: Add more detailed performance metrics
- **Error Context**: Improve error messages for better debugging

### Modernization Opportunities
- **gRPC Support**: Add gRPC endpoints for service-to-service communication
- **GraphQL Layer**: Consider GraphQL for complex queries
- **Message Queue**: Add async processing with message queues
- **Database Integration**: Consider persistent storage for policies and audit logs

### Security Enhancements
- **Hardware Security Modules (HSM)**: Integration for key management
- **Certificate Rotation**: Automated certificate lifecycle management
- **Advanced Monitoring**: Anomaly detection for security events
- **Backup and Recovery**: Automated backup strategies for critical data

### Performance Optimizations
- **Connection Pooling**: Optimize Redis connection management
- **Batch Operations**: Implement batch token operations
- **CDN Integration**: Cache public keys and metadata
- **Load Testing**: Comprehensive performance benchmarking

### Developer Experience
- **CLI Tools**: Developer CLI for common operations
- **Local Development**: Improved local development setup
- **Migration Tools**: Database migration and upgrade utilities
- **Integration Examples**: More integration examples and tutorials