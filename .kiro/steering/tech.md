# Technology Stack

## Core Technologies

- **Language**: Rust (2021 edition, stable toolchain)
- **Web Framework**: Axum 0.7 with async/await
- **Runtime**: Tokio (multi-threaded)
- **Database**: Redis (with in-memory HashMap fallback)
- **Authorization Engine**: AWS Cedar Policy 3.x
- **Documentation**: utoipa for OpenAPI generation

## Key Dependencies

- `axum` - Web framework with macros
- `tokio` - Async runtime with rt-multi-thread, macros, signal features
- `serde` - Serialization with derive feature
- `tower-http` - HTTP middleware (tracing, request-id, rate limiting)
- `redis` - Token storage with tokio-comp, aio, connection-manager
- `cedar-policy` - Authorization policy engine
- `utoipa` - OpenAPI documentation generation
- `uuid` - Token generation with v4 and serde features
- `tracing` - Structured logging and observability

## Build System

Cargo workspace with two service members:
- `auth-service`
- `policy-service`

## Common Commands

### Development
```bash
# Build entire workspace
cargo build

# Run specific service
cargo run -p auth-service
cargo run -p policy-service

# Run all tests
cargo test --all --all-features --verbose
```

### Code Quality
```bash
# Format code
cargo fmt --all

# Lint with clippy (warnings as errors)
cargo clippy --all-targets --all-features -- -D warnings

# Security audit
cargo audit --deny warnings

# License and dependency policy check
cargo deny check --all-features
```

### Docker
```bash
# Build service images
docker build -t auth-service:local auth-service
docker build -t policy-service:local policy-service
```

## Configuration

Services use environment variables:
- `REDIS_URL` - Redis connection string (auth-service)
- `BIND_ADDR` - Service bind address (default: 0.0.0.0:8080/8081)
- `RUST_LOG` - Tracing level (info, debug, trace)

## Security Tools

- `cargo-audit` - Vulnerability scanning
- `cargo-deny` - License and dependency policy enforcement
- Security-focused middleware and headers
- Input validation and sanitization