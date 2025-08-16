# Rust Security Workspace

Rust-only, App Runner–ready authentication/authorization workspace.

## Project Overview

This is a Rust-based monorepo for a security-focused application. It consists of two main services: an `auth-service` and a `policy-service`. The services are built using the Axum web framework and the Tokio runtime. The project uses a workspace-based setup with Cargo.

- **`auth-service`**: OAuth2-compatible authentication service handling token issuance, introspection, and revocation. Uses Redis for token persistence with in-memory fallback.
- **`policy-service`**: Authorization service using Cedar policy engine for fine-grained access control decisions.

Both services are built with Axum framework, use tower-http middleware for request tracing/IDs, and generate OpenAPI documentation via utoipa.

## Service Architecture

### Auth Service (port 8080)
- `/health` - Health check endpoint
- `/oauth/token` - Issue new access tokens
- `/oauth/introspect` - Validate and check token status
- `/oauth/revoke` - Revoke existing tokens
- `/openapi.json` - OpenAPI specification

Token responses include:
- `access_token` (opaque)
- `token_type` (Bearer)
- `expires_in` (seconds; configurable)
- `refresh_token`
- `scope`
- `exp` (unix seconds)
- `iat` (unix seconds)

Token Store abstraction in `auth_service::store` supports:
- Redis with connection pooling (production)
- In-memory HashMap (development/fallback)

### Policy Service (port 8081)
- `/health` - Health check endpoint
- `/v1/authorize` - Cedar-based authorization decisions
- `/openapi.json` - OpenAPI specification

Uses Cedar policy language for declarative authorization rules.

## Building and Running

The project is built and managed using Cargo.

- **Build the entire project**:
  ```bash
  cargo build
  ```

- **Run the `auth-service`**:
  ```bash
  cargo run -p auth-service
  ```
  The service will be available at `http://localhost:8080`.

- **Run the `policy-service`**:
  ```bash
  cargo run -p policy-service
  ```
  The service will be available at `http://localhost:8081`.

- **Run tests**:
  ```bash
  cargo test --all --all-features --verbose
  ```

## Development Conventions

- **Linting**: The project uses `rustfmt` for code formatting and `clippy` for static analysis.
  - **Format**: `cargo fmt --all`
  - **Lint**: `cargo clippy --all-targets --all-features -- -D warnings`

- **Security**: The project uses `cargo-audit` to check for security vulnerabilities in dependencies and `cargo-deny` to enforce policies on dependencies.
  - **Audit**: `cargo audit --deny warnings`
  - **Deny**: `cargo deny check --all-features`

- **API Documentation**: The services use `utoipa` to generate OpenAPI (Swagger) documentation. The OpenAPI specification can be accessed at the `/openapi.json` endpoint of each service.

## Environment Configuration

Services read configuration from environment variables:
- `REDIS_URL` - Redis connection string (auth-service)
- `BIND_ADDR` - Service bind address (default: 0.0.0.0:8080/8081)
- `RUST_LOG` - Tracing level (e.g., info, debug, trace)
- `TOKEN_EXPIRY_SECONDS` - Access token TTL in seconds (default: 3600)
- `RATE_LIMIT_REQUESTS_PER_MINUTE` - Global per-client request rate (default: 60)
- `CLIENT_CREDENTIALS` - Semicolon-separated list of `client_id:client_secret` pairs (default: `test_client:test_secret`)
- `ALLOWED_SCOPES` - Comma-separated list of allowed scopes (default: `read,write`)
- `ALLOWED_ORIGINS` - Comma-separated list of allowed CORS origins (default: `*`)

## CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/ci.yml`) runs on push/PR:
1. Format check (`cargo fmt --check`)
2. Clippy linting with warnings as errors
3. Full test suite
4. Security audit via cargo-audit
5. License/dependency policy via cargo-deny

## Key Dependencies

- **axum**: Async web framework
- **tokio**: Async runtime
- **cedar-policy**: AWS Cedar authorization engine
- **redis**: Token persistence (auth-service)
- **tower-http**: HTTP middleware (tracing, request IDs)
- **utoipa**: OpenAPI documentation generation

## Docker

```bash
docker build -t auth-service:local auth-service
docker build -t policy-service:local policy-service
```
