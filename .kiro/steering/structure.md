# Project Structure

## Workspace Layout

```
├── Cargo.toml                 # Workspace configuration
├── auth-service/              # Authentication service
│   ├── Cargo.toml            # Service dependencies
│   ├── Dockerfile            # Development container
│   ├── Dockerfile.prod       # Production container
│   ├── src/
│   │   ├── main.rs           # Service entry point
│   │   ├── lib.rs            # Core service logic and routes
│   │   ├── config.rs         # Configuration management
│   │   ├── jwt.rs            # JWT token handling
│   │   ├── security.rs       # Security middleware and validation
│   │   ├── store.rs          # Token storage abstraction
│   │   ├── secrets.rs        # Secret management
│   │   ├── tls.rs            # TLS configuration
│   │   └── monitoring.rs     # Health checks and metrics
│   └── tests/                # Integration and unit tests
├── policy-service/           # Authorization service
│   ├── Cargo.toml           # Service dependencies
│   ├── Dockerfile           # Container configuration
│   ├── entities.json        # Cedar entities definition
│   ├── policies.cedar       # Cedar policy rules
│   ├── src/
│   │   ├── main.rs          # Service entry point
│   │   ├── lib.rs           # Core service logic and routes
│   │   └── config.rs        # Configuration management
│   └── tests/               # Integration tests
└── src/                     # Workspace-level shared code (empty)
```

## Code Organization Patterns

### Service Structure
- `main.rs` - Service bootstrap, configuration loading, server startup
- `lib.rs` - Core business logic, route handlers, error types, OpenAPI schemas
- `config.rs` - Environment variable configuration structs
- Separate modules for distinct concerns (security, storage, etc.)

### Error Handling
- Custom error enums implementing `IntoResponse` for HTTP responses
- Use `thiserror` for error derivation
- Convert external errors (Redis, etc.) to internal error types

### API Design
- Use `utoipa` macros for OpenAPI documentation on route handlers
- Consistent request/response structs with `ToSchema` derive
- Form-encoded requests for OAuth2 endpoints
- JSON for other APIs

### Testing
- Integration tests in `tests/` directory
- Test naming convention: `*_it.rs` for integration, `*_test.rs` for unit tests
- Use `reqwest` for HTTP client testing

## Configuration Files

- `.rustfmt.toml` - Code formatting rules (Unix newlines, field init shorthand)
- `deny.toml` - Dependency policy and license checking
- `rust-toolchain.toml` - Rust version and components (stable + rustfmt + clippy)
- `.editorconfig` - Editor settings (4-space indentation, UTF-8, LF endings)
- `.github/workflows/ci.yml` - CI pipeline (format, lint, test, audit, deny)

## Naming Conventions

- Services: `kebab-case` (auth-service, policy-service)
- Rust modules: `snake_case`
- Environment variables: `UPPER_SNAKE_CASE`
- Route paths: `/kebab-case` or `/snake_case`
- Test files: `*_it.rs` (integration), `*_test.rs` (unit), `*_unit.rs` (unit)