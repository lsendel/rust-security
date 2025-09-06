# Developer Setup Guide

Complete setup guide for developers who want to contribute to or extend the Rust Security Platform.

## Prerequisites

Before starting, ensure you have:

### Required Tools
- **Rust** (1.80 or later) - Install via [rustup](https://rustup.rs/)
- **Git** - For version control
- **Docker** - For running dependencies (Redis, PostgreSQL)
- **Node.js** (18+) - For frontend development and tools

### Optional Tools
- **Just** - Command runner (alternative to Make)
- **Cargo tools** - For development utilities
- **PostgreSQL client** - For database management

## Environment Setup

### 1. Install Rust Toolchain

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default 1.80

# Verify installation
rustc --version
cargo --version
```

### 2. Install Development Dependencies

```bash
# Install essential Cargo tools
cargo install cargo-watch cargo-llvm-cov cargo-audit cargo-deny

# Install system dependencies (macOS)
brew install redis postgresql

# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install redis-server postgresql postgresql-client

# Start required services
redis-server &
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS
```

### 3. Clone the Repository

```bash
# Clone the repository
git clone https://github.com/company/rust-security.git
cd rust-security

# Set up Git hooks (optional)
git config core.hooksPath .githooks
```

## Project Structure

The platform is organized as a Cargo workspace with multiple crates:

```
rust-security/
├── auth-service/          # Main authentication service
├── policy-service/        # Authorization policy engine
├── common/                # Shared utilities and types
├── mvp-oauth-service/     # Minimal OAuth implementation
├── mvp-tools/             # Development tools and examples
├── user-portal/           # Frontend administration portal
├── monitoring/            # Observability stack
└── docs/                  # Documentation
```

## Running Services Locally

### 1. Start Dependencies

```bash
# Start Redis and PostgreSQL using Docker
docker-compose up -d redis postgres

# Or start locally if installed
redis-server &
pg_ctl -D /usr/local/var/postgres start  # macOS
sudo systemctl start postgresql           # Linux
```

### 2. Configure Environment

```bash
# Copy example environment files
cp auth-service/.env.example auth-service/.env
cp policy-service/.env.example policy-service/.env

# Edit configuration as needed
# See Configuration Guide for details
```

### 3. Database Setup

```bash
# Create databases
createdb auth_service_dev
createdb policy_service_dev

# Run migrations
cd auth-service
sqlx migrate run
cd ../policy-service
sqlx migrate run
```

### 4. Run Services

```bash
# Run auth service
cargo run -p auth-service

# Run policy service
cargo run -p policy-service

# Run both services (in separate terminals)
# Terminal 1:
cargo run -p auth-service
# Terminal 2:
cargo run -p policy-service
```

## Development Workflow

### Code Quality Checks

```bash
# Run formatting
cargo fmt

# Run linter
cargo clippy --workspace --all-targets --all-features

# Run tests
cargo test --workspace

# Run security audit
cargo audit

# Check for outdated dependencies
cargo outdated
```

### Continuous Development

```bash
# Watch for changes and rebuild automatically
cargo watch -x run -p auth-service

# Run tests on change
cargo watch -x test

# Check code quality on change
cargo watch -x clippy
```

### Testing

```bash
# Run unit tests
cargo test --lib

# Run integration tests
cargo test --test '*'

# Run specific test
cargo test test_name

# Run tests with coverage
cargo llvm-cov --workspace

# Run security tests
cargo test --features security-tests
```

## Development Tools

### Just Commands

If you have `just` installed, you can use predefined commands:

```bash
# List available commands
just --list

# Run common development tasks
just dev
just test
just lint
just build
```

### Database Management

```bash
# Connect to PostgreSQL
psql -d auth_service_dev

# Run SQL commands
psql -d auth_service_dev -c "SELECT * FROM users LIMIT 10;"

# Export database schema
pg_dump -s auth_service_dev > auth-schema.sql
```

### Debugging

```bash
# Run with debug logging
RUST_LOG=debug cargo run -p auth-service

# Run with trace logging for specific modules
RUST_LOG=auth_service=trace,policy_service=debug cargo run

# Enable backtraces
RUST_BACKTRACE=1 cargo run -p auth-service
```

## Contributing

### Branching Strategy

- **main** - Production-ready code
- **develop** - Development branch
- **feature/** - Feature branches
- **hotfix/** - Urgent fixes
- **release/** - Release preparation

### Commit Guidelines

Follow conventional commits:
```
feat: Add new authentication method
fix: Resolve token validation issue
docs: Update API documentation
test: Add integration tests for OAuth flow
refactor: Improve error handling in policy engine
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make changes and commit
4. Run code quality checks
5. Submit pull request
6. Address review feedback

### Code Standards

- Follow Rust naming conventions
- Write comprehensive documentation
- Include tests for new functionality
- Maintain 80%+ test coverage
- Use error handling appropriately
- Follow security best practices

## IDE Setup

### VS Code

Recommended extensions:
- **rust-analyzer** - Rust language support
- **Even Better TOML** - TOML file support
- **CodeLLDB** - Debugger
- **EditorConfig** - Consistent formatting

### IntelliJ IDEA / RustRover

- Install Rust plugin
- Configure Rust toolchain
- Enable formatting on save

## Troubleshooting

### Common Issues

#### Compilation Errors
```bash
# Clean build artifacts
cargo clean

# Update dependencies
cargo update

# Check toolchain
rustc --version
rustup show
```

#### Database Connection Issues
```bash
# Check if services are running
docker-compose ps

# Test connection
pg_isready -d auth_service_dev
redis-cli ping
```

#### Test Failures
```bash
# Run tests with output
cargo test -- --nocapture

# Run specific test with verbose output
cargo test test_name -- --nocapture --verbose
```

## Next Steps

After setting up your development environment:

1. **Run the Test Suite**: Ensure all tests pass
2. **Explore the Codebase**: Familiarize yourself with the architecture
3. **Make a Small Change**: Try implementing a simple feature
4. **Submit a Pull Request**: Contribute back to the project

For more detailed information:
- [API Reference](../03-api-reference/README.md) - Detailed API documentation
- [Architecture Overview](../02-core-concepts/architecture-overview.md) - System design
- [Testing Guide](../06-development/testing.md) - Comprehensive testing strategies
- [Coding Standards](../06-development/coding-standards.md) - Code quality guidelines