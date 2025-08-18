# Rust Security Project Justfile
# Common development tasks

# Default recipe that lists available commands
default:
    @just --list

# Build the entire workspace
build:
    cargo build --workspace --all-features

# Build for release
build-release:
    cargo build --workspace --all-features --release

# Run all tests
test:
    #!/usr/bin/env bash
    export TEST_MODE=1
    cargo test --workspace --all-features --verbose

# Run tests with coverage
test-coverage:
    #!/usr/bin/env bash
    export TEST_MODE=1
    cargo llvm-cov --workspace --all-features --html

# Run only unit tests
test-unit:
    #!/usr/bin/env bash
    export TEST_MODE=1
    cargo test --workspace --lib

# Run only integration tests
test-integration:
    #!/usr/bin/env bash
    export TEST_MODE=1
    cargo test --workspace --test '*'

# Run linting checks
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::perf -W clippy::suspicious

# Fix formatting and linting issues
fix:
    cargo fmt --all
    cargo clippy --workspace --all-targets --all-features --fix --allow-dirty

# Run security audit
audit:
    cargo audit --deny warnings
    cargo deny check --all-features

# Run all quality checks (CI pipeline locally)
ci: lint test audit

# Install pre-commit hooks
install-hooks:
    pre-commit install
    pre-commit install --hook-type commit-msg

# Run pre-commit on all files
pre-commit-all:
    pre-commit run --all-files

# Clean build artifacts
clean:
    cargo clean
    rm -rf target/

# Run the auth service locally
run-auth:
    #!/usr/bin/env bash
    export TEST_MODE=1
    export RUST_LOG=debug
    cd auth-service && cargo run

# Run the policy service locally
run-policy:
    #!/usr/bin/env bash
    export RUST_LOG=debug
    cd policy-service && cargo run

# Start development environment with Docker
dev-env:
    docker-compose up -d redis
    @echo "Redis started. Use 'just run-auth' and 'just run-policy' to start services."

# Stop development environment
dev-env-down:
    docker-compose down

# Run performance benchmarks
bench:
    cargo bench --workspace

# Generate documentation
docs:
    cargo doc --workspace --all-features --no-deps --open

# Run load tests
load-test:
    ./scripts/testing/comprehensive_load_test.sh

# Run security tests
security-test:
    ./scripts/testing/test_security_scenarios.sh

# Run end-to-end tests
e2e-test:
    ./scripts/testing/end_to_end_integration_test.sh

# Update dependencies
update:
    cargo update
    cargo audit --deny warnings
    cargo deny check

# Generate SBOM
sbom:
    cd compliance-tools && cargo run --bin sbom-generator -- --project-root .. --output ../sbom.spdx.json

# Validate security configuration
validate-security:
    ./scripts/validation/validate_security_implementation.sh

# Quick validation (fast feedback)
validate-quick:
    ./scripts/validation/quick_validation.sh

# Check for outdated dependencies
outdated:
    cargo outdated --workspace

# Format all files
fmt:
    cargo fmt --all

# Check format without making changes
fmt-check:
    cargo fmt --all -- --check

# Run clippy with extra lints
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::perf -W clippy::suspicious -W clippy::nursery

# Build Docker images
docker-build:
    docker build -f auth-service/Dockerfile.secure -t auth-service:latest .
    docker build -f policy-service/Dockerfile -t policy-service:latest .

# Deploy to local Kubernetes
k8s-deploy:
    kubectl apply -f k8s/

# Remove from local Kubernetes
k8s-remove:
    kubectl delete -f k8s/

# View logs from auth service
logs-auth:
    kubectl logs -f deployment/auth-service

# View logs from policy service
logs-policy:
    kubectl logs -f deployment/policy-service
