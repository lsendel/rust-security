# Rust Security Workspace Development Makefile
# Provides convenient commands for common development tasks

.PHONY: help build test check lint security audit clean install format docs

# Default target
help:
	@echo "Rust Security Workspace - Development Commands"
	@echo ""
	@echo "Common Commands:"
	@echo "  make build      - Build all workspace crates"
	@echo "  make test       - Run all tests"
	@echo "  make check      - Fast compile check"
	@echo "  make lint       - Run clippy linting"
	@echo "  make format     - Format all code"
	@echo ""
	@echo "Security Commands:"
	@echo "  make security   - Run all security checks"
	@echo "  make audit      - Audit dependencies for vulnerabilities"
	@echo "  make deny       - Check dependency licenses and sources"
	@echo ""
	@echo "Development Commands:"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make install    - Install development tools"
	@echo "  make docs       - Generate documentation"
	@echo "  make examples   - Run all examples"

# Development setup
install:
	@echo "Installing development tools..."
	cargo install cargo-audit
	cargo install cargo-deny
	cargo install cargo-outdated
	cargo install cargo-edit
	cargo install cargo-sweep
	cargo install cargo-watch
	cargo install --locked cargo-mutants
	rustup component add clippy rustfmt

# Build commands
build:
	@echo "Building workspace..."
	cargo build --workspace

build-release:
	@echo "Building workspace in release mode..."
	cargo build --workspace --release

check:
	@echo "Checking workspace..."
	cargo check --workspace

# Testing commands
test:
	@echo "Running tests..."
	cargo test --workspace

test-ignored:
	@echo "Running ignored tests..."
	cargo test --workspace -- --ignored

test-security:
	@echo "Running security-focused tests..."
	cargo test --workspace --features threat-hunting,post-quantum

# Code quality commands
lint:
	@echo "Running clippy..."
	cargo clippy --workspace --all-targets --all-features -- -D warnings

lint-security:
	@echo "Running security-focused lints..."
	cargo clippy --workspace --all-targets --all-features -- \
		-D clippy::unwrap_used \
		-D clippy::expect_used \
		-D clippy::panic \
		-D clippy::integer_overflow \
		-D clippy::indexing_slicing

format:
	@echo "Formatting code..."
	cargo fmt --all

format-check:
	@echo "Checking code formatting..."
	cargo fmt --all -- --check

# Security commands
security: audit deny lint-security
	@echo "All security checks completed"

audit:
	@echo "Auditing dependencies for vulnerabilities..."
	cargo audit

deny:
	@echo "Checking dependencies with cargo-deny..."
	cargo deny check

outdated:
	@echo "Checking for outdated dependencies..."
	cargo outdated --workspace

# Documentation
docs:
	@echo "Generating documentation..."
	cargo doc --workspace --no-deps --open

docs-private:
	@echo "Generating documentation with private items..."
	cargo doc --workspace --no-deps --document-private-items

# Examples
examples:
	@echo "Running simple auth client example..."
	cd examples/simple-auth-client && cargo run
	@echo "Building axum integration example..."
	cd examples/axum-integration-example && cargo build

# Development workflow
dev-setup: install
	@echo "Setting up development environment..."
	git config core.hooksPath .githooks
	chmod +x .githooks/*

watch:
	@echo "Starting development watch mode..."
	cargo watch -x check -x test

watch-tests:
	@echo "Watching tests..."
	cargo watch -x "test --workspace"

# Performance and profiling
bench:
	@echo "Running benchmarks..."
	cargo bench --workspace --features benchmarks

profile:
	@echo "Building with profiling..."
	cargo build --workspace --profile release-with-debug

# Maintenance commands
clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	@echo "Sweeping unused build files..."
	cargo sweep --time 7

clean-all: clean
	@echo "Cleaning all artifacts including dependencies..."
	rm -rf target/
	rm -rf Cargo.lock

update:
	@echo "Updating dependencies..."
	cargo update

upgrade:
	@echo "Upgrading dependencies to latest versions..."
	cargo upgrade --workspace

# CI/CD simulation
ci-check: format-check lint test audit deny
	@echo "CI checks completed successfully"

ci-build: build-release test
	@echo "CI build completed successfully"

# Red team exercises (when compilation issues are resolved)
red-team:
	@echo "Running red team exercises..."
	cd red-team-exercises && cargo run

compliance:
	@echo "Running compliance tools..."
	cd compliance-tools && cargo run --bin compliance-report-generator

# Individual service commands
auth-service:
	@echo "Building auth-service..."
	cargo build -p auth-service

policy-service:
	@echo "Building policy-service..."
	cargo build -p policy-service

# Feature-specific builds
build-optimizations:
	@echo "Building with optimizations..."
	cargo build -p auth-service --features optimizations

build-threat-hunting:
	@echo "Building with threat hunting features..."
	cargo build -p auth-service --features threat-hunting

build-post-quantum:
	@echo "Building with post-quantum crypto..."
	cargo build -p auth-service --features post-quantum

# Development utilities
loc:
	@echo "Counting lines of code..."
	find . -name "*.rs" -not -path "./target/*" | xargs wc -l | tail -1

deps-tree:
	@echo "Showing dependency tree..."
	cargo tree

deps-graph:
	@echo "Generating dependency graph..."
	cargo depgraph --workspace-only | dot -Tpng > deps.png
	@echo "Dependency graph saved to deps.png"

# Quick development shortcuts
q-check: check
q-test: test
q-lint: lint
q-fmt: format