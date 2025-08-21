# Rust Security Platform - Makefile
# Simplifies common development and testing tasks

.PHONY: help build test clean doc fmt lint security bench all

# Default target - show help
help:
	@echo "Rust Security Platform - Development Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Quick Start:"
	@echo "  make build          - Build all components"
	@echo "  make test           - Run all tests"
	@echo "  make run            - Run minimal auth-core server"
	@echo ""
	@echo "Development:"
	@echo "  make fmt            - Format code"
	@echo "  make lint           - Run clippy linter"
	@echo "  make check          - Format check + lint"
	@echo "  make doc            - Generate documentation"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "Testing:"
	@echo "  make test-quick     - Run quick unit tests only"
	@echo "  make test-security  - Run security test suite"
	@echo "  make test-coverage  - Generate test coverage report"
	@echo "  make test-property  - Run property-based tests"
	@echo "  make bench          - Run performance benchmarks"
	@echo "  make test-all       - Run complete test suite"
	@echo ""
	@echo "Build Profiles:"
	@echo "  make build-minimal  - Build minimal auth-core"
	@echo "  make build-standard - Build with standard features"
	@echo "  make build-enterprise - Build with all features"
	@echo ""
	@echo "Security:"
	@echo "  make audit          - Run security audit"
	@echo "  make sec-check      - Complete security validation"
	@echo ""
	@echo "CI/CD:"
	@echo "  make ci             - Run CI validation locally"
	@echo "  make release        - Build release artifacts"

# Build targets
build:
	@echo "🔨 Building all components..."
	@cargo build --workspace --all-features

build-minimal:
	@echo "🚀 Building minimal auth-core..."
	@cd auth-core && cargo build --release --no-default-features --features client-credentials

build-standard:
	@echo "🏭 Building standard profile..."
	@./scripts/build-profiles.sh standard

build-enterprise:
	@echo "🏢 Building enterprise profile..."
	@./scripts/build-profiles.sh enterprise

# Run targets
run:
	@echo "🚀 Starting minimal auth-core server..."
	@cd auth-core && cargo run --example minimal_server

run-docker:
	@echo "🐳 Running in Docker..."
	@docker-compose up -d

# Testing targets
test:
	@echo "🧪 Running all tests..."
	@cargo test --workspace --all-features

test-quick:
	@echo "⚡ Running quick tests..."
	@cargo test --lib --bins

test-security:
	@echo "🔒 Running security tests..."
	@cargo test --workspace security
	@cargo test --workspace integration_security
	@cargo test --workspace owasp

test-coverage:
	@echo "📊 Generating test coverage..."
	@cargo llvm-cov --workspace --all-features --html --output-dir coverage
	@echo "Coverage report generated at: coverage/index.html"

test-property:
	@echo "🎲 Running property-based tests..."
	@PROPTEST_CASES=1000 cargo test --workspace property

bench:
	@echo "📈 Running benchmarks..."
	@./scripts/run-benchmarks.sh all

test-all: test test-security test-property bench
	@echo "✅ Complete test suite finished"

# Code quality targets
fmt:
	@echo "✨ Formatting code..."
	@cargo fmt --all

fmt-check:
	@echo "🔍 Checking code formatting..."
	@cargo fmt --all --check

lint:
	@echo "🔍 Running clippy..."
	@cargo clippy --workspace --all-features --all-targets -- -D warnings

check: fmt-check lint
	@echo "✅ Code quality checks passed"

# Documentation
doc:
	@echo "📚 Generating documentation..."
	@cargo doc --workspace --all-features --no-deps --open

doc-private:
	@echo "📚 Generating documentation (including private items)..."
	@cargo doc --workspace --all-features --no-deps --document-private-items --open

# Security targets
audit:
	@echo "🔒 Running security audit..."
	@cargo audit

deny:
	@echo "🚫 Checking dependencies..."
	@cargo deny check

sec-check: audit deny test-security
	@echo "✅ Security validation complete"

# Clean targets
clean:
	@echo "🧹 Cleaning build artifacts..."
	@cargo clean
	@rm -rf coverage/
	@rm -rf benchmark-results/

clean-all: clean
	@echo "🧹 Deep cleaning..."
	@rm -rf target/
	@rm -rf auth-core/target/
	@rm -rf auth-service/target/
	@find . -name "*.profraw" -delete

# CI/CD targets
ci: fmt-check lint test test-security
	@echo "✅ CI validation passed"

ci-extensive: ci test-property bench test-coverage
	@echo "✅ Extensive CI validation passed"

release:
	@echo "📦 Building release artifacts..."
	@cargo build --release --workspace --all-features
	@mkdir -p release-artifacts
	@cp target/release/auth-core release-artifacts/ 2>/dev/null || true
	@cp target/release/auth-service release-artifacts/ 2>/dev/null || true
	@echo "Release artifacts in: release-artifacts/"

# Development helpers
watch:
	@echo "👁️ Watching for changes..."
	@cargo watch -x check -x test -x run

todo:
	@echo "📝 Finding TODOs..."
	@grep -r "TODO\|FIXME\|XXX" --include="*.rs" --include="*.toml" --include="*.md" .

loc:
	@echo "📏 Lines of code:"
	@tokei

deps:
	@echo "🌳 Dependency tree:"
	@cargo tree

update:
	@echo "⬆️ Updating dependencies..."
	@cargo update

# Installation targets
install-tools:
	@echo "🔧 Installing development tools..."
	@cargo install cargo-watch
	@cargo install cargo-audit
	@cargo install cargo-deny
	@cargo install cargo-llvm-cov
	@cargo install cargo-criterion
	@cargo install tokei
	@echo "✅ Development tools installed"

# Docker targets
docker-build:
	@echo "🐳 Building Docker image..."
	@docker build -t rust-security-auth .

docker-run: docker-build
	@echo "🐳 Running Docker container..."
	@docker run -p 8080:8080 rust-security-auth

docker-compose:
	@echo "🐳 Starting with docker-compose..."
	@docker-compose up

# Utility targets
.PHONY: version
version:
	@echo "Rust Security Platform"
	@echo "Rust version: $$(rustc --version)"
	@echo "Cargo version: $$(cargo --version)"
	@echo "Git commit: $$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
	@echo "Git branch: $$(git branch --show-current 2>/dev/null || echo 'unknown')"

# Performance profiling
profile:
	@echo "🔬 Running performance profiling..."
	@cargo build --release
	@valgrind --tool=callgrind target/release/auth-core || echo "Valgrind not available"

# Quick development cycle
dev: fmt test-quick
	@echo "✅ Quick development checks passed"

# Full validation before commit
pre-commit: fmt-check lint test test-security
	@echo "✅ Ready to commit"

# Default target
all: clean build test doc
	@echo "✅ Full build and test complete"