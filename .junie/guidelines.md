# Project Guidelines: Rust Security Workspace

This document provides an overview of the repository, how to work with it, and the expectations for contributions and automated assistants.

Last updated: 2025-08-19

## 1. Overview
A Rust-based security workspace focused on:
- Authentication and session management (auth-service)
- Policy enforcement (policy-service)
- Red-team exercises and examples for security scenarios (red-team-exercises, examples)
- Common libraries and shared utilities (common)
- Monitoring, SOAR workflows, and supporting tooling (monitoring, ml-attack-detection, compliance-tools, docs)

The repository is a Cargo workspace with multiple crates and auxiliary services, infrastructure manifests, and scripts.

## 2. Project Structure (top-level)
- auth-service: Microservice for auth/session/admin middleware, security logging, SOAR integration.
- policy-service: Policy enforcement service.
- common: Shared Rust crates and utilities.
- red-team-exercises: Security scenarios and a small dashboard (TS/React) for exercises.
- examples: Sample integrations (e.g., axum integration examples).
- src: Root crate (if present) and top-level Rust code.
- tests: Workspace-level integration/regression tests.
- scripts, load_test, benchmarks: Utility scripts and performance tooling.
- monitoring, k8s, helm, docker-compose*.yml: Ops and deployment artifacts.
- docs, evidence, reports: Documentation and generated evidence/artifacts.
- Makefile, justfile: Developer convenience commands (where applicable).

Refer to README.md and quickstart.md for detailed getting started steps.

## 3. Build
- Build all workspace crates:
  - cargo build --workspace --all-features
- Release build (when needed):
  - cargo build --workspace --release
- Some services may be runnable via docker-compose:
  - docker-compose up -d  # or docker-compose.yml variants in repo

## 4. Test
- Run all tests across the workspace:
  - cargo test --workspace --all-features
- Run a single test file or crate:
  - cargo test -p <crate_name>
- Integration/regression suites live under tests/ (e.g., integration_tests.rs, regression_test_suite.rs, phase1_security_tests.rs). Prefer running the whole workspace test suite before submitting changes.

## 5. Lint, Format, Security
- Format:
  - cargo fmt --all
- Lint (warnings as errors encouraged):
  - cargo clippy --workspace --all-features -- -D warnings
- Deny list (deny.toml):
  - cargo deny check  # if cargo-deny is installed
- Supply chain / SBOM files maintained at repo root (sbom.*). Keep them updated as part of release processes when relevant.

## 6. Code Style and Conventions
- Rust 2021 edition (per rust-toolchain.toml and Cargo.toml). Use stable toolchain unless stated otherwise.
- Keep functions small and focused; prefer explicit types in public APIs.
- Error handling: use anyhow/thiserror patterns consistently; never silently ignore errors.
- Logging: Prefer structured logs; do not log secrets. Follow existing security_logging patterns in auth-service.
- Security first: validate inputs, avoid panics in library code, and document threat models for new components.

## 7. Running Services Locally
- Auth Service:
  - cargo run -p auth-service --bin auth-service
  - Config via soar_config.toml and config/ directory; see auth-service/ README if present.
- Policy Service:
  - cargo run -p policy-service
- Examples:
  - cargo run -p examples --example <name>  # or navigate into examples/* crates
- For dashboards or TS components under red-team-exercises/security-dashboard, use the standard Node/Yarn/PNPM command per that subproject’s README.

## 8. Performance and Load Testing
- See PERFORMANCE.md, performance_results, and load_test. Use run_complete_performance_analysis.sh where appropriate. Check benchmarks/ for Criterion or similar setups.

## 9. CI Expectations (for Junie and contributors)
- Before submitting:
  - Build, format, and clippy clean across the workspace.
  - Run cargo test --workspace.
  - Update docs if you change external behavior.
- Keep changes minimal and focused. Prefer small PRs.

## 10. Project-Specific Notes
- SOAR and security workflow code is under auth-service/src/soar_*.rs.
- Red-team scenarios live under red-team-exercises/src/scenarios/*.rs. When adding new scenarios, include brief docs and tests where feasible.
- Examples include axum-integration-example; keep examples compiling on stable.

## 11. Troubleshooting
- If workspace build fails, try:
  - cargo clean && cargo build --workspace
  - Ensure rustup toolchain matches rust-toolchain.toml
- For Docker-based runs, verify ports and environment files in docker-compose*.yml.

## 12. How Junie Should Operate
- Always read this guidelines file and the repository README.md/quickstart.md first.
- Prefer cargo test --workspace to validate changes.
- For docs-only changes (like this one), no build/test run is required, but ensure formatting and links are correct.
- Keep edits minimal and provide an <UPDATE> plan and summary with every change.

## 13. Contacts and Further Docs
- See docs/ and README.md for detailed architecture and component-level guides.
- Security-related evidence and reports are under evidence/ and reports/.
