# Project Improvement Plan — Rust Security Workspace

Date: 2025-08-30
Owner: Platform Team (assign per component)
Scope: Workspace (auth-service, policy-service, common), with notes for excluded crates and tooling

## Executive Summary
The workspace is well-documented and security-focused, but several improvements will increase reliability, developer productivity, and verifiability:
- Tighten CI and linting to prevent code smells from landing (tests and benches included).
- Reduce drift between “production-only” workspace and the broader repo by validating excluded crates on a schedule.
- Improve test hygiene and benchmarking methodology to produce meaningful, reproducible results.
- Make supply-chain/security checks first-class in CI (cargo-deny, audit, SBOM generation/signing).
- Formalize fuzz testing integration and corpora management.

This plan lists concrete, prioritized tasks with acceptance criteria.

## Key Findings (evidence-based)
1) Workspace and Tooling
- Cargo workspace is narrowed to {auth-service, policy-service, common}; many crates (e.g., input-validation, compliance-tools, red-team-exercises) are excluded for production stability. Risk: excluded crates can bit-rot and hide regressions.
- rust-toolchain.toml targets stable toolchain with clippy/rustfmt components present (good), but ensure CI uses the same version.
- Workspace lints use warn levels (clippy.*, rust.*) instead of deny. Good for local iteration, but CI should enforce -D warnings.

2) Tests
- policy-service/tests/error_mapping_test.rs contains a large block of “unused imports” aliased to _ to suppress warnings. This is an anti-pattern, can hide real problems, and slows compile.
- compliance-tools/src/bin/security_metrics_collector/tests.rs appears to have variable name inconsistencies (let _result = ...; then assert! on result), which would fail compilation if built. This crate is currently excluded from workspace.

3) Benchmarks
- auth-service/benches/performance_suite.rs creates a new Tokio Runtime per benchmark iteration and spawns tasks inside the hot loop, with each handle instantiating a new service. This distorts measurements (setup dominates), reduces reproducibility, and doesn’t model steady-state load.

4) Security & Supply Chain
- deny.toml is referenced in scripts and config/, but ensure a canonical policy file exists and is enforced in CI. Risk acceptances should be explicit and time-bounded.
- SBOM generation is present in scripts/Makefile and compliance-tools, but ensure CI job produces and (optionally) signs SBOM artifacts per release.

5) Fuzz Testing
- input-validation provides a robust fuzz runner, but the crate is excluded from the workspace. There’s no visible CI integration invoking fuzzing or managing seeds/corpora. Opportunity to automate limited-time fuzz smoke runs and scheduled deeper runs.

6) Documentation
- Docs are comprehensive and marketing-forward (e.g., sub-50ms latency claims). Ensure performance claims are tied to reproducible benchmarks and environment specs. Link SLO/SLA to measured results.

## Prioritized Backlog

P0 — Quality Gates and Hygiene
- CI: Enforce formatting and deny warnings
  - Task: Add/ensure CI workflow that runs: cargo fmt --all --check; cargo clippy --workspace --all-features -- -D warnings; cargo test --workspace
  - Acceptance: CI fails on any warning or formatting diff.
- Tests: Remove “unused imports” suppression patterns
  - Task: Refactor policy-service/tests/error_mapping_test.rs to remove aliasing imports to _; only import required items.
  - Acceptance: Test compiles with clippy -D warnings and passes.
- Bench: Stabilize runtime setup
  - Task: Update auth-service criterion benches to initialize Tokio Runtime and test state in setup (group-level), reuse service instances where realistic, avoid spawning within the inner measurement loop; document methodology.
  - Acceptance: Benchmarks run deterministically on CI runner with <5% variance on repeated runs in controlled env.

P1 — Security and Supply Chain
- cargo-deny and audit in CI
  - Task: Ensure deny.toml at repo root; add CI steps: cargo deny check and cargo audit --json
  - Acceptance: CI job runs on PR and nightly; fails on unapproved advisories or license violations; risk acceptances documented with expiry.
- SBOM artifacts
  - Task: Add CI job to generate CycloneDX (cargo sbom/cyclonedx) and upload artifacts; optional signing via Cosign/Keyless.
  - Acceptance: Release pipeline publishes SBOM; integrity verification step passes.

P1 — Testing Depth and Fuzzing
- Re-enable validation of excluded crates on a schedule
  - Task: Add scheduled CI job (e.g., nightly/weekly) to temporarily include excluded crates (or cargo test -p <crate>) to prevent bit-rot.
  - Acceptance: Scheduled job runs, reports failures; owners triage.
- Fuzz smoke tests in CI
  - Task: Add a short-run fuzz workflow (e.g., 60–120s per target) using the existing fuzz_runner with limited iterations.
  - Acceptance: CI executes on main/nightly; artifacts contain crashes/hangs if any; non-flaky.

P2 — Observability & Docs
- Secure logging guardrails
  - Task: Add clippy lint or custom checks and code review checklist for secret-redaction; verify auth-service uses structured fields and avoids PII in logs.
  - Acceptance: Code scanning or clippy config flags violations; doc checklist updated.
- Performance claims and SLOs
  - Task: Create PERFORMANCE.md with environment specs, benchmark methodology, and current P50/P95 results per endpoint.
  - Acceptance: Document published and referenced from README; claims match measured results.

## Concrete Actions (short list to start)
1) Add/verify .github/workflows/ci.yml to run fmt, clippy -D, test, deny, audit.
2) Remove test anti-patterns in policy-service tests; fix obvious variable name issues in compliance-tools tests (when re-enabling).
3) Rework auth-service benches to avoid per-iter runtime creation; add Criterion configuration for warmup/measurement and sampling.
4) Commit deny.toml at repo root; centralize policy management.
5) Introduce scheduled “full workspace” validation job to build/test excluded crates.
6) Add fuzz smoke testing job with controlled time budget.

## Notes on Minimality and Risk
- Start by strengthening CI gates without altering runtime behavior.
- Defer code refactors (tests/benches) to small, focused PRs to avoid broad changes.
- Keep excluded crates excluded for normal PR CI; validate them on schedule to manage build time.

## Ownership (suggested)
- CI & Tooling: DevEx/Infra
- Security/Supply Chain: Security Engineering
- Tests & Benches: Component owners (Auth, Policy)
- Fuzzing: Input-Validation team

## Appendix — References in Repo
- policy-service/tests/error_mapping_test.rs (unused imports suppression)
- auth-service/benches/performance_suite.rs (runtime per iteration)
- compliance-tools/src/bin/security_metrics_collector/tests.rs (variable name mismatch)
- rust-toolchain.toml (stable toolchain)
- Cargo.toml [workspace.lints] (warn levels)
- Scripts/docs referencing deny.toml and SBOM generation
