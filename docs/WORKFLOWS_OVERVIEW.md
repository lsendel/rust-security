# GitHub Workflows Overview

This repository’s GitHub Actions have been standardized for performance, security, and least-privilege defaults. Key changes:

- Unified Rust toolchain via `dtolnay/rust-toolchain@stable` and cargo caching with `Swatinem/rust-cache@v2`.
- Added `permissions: contents: read` and `concurrency` to cancel stale runs across workflows.
- Upgraded artifact actions to `actions/upload-artifact@v4` and `actions/download-artifact@v4`.
- Added a dedicated frontend workflow for `user-portal/` (Node 20, npm cache).

## Primary Workflows

- CI (`.github/workflows/ci.yml`): Rust build, fmt, clippy, tests; isolated policy-service job.
  - Uses `just` commands if available (`just build|test|fmt-check|lint`).
  - CI installs `just` if not present on runner.
- Enhanced CI (`enhanced-ci.yml`): Compilation check, code-quality, test matrix, security scan, docs build.
- Frontend (`frontend.yml`): Lint, test, and build `user-portal`.
- Security (`security.yml`): Supply chain, CodeQL (JavaScript/TypeScript), IaC scans, compliance artifacts.
- Release (`release.yml`): Tag-driven build and artifact publishing with concurrency protection.

## Supporting Workflows

- API Validation (`api-validation.yml`): API consistency checks and docs build; artifacts uploaded.
- SonarQube (`sonarqube-analysis.yml`): Coverage + clippy to Sonar.
- Dependency, Security Scans (`dependency-check.yml`, `security-scan.yml`, `security-testing.yml`): Various audits.
- Quality/Performance/Compliance (`quality-monitoring.yml`, `performance-monitoring.yml`, `compliance-automation.yml`).
- Specialized Testing (`ci-clippy.yml`, `doctest-validation.yml`, `pr-fast.yml`, `threat-intel-ci.yml`).
- On-demand Security (`pr-on-demand-security.yml`): Comment `/security-scan` on a PR to run cargo-audit/deny against the PR head and attach results.
- On-demand Performance (`pr-on-demand-performance.yml`): Comment `/performance-scan` on a PR to run performance tests/benches and upload Criterion results.
- On-demand Compliance (`pr-on-demand-compliance.yml`): Comment `/compliance-scan` on a PR to generate an SBOM and optional compliance report.
- On-demand API (`pr-on-demand-api-validation.yml`): Comment `/api-validate` on a PR to lint OpenAPI specs and build Rust docs.
- On-demand Frontend (`pr-on-demand-frontend.yml`): Comment `/frontend-validate` on a PR to run UI lint/test/build and upload dist.

## Retired/Consolidated Workflows

- Removed to reduce duplication: `advanced-testing-ci.yml`, `comprehensive-testing.yml`, `ci-pipeline.yml`.
  - All functionality is covered by `CI`, `Enhanced CI`, and targeted workflows.

## Recommendations

- Converted `advanced-testing-ci.yml`, `comprehensive-testing.yml`, and `ci-pipeline.yml` to manual (`workflow_dispatch`) to reduce duplication with core CI.
- Set required checks in branch protection: `CI`, `Frontend CI`, `Advanced Supply Chain Security` (or specific jobs within it).
- Kept heavy scans (container/IaC, performance, compliance) on `push` to default branches and scheduled runs; removed PR triggers.

## Local Validation

- Run `just ci-complete` locally where possible.
- Validate workflow logic with `act` (if installed): `act pull_request -j ci`.
