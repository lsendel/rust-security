# Project Improvement Checklist (Actionable)

This checklist provides a concise, prioritized set of improvements for the Rust Security Workspace. It links to existing documents where details already exist, so you can adopt improvements quickly without duplicating content.

Status marks: [ ] todo, [*] in progress, [x] done.

## 0) One-command local validation
- [ ] Run the full local CI quality gate: `just ci` (fmt + clippy + tests + audit + deny)
- [ ] Quick validation for fast feedback: `just validate-quick`
- [ ] Security validation sweep: `just validate-security`
- [ ] Generate SBOM (supply chain transparency): `just sbom`

Tip: Use `just --list` to discover all helpers. See project guidelines in README.md and TESTING_GUIDE.md.

## 1) Security Enhancements (near-term)
- [ ] Enforce rate limiting across all external endpoints (DoS protection)
  - Track in SECURITY_IMPROVEMENTS.md → Future Recommendations
- [ ] Add CSRF protection tokens for state-changing endpoints
- [ ] Expand security logging with structured, privacy-safe events in auth-service (no secrets)
- [ ] Add periodic dependency baseline report to CI artifacts (cargo-audit, cargo-deny summary)
- [ ] Add fuzz targets for parsers/validators (e.g., SCIM filters, token parsing) using cargo-fuzz
- [ ] Secrets scanning in CI (e.g., trufflehog or gitleaks) with allowlist for known test fixtures

References: SECURITY.md, SECURITY_IMPROVEMENTS.md, INPUT_VALIDATION_SECURITY_IMPLEMENTATION.md

## 2) Testing & Quality
- [ ] Increase unit + integration coverage for critical paths (targets ≥ 80% lines)
  - Use: `just test-coverage` and `just coverage-check`
- [ ] Introduce property-based tests (proptest) for input validators and policy evaluation
- [ ] Add regression tests for previously fixed panics and unwraps
- [ ] Add chaos/latency injection in tests for network clients (see chaos-engineering/ guides)

References: TESTING_GUIDE.md, CHAOS_ENGINEERING_SECURITY_TESTING_GUIDE.md

## 3) Performance & Reliability
- [ ] Benchmark auth-service hot paths regularly; track P95 latency budgets
  - Use: `just bench` and load_test/ scripts
- [ ] Add flamegraph profiling recipe (criterion + inferno) and capture profiles for PRs that touch hot paths
- [ ] Add circuit-breaker & retry policy tests under induced failures (timeouts, connection resets)
- [ ] Performance SLO check in CI (alert if >N% regression vs baseline)

References: PERFORMANCE.md (if present), performance_results/, benches/, load_test/

## 4) Developer Experience (DX)
- [ ] Dev containers / Nix or reproducible toolchain bootstrap to reduce setup friction
- [ ] Pre-commit hooks default install (format, clippy, deny, audit) → `just install-hooks`
- [ ] Example snippets for common flows in docs/api and examples/
- [ ] Expand just targets where gaps exist (e.g., `improve` target below)

References: justfile, docs/development/, GETTING_STARTED_SIMPLE.md

## 5) Observability & Ops
- [ ] Standardize tracing spans and fields across services (trace_id, user_id hash, request_id)
- [ ] Add RED metrics (Rate, Errors, Duration) dashboards for auth/policy services
- [ ] SLO and error budget dashboards (Grafana); document runbooks in docs/operations
- [ ] Synthetic checks for critical endpoints; publish status to monitoring/

References: monitoring/, docker-compose.monitoring.yml, docs/operations/

## 6) Documentation Improvements
- [ ] Add “production readiness checklist” summarizing required toggles and configs
- [ ] Ensure all READMEs have current commands that match justfile
- [ ] Cross-link architecture and threat model docs from service READMEs
- [ ] Document multi-tenant isolation guarantees and data lifecycle in docs/architecture

References: docs/architecture/, docs/security/, README.md

---

## How to Use
1) Run local CI: `just ci`.
2) Pick a section above and open a short PR per bullet.
3) Keep PRs small and focused; link to the references listed for details.

## Quick Win PR Ideas (1–2 hours)
- Add basic rate limiting middleware and a feature-flag to enable in dev.
- Add a few proptest generators for validators.
- Add a flamegraph capture script and a doc page with screenshots.
- Add missing tracing spans in auth-core request handlers.
- Create a production readiness checklist doc under docs/operations/.

Last updated: 2025-08-22
