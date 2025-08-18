# Project Improvements Roadmap (2025-08-18)

This roadmap highlights high-impact, concrete improvements for the rust-security workspace. It is prioritized to maximize security, reliability, and developer experience with minimal risk.

## 1) Continuous Integration and Quality Gates (High)
- Add Rust CI workflow to run: format, clippy (deny warnings), tests, cargo-audit, and cargo-deny on pushes/PRs. [Added: .github/workflows/rust-ci.yml]
- Consider adding test matrix (stable + nightly) and Linux + macOS runners for broader coverage.
- Cache target and cargo directories for faster builds (already configured in the workflow).

## 2) Testing Strategy (High)
- Strengthen unit/integration tests for auth flows:
  - OAuth2/OIDC happy and error paths: /oauth/token, /oauth/authorize, /oauth/userinfo, /jwks.json
  - Policy service interaction: timeouts, strict vs permissive modes, cache invalidation
  - Session lifecycle: creation, inactivity timeout, concurrent session limit, cleanup scheduler shutdown
- Add property-based tests (proptest) for token parsing and PII redaction edge-cases.
- Introduce fuzzing targets for parsers and request validators.
- Track coverage (e.g., via llvm-cov or grcov); set a baseline threshold in CI (informational at first).

## 3) Security Hardening (High)
- Enforce secrets policy:
  - Fail startup if JWT_SECRET is weak in production (already noted; ensure tests cover it).
  - Validate REQUEST_SIGNING_SECRET length and rotation cadence.
- Cryptographic key lifecycle:
  - Confirm keys::initialize_keys() generates and rotates keys with explicit retention and rollover windows.
  - Document operational runbook (rotation, revocation, emergency procedures).
- Strengthen input validation:
  - Centralize validation using validator crate for public-facing structs (request payloads).
  - Ensure consistent error messages without leaking internals.
- Formalize security headers middleware (single layer applying CSP/HSTS/etc. in one place with tests).
- Threat modeling review: add STRIDE checklist per endpoint in docs.

## 4) Observability and Operability (Medium)
- Metrics: ensure counters/histograms for key paths:
  - Token issuance, revocation, introspection (latency, status)
  - Policy eval success/failure, cache hits/misses, dependency timeouts
- Tracing: add spans for major flows with correlation IDs; ensure no sensitive values in spans.
- Health endpoints: extend admin health to include readiness gates (Redis available, policy service reachable, keyset loaded).
- Log sampling and rate limiting for noisy security events to prevent log flooding under attack.

## 5) Performance and Resilience (Medium)
- Backpressure and rate limiting:
  - Add configurable limits per client and global; export current state via metrics.
  - Add protection for burst scenarios (token bucket/leaky bucket combining IP + client ID).
- Cache tuning:
  - Validate policy cache eviction strategy and TTLs; add metrics for cache size and eviction reason.
- Benchmarks:
  - Criterion benchmarks for hot paths (token signing/verification, policy eval); ensure they run behind a feature flag as already configured.

## 6) Dependency and Supply Chain (Medium)
- Maintain cargo-deny config to pin or ban risky crates; review exceptions regularly.
- Enable dependabot or renovate for Cargo updates.
- Periodic SBOM generation and signing (CycloneDX present—ensure it’s refreshed in releases).

## 7) Developer Experience (Medium)
- Add pre-commit hooks: fmt, clippy, cargo-deny, basic tests (document in docs/development/README.md).
- Make TEST_MODE usage clearer in test harnesses with helpers to sign admin requests.
- Provide local "make"-like command aliases (justfile or cargo-make) for common tasks: build, test, lint, audit, run-dev.

## 8) Documentation Enhancements (Medium)
- Operational runbooks: key rotation, incident response, token revocation at scale, cache flush procedures.
- Security architecture diagram: request flows, trust boundaries, key storage.
- API contract tests in docs (via examples with wiremock where applicable).

## 9) Kubernetes/Production Readiness (Medium)
- Confirm Pod Security Standards and network policies align with zero-trust defaults.
- Add readiness/liveness probes for all services; ensure graceful shutdown tested.
- Resource requests/limits tuned; add Vertical/Horizontal Pod Autoscaler recommendations.

## 10) Roadmap Items (Optional/Advanced)
- Post-Quantum crypto features are gated—add ADR explaining threat model and when to enable.
- ML/threat-hunting features: document data flow, privacy considerations, and sampling.
- Consider OPA or Wasm policy sandboxing for policy-service defense-in-depth.

---

How to start:
1) Let the new Rust CI run on your next PR and address clippy/test feedback.
2) Pick one area per sprint (e.g., Testing Strategy) and close specific sub-items.
3) Convert this list into GitHub issues with labels: kind/enhancement, area/security, area/observability, priority.
