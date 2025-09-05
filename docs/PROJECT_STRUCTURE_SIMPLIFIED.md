# Project Structure (Simplified)

This document summarizes a simplified, consistent structure for the repository to reduce duplication and make navigation and builds predictable. Changes applied in this pass are low‑risk and reversible.

## Workspace Crates
- `auth-service/`: Main authentication service (Axum/Tokio).
- `mvp-oauth-service/`: Minimal OAuth service used for demonstrations and quick starts.
- `common/`: Shared utilities and cross‑cutting helpers.
- `mvp-tools/`: Essential tooling and helper modules (contains `api-contracts/`, `input-validation/`, etc.).
- `enterprise/policy-service/`: Cedar-based authorization service (now in workspace).

Notes:
- Enterprise and experimental components mostly remain under `enterprise/`. The policy service is enabled as a workspace member for development and testing.

## Benchmarks
- Canonical location: `benchmarks/` crate with `benches/` folder.
- Consolidation:
  - Moved root `benches/` into `benchmarks/benches/`.
  - Configured `benchmarks/Cargo.toml` with explicit `[[bench]]` entries and `harness = false` for Criterion.

How to run:
- `cargo bench -p auth-service-benchmarks --no-run` to compile quickly.
- `cargo bench -p auth-service-benchmarks` to run (may require services like Redis if enabled in a benchmark).

## Examples and Scripts
- Canonical location: `mvp-tools/examples/`.
- Consolidation:
  - Moved standalone Rust scripts from repo root into `mvp-tools/examples/`.
  - These are illustrative; for real coverage, prefer crate unit/integration tests.

## Frontend and Ops
- Frontend: `user-portal/` (Vite/React).
- Monitoring: `monitoring/` (Prometheus/Grafana/Alertmanager).
- Deployment manifests: prefer `helm/` and `gitops/`. Duplicated directories like `deploy/`, `deployment/`, and `k8s/` contain overlapping assets — recommend consolidating into Helm charts and GitOps pipelines over time.

## Next Simplifications (Proposed)
- Choose a single auth service for MVP: either keep `mvp-oauth-service` or fold it into `auth-service` (rename or mark one as deprecated).
- Add (or re‑enable) `policy-service/` as a workspace member if authorization is in‑scope; otherwise, update monitoring and docs to mark it as optional/enterprise.
- Collapse `justfile.enhanced` into the primary `justfile` and remove duplication.
- Remove root‑level `node_modules` by relocating integration test tooling into a scoped package (e.g., under `mvp-tools/tests/integration`) and adding a per‑folder install.
- Normalize test locations: move root `.rs` tests into `tests/` under their respective crates.

## Rationale
- One place for benchmarks and examples reduces confusion.
- Keeping workspace members minimal speeds builds and reduces dependency surface.
- Gradual consolidation of ops manifests eases maintenance without breaking current workflows.
