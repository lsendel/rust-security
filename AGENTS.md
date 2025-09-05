# Repository Guidelines

## Architecture Overview
- User interacts with `user-portal` (Vite/React), which authenticates via `auth-service` (Axum) and authorizes via `policy-service` (Axum + Cedar). `compliance-tools` produces reports/SBOM. Monitoring is under `monitoring/` (Prometheus/Grafana/Alertmanager).

## Project Structure & Module Organization
- Rust crates: `auth-service/`, `policy-service/`, `input-validation/`, `compliance-tools/`, `api-contracts/`.
- Frontend: `user-portal/` with tests in `src/components/__tests__/`.
- Ops/Security: `monitoring/`, `helm/`, `gitops/`, `zero-trust/`, `config/`, `api-specs/`.
- Performance: `benches/`, `load_test/`. Policies: `policy-service/policies.cedar`, `policy-service/entities.json`.

## Build, Test, and Development Commands
- `just build`: Build all Rust crates (`cargo build --workspace --all-features`).
- `just test`: Run all Rust tests with verbose output.
- `just fmt` / `just fmt-check`: Format or verify via rustfmt.
- `just lint`: Clippy with `-D warnings`.
- `just audit` / `just deny`: Dependency security checks.
- Frontend: `cd user-portal && npm run dev|test|build`.

## Run Locally (Services)
- Auth: `CONFIG_DIR=config APP_ENV=development cargo run -p auth-service` (health: `curl :8080/health`).
- Policy: `CONFIG_DIR=config APP_ENV=development cargo run -p policy-service` (authorize endpoint `/v1/authorize`).
- Frontend: `cd user-portal && npm install && npm run dev` (defaults to http://localhost:5173).

## Coding Style & Naming Conventions
- Rust: 4‑space indent; `rustfmt` enforced; Clippy clean with warnings as errors.
- Rust naming: modules/functions `snake_case`; types/enums/traits `CamelCase`; constants `SCREAMING_SNAKE_CASE`.
- TypeScript/React: ESLint rules, 2‑space indent; components in `PascalCase`.

## Testing Guidelines
- Rust unit tests inline; integration tests in `tests/*.rs`; benches in `benches/`.
- UI tests: `user-portal/src/components/__tests__/*.test.tsx` (Vitest).
- Coverage: `just coverage-report`; enforce with `just coverage-check baseline=70`.

## Commit & Pull Request Guidelines
- Commits: imperative mood, concise (e.g., "Refactor JWT handling"); wrap body ~72 chars; prefix area when useful (e.g., `policy-service:`).
- PRs: describe motivation/scope, link issues, include test evidence; note security/perf impact; add UI screenshots/GIFs for frontend changes.

## Security & Configuration Tips
- Do not commit secrets; prefer `config/` and Helm external secrets.
- Overrides: env vars like `AUTH__JWT__SECRET`, `AUTH__SERVER__PORT`. Local template in `.env`.
- Before PRs: run `just validate-security` and `just ci-complete`. Generate SBOMs with `just sbom-generate`.

## Policy Integration (Auth ↔ Policy Service)
- Enable remote decisions: `ENABLE_REMOTE_POLICY=1` and set `POLICY_SERVICE_BASE_URL` (e.g., `http://127.0.0.1:8081`). Optional fail‑open: `POLICY_FAIL_OPEN=1`.
- Auth gates (optional): profile (`/api/v1/auth/me`), OAuth (`/oauth/authorize`, `/oauth/token`), login, and all `/admin/*` endpoints (granular actions like `Admin::users_read`, `Admin::billing_update`).
- Metrics: with `--features metrics`, Prometheus `/metrics` includes `auth_policy_evaluation_total{policy_type="remote",endpoint_group,resource,action,result}` and latency histogram.
- Example Cedar allow (policy-service): allow admin metrics read
  - principal: `Admin::<hashed-admin-key>`, action: `Admin::metrics_read`, resource: `AdminEndpoint::<path>`.
