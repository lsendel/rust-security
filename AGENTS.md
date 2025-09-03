# Repository Guidelines

## Architecture Overview
```
User (browser)
  -> user-portal (Vite/React)
      -> auth-service (Axum) -----> policy-service (Axum + Cedar)
                      \            
                       -> compliance-tools (reports/SBOM)
Monitoring: Prometheus/Grafana + Alertmanager under monitoring/
```

## Project Structure & Module Organization
- Rust services and libraries: `auth-service/`, `policy-service/`, `input-validation/`, `compliance-tools/`, `api-contracts/`.
- Frontend (React/TS): `user-portal/` with tests under `src/components/__tests__/`.
- Security/ops: `monitoring/`, `helm/`, `gitops/`, `zero-trust/`, `config/`, `api-specs/`.
- Benchmarks and load tests: `benches/`, `load_test/`.
- Policies and entities: `policy-service/policies.cedar`, `policy-service/entities.json`.

## Build, Test, and Development Commands
- `just build`: Build all Rust crates (`cargo build --workspace --all-features`).
- `just test`: Run all Rust tests with features and verbose output.
- `just fmt` / `just fmt-check`: Format or verify formatting via rustfmt.
- `just lint`: Run clippy with warnings treated as errors.
- `just audit` / `just deny`: Dependency security checks (`cargo-audit`, `cargo-deny`).
- `just coverage-report` / `just coverage-check baseline=70`: Generate and enforce coverage.
- Frontend: `cd user-portal && npm run dev|test|build` (Vite + Vitest).

## Run Locally (Services)
- Auth Service: `CONFIG_DIR=config APP_ENV=development cargo run -p auth-service`
- Policy Service: `CONFIG_DIR=config APP_ENV=development cargo run -p policy-service`
- Frontend: `cd user-portal && npm install && npm run dev` (default: http://localhost:5173)
- Notes: services read `config/{base,development,local}.toml`; env vars with prefix `AUTH__` override for auth-service.

## Quick Checks
- Auth health: `curl -s http://127.0.0.1:8080/health | jq .`
- Auth status: `curl -s http://127.0.0.1:8080/api/v1/status | jq .`
- Policy health: `curl -s http://127.0.0.1:8081/health | jq .`
- Policy authorize:
  `curl -sS -H 'Content-Type: application/json' -d '{"request_id":"dev-1","principal":{"type":"User","id":"alice"},"action":"Document::read","resource":{"type":"Document","id":"doc1"},"context":{}}' http://127.0.0.1:8081/v1/authorize`

## Local .env Template
```
# Auth Service overrides (prefix AUTH__)
AUTH__SERVER__PORT=8080
AUTH__JWT__SECRET=change-me-at-least-32-chars-long
AUTH__DATABASE__URL=sqlite::memory:
AUTH__REDIS__URL=redis://localhost:6379
AUTH__OAUTH__REDIRECT_BASE_URL=http://localhost:8080/auth/callback
# Optional: tighten security
AUTH__SECURITY__BCRYPT_COST=12
```

## Coding Style & Naming Conventions
- Rust: 4-space indent, `rustfmt` enforced; `clippy` must pass with `-D warnings`.
  - Modules/functions: `snake_case`; types/enums/traits: `CamelCase`; constants: `SCREAMING_SNAKE_CASE`.
- TypeScript/React: Follow ESLint rules; 2-space indent; components in `PascalCase`.
- Keep files focused; prefer small modules under `src/` with clear names (e.g., `metrics.rs`, `errors.rs`).

## Testing Guidelines
- Rust unit tests live next to code (`mod tests`); integration tests in `tests/*.rs`.
- Benches in `benches/`; performance helpers in `load_test/`.
- Frontend tests in `user-portal/src/components/__tests__/*.test.tsx`.
- Run: `just test` (Rust); `cd user-portal && npm run test` (UI).
- Coverage: `just coverage-report`; enforce baseline with `just coverage-check baseline=70`.

## Commit & Pull Request Guidelines
- Commits: Imperative mood, concise summary (e.g., "Refactor JWT handling"), wrap body at ~72 chars, reference files/areas (e.g., `policy-service:`) when useful.
- PRs: Clear description, motivation, and scope; link issues; include test evidence and potential security/perf impact. For UI changes, add screenshots or GIFs.

## Security & Configuration Tips
- Never commit secrets; prefer configs under `config/` and Helm values with external secrets.
- Run `just validate-security` and `just ci-complete` before PRs.
- Generate SBOMs with `just sbom-generate`; review `monitoring/` and `helm/` changes for operational impact.
