# Contributing Guidelines

## Lint & Quality
- Run clippy locally with warnings enabled for perf/suspicious/pedantic:
  - `cargo clippy --workspace --all-features -- -W clippy::perf -W clippy::suspicious -W clippy::pedantic`
- Warnings are allowed by default; critical lints (panics in core paths, unsafe) must be fixed.
- Prefer Result-based error handling over `unwrap`/`expect`; use logging + fallbacks where sensible.

## Build & Test
- Build all crates: `cargo check --workspace --all-features`
- Run tests: `cargo test --workspace`
- Security audit: `cargo audit` (configured via `.cargo/audit.toml`).

## Commit & PRs
- Use imperative summaries, reference areas (e.g., `policy-service:`), and include validation evidence (clippy/test/audit).
- For UI changes, include screenshots; for APIs, attach curl examples.

## Before You Push
- `cargo clippy` clean in modified code.
- `cargo test` passes locally.
- No secrets in changes; config goes under `config/` or external secret stores.
