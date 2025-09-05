# Policy Service (MVP)

A lightweight authorization service using the Cedar policy language, built with Axum/Tokio.

- Endpoints:
  - `GET /health`: service health
  - `POST /v1/authorize`: evaluate an authorization request against loaded policies
  - `GET /metrics`: basic metrics (text), enabled by default via a minimal prom-client feature

## Run

- Workspace: `cargo run -p policy-service`
- Direct: `cd enterprise/policy-service && cargo run`

Environment:
- `PORT` (default: `8081`)
- `ALLOWED_ORIGINS` (comma-separated; optional)

## Policies

- Default files: `policies.cedar`, `entities.json` in this folder.
- If missing, the service loads a permissive MVP default allowing authenticated users.

## Test

- `cargo test -p policy-service`

## Notes

- This crate is now part of the root workspace.
- For production, wire real policies/entities and tighten CORS and metrics configuration.
