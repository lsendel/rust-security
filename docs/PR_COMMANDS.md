# PR Slash Commands

Comment these commands on a PR to run targeted workflows:

- /ci-help
  - Posts this command reference into the PR.

- /security-scan [full]
  - Runs cargo-audit and cargo-deny on the PR head.
  - With `full`, also runs IaC and Dockerfile scans (Trivy, Checkov) and uploads SARIF artifacts.

- /performance-scan
  - Runs performance tests and benches (if configured), uploads Criterion results.

- /compliance-scan
  - Generates a CycloneDX SBOM and runs any available compliance tooling; uploads artifacts.

- /api-validate
  - Lints OpenAPI specs with Spectral and builds Rust docs to catch drift.

- /frontend-validate
  - Runs `npm ci`, lints, tests, and builds the `user-portal` app. Uploads built `dist` as an artifact.

- /image-scan
  - Builds Docker images for found Dockerfiles and scans them with Trivy; uploads SARIF to Code Scanning and artifacts.

Notes:
- These commands are limited to collaborators with write access or above.
- Artifacts are attached to the workflow run with names like `pr-<category>-results-<PR#>`.
- You can also apply labels to trigger the corresponding command automatically:
  - `security-scan` → `/security-scan full`
  - `performance-scan` → `/performance-scan`
  - `compliance-scan` → `/compliance-scan`
  - `api-validate` → `/api-validate`
  - `frontend-validate` → `/frontend-validate`
  - `image-scan` → `/image-scan`
