# Improvement Tasks Checklist

Below is an ordered, actionable checklist to improve architecture, security, reliability, performance, code quality, testing, operations, documentation, and CI/CD across this repository. Each item can be checked once completed. Items reference observed components such as auth-service, policy-service, Helm/Istio configs, monitoring, and scripts.

1. [ ] Establish an Architecture Decision Record (ADR) process and create initial ADRs for key choices (auth-service boundaries, policy-service responsibilities, storage, crypto libs).
2. [ ] Document the current high-level architecture diagram (services, data flows, external dependencies like Redis, Prometheus, Istio, Helm, OIDC IdPs).
3. [ ] Define clear service contracts between auth-service and policy-service (APIs, ownership of policy enforcement vs. policy evaluation, data models).
4. [ ] Introduce versioning for public APIs (OpenAPI/utoipa) and set a deprecation policy with timelines.
5. [ ] Create a formal configuration strategy (12-factor): environment variable schema, defaults, required vs optional, validation on startup.
6. [ ] Centralize secrets management (e.g., ExternalSecrets or sealed-secrets) and remove any plaintext secrets from manifests and scripts.
7. [ ] Define a consistent error model across services (thiserror + structured error responses) and replace ad-hoc anyhow usage in request paths.
8. [ ] Implement consistent request/trace context propagation across services (traceparent, request-id) and ensure propagation in all outbound calls.
9. [ ] Establish a unified DTO/schema layer with validation (serde + validator) to harden input handling for OAuth, SCIM, and OIDC endpoints.
10. [ ] Formalize a key management strategy for JWT signing: key generation, storage, rotation cadence, audit logging, and emergency key revoke/roll-over.
11. [ ] Audit the keys module for side-effects and race conditions on startup (auth-service::keys::initialize_keys) and add idempotency + retries.
12. [ ] Introduce policy caching and invalidation in policy-service with bounded TTLs and metrics for cache hit/miss.
13. [ ] Add circuit breakers and timeouts for all network I/O (Redis, HTTP, OIDC providers), using tower layers consistently.
14. [ ] Define backpressure and request body size limits for all endpoints (ensure MAX_REQUEST_BODY_SIZE is applied service-wide via middleware).
15. [ ] Consolidate rate limiting (per-IP and per-client) with clear configuration, quotas, and banlist/allowlist management.
16. [ ] Add feature flags for optional modules (SOAR, OIDC providers) to reduce attack surface when unused.
17. [ ] Ensure strong redirect URI validation in OAuth flows (strict allow-list, exact match rules, and test coverage for edge cases).
18. [ ] Normalize token store abstraction: finalize trait boundaries for TokenStore, ensure atomicity for revoke/refresh operations.
19. [ ] Add robust session cleanup scheduling with jitter, observability, and safe shutdown hooks.
20. [ ] Implement structured security log fields across all modules (actor, action, target, outcome, reason, correlation_id, ip, user_agent) and redact PII.
21. [ ] Enforce PII/SPI data classification and masking in logs and error messages (e.g., emails, phone numbers, tokens).
22. [ ] Add request authentication/authorization middleware for admin endpoints (metrics, health, introspection) as appropriate for production.
23. [ ] Validate SCIM filter parsing/length (MAX_FILTER_LENGTH) with safe parsing to avoid DoS and injection.
24. [ ] Create a dependency update and auditing workflow (cargo-audit, cargo-deny), with CI gates and risk exception handling.
25. [ ] Generate and publish SBOMs (cyclonedx-cargo) for each release; store in artifacts and align with supply-chain policies.
26. [ ] Adopt reproducible builds and provenance (SLSA level targets) for binaries/containers; sign artifacts (cosign).
27. [ ] Review cryptographic primitives: prefer ring/evercrypt/aws-lc for JWT signing, ensure RSA/ECDSA choices align with policy, and document.
28. [ ] Add secure randomness facade that is consistent across modules; remove any ad-hoc RNG usage.
29. [ ] Apply strict TLS settings for all outbound HTTP clients (min TLS1.2/1.3, cert pinning where applicable) and validate at startup.
30. [ ] Introduce secrets zeroization and memory hygiene for sensitive materials where feasible.
31. [ ] Add comprehensive timeout budgets and retries with exponential backoff and jitter for all external interactions.
32. [ ] Ensure graceful shutdown for background tasks (rate_limit_cleanup, security_monitoring, session_cleanup) with cancellation and drain.
33. [ ] Add Prometheus metrics registry export for all modules (tokens issued/refresh/revoked already present) and extend to error rates and latencies.
34. [ ] Instrument request handlers with latency histograms and high-cardinality safeguards; define SLOs for p50/p90/p99 latencies.
35. [ ] Add OpenTelemetry tracing (OTLP exporter) and correlate spans across services and background tasks.
36. [ ] Create Grafana dashboards for auth-service and policy-service (traffic, errors, latencies, rate limits, cache stats, key rotations).
37. [ ] Expand Alertmanager rules for security anomalies (spikes in auth failures, token revocation anomalies, unknown client IDs).
38. [ ] Add health/readiness/liveness endpoints with dependency checks (Redis, OIDC discovery, policy load) and wire to Kubernetes probes.
39. [ ] Review Helm charts: set resource requests/limits, HPA, PodDisruptionBudget, PodSecurityContext, SecurityContext (drop caps, readOnlyRootFilesystem).
40. [ ] Enforce Kubernetes NetworkPolicies to limit east-west traffic to necessary ports; ensure Istio PeerAuthentication is STRICT mTLS.
41. [ ] Tighten Istio AuthorizationPolicies for least-privilege access; audit zero-trust examples for production readiness.
42. [ ] Migrate any plaintext ConfigMaps of secrets to Secret or ExternalSecrets; rotate demo keys.
43. [ ] Add migration strategy for zero-downtime key rotation and token validation compatibility (accept old+new for a window).
44. [ ] Optimize Redis connection pooling and reconnection strategies; add metrics for pool exhaustion and latency.
45. [ ] Review async concurrency: replace heavy RwLock hotspots with more granular structures or sharded maps where appropriate.
46. [ ] Remove unwrap/expect in production paths; standardize error bubbling and mapping to HTTP responses.
47. [ ] Strengthen input validation across endpoints (lengths, formats, allowlists) with property-based tests.
48. [ ] Adopt clippy lints (deny on critical categories) and rustfmt in CI; fix current findings.
49. [ ] Introduce modular workspace-level features and crate separation where natural (e.g., move shared types to a common crate).
50. [ ] Establish a versioned configuration schema with sample .env files and validation tool (fail-fast on invalid config).
51. [ ] Add database or persistent storage strategy if/when in-memory stores are inadequate; document data retention policies.
52. [ ] Implement token introspection rate limiting and abuse protection; add anomaly detection hooks.
53. [ ] Ensure JWT audience/issuer/nonce validations are strict and covered by tests; document OIDC provider deviations.
54. [ ] Harden redirect validation against open redirect and path traversal; create unit + integration tests for edge cases.
55. [ ] Add fuzz testing for parsers (SCIM filter, OAuth params) using cargo-fuzz.
56. [ ] Add property-based testing (proptest/quickcheck) for token lifecycle invariants (issue -> refresh -> revoke cannot regress).
57. [ ] Expand integration tests covering OAuth/OIDC flows, SCIM CRUD, and policy evaluation under failure scenarios.
58. [ ] Add load tests to CI (k6 smoke profile) and schedule comprehensive runs; capture and compare baseline metrics.
59. [ ] Set up chaos experiments (fault injection, network latency) in a non-prod cluster; ensure resilience patterns hold.
60. [ ] Establish regression test packs and publish results to test_results/ with trend graphs.
61. [ ] Add security E2E tests simulating common attacks (credential stuffing, token replay, JWT tampering) with expected detections.
62. [ ] Ensure documentation for runbooks: incident response, key compromise procedures, emergency rotation steps.
63. [ ] Add developer onboarding guide and coding standards (error handling, logging, tracing, security patterns).
64. [ ] Update README with clear local dev instructions, service ports, and troubleshooting pointers.
65. [ ] Create OPERATIONS: capacity planning, SLOs, release process, rollback playbook.
66. [ ] Add CHANGELOG and release notes automation; semantic versioning for services.
67. [ ] Implement pre-commit hooks (format, clippy, cargo-deny) and git hooks for conventional commits.
68. [ ] Add CI workflows: build, test, lint, audit, SBOM, container build+scan, Helm chart lint, k8s dry-run, and deploy to staging.
69. [ ] Add container best practices: distroless images, non-root user, minimal layers, image signing and verification.
70. [ ] Configure secrets scanning in CI (gitleaks/trufflehog) and add allowlist where necessary.
71. [ ] Add license scanning and third-party notices; enforce license policy via cargo-deny.
72. [ ] Create performance budgets and alerts (latency, CPU/mem, GC/alloc) with automatic regression detection.
73. [ ] Profile hot paths (issue/refresh token, Redis interactions) and optimize allocations (avoid unnecessary clones, use &str where possible).
74. [ ] Review and cap Tokio runtime resources (worker threads, blocking pools) and audit blocking operations.
75. [ ] Ensure graceful reloads for configuration changes without restarts where feasible.
76. [ ] Add migration scripts/checklists for changes to policy formats or token schemas.
77. [ ] Add JWKS endpoint hardening: caching headers, ETag support, and rate limits; test with rotating keys.
78. [ ] Validate OAuth client registration flows and secure storage of client secrets (hashing, rotation policy).
79. [ ] Add automated verification of Helm values vs. env vars to detect drift; document required production overrides.
80. [ ] Create a periodic security posture report pipeline, aggregating metrics and logs into SECURITY_IMPROVEMENTS.md updates.
81. [ ] Audit logging to ensure no secrets or tokens are logged at any level; add tests that assert redaction.
82. [ ] Confirm all background tasks respect context cancellation and time budgets; add tests using tokio::time.
83. [ ] Add end-to-end tracing examples and dashboards for common flows (login, token refresh, SCIM user create).
84. [ ] Review and harden CORS configuration (allowlists, credentials policy) and add tests.
85. [ ] Ensure per-tenant or per-client isolation capabilities if multi-tenant usage is expected; document boundaries and quotas.
86. [ ] Add automated doc completeness checker into CI leveraging existing scripts; fail builds when critical docs are missing.
87. [ ] Create a security tabletop exercise checklist and store results under evidence/ with action items.
88. [ ] Codify threat models for critical flows and update SECURITY.md with mitigations and residual risks.
89. [ ] Add automated release pipelines to push Helm charts to a registry and sign them; include provenance metadata.
90. [ ] Set up regular dependency and base image update bots (Dependabot/Renovate) for Cargo and container images.
