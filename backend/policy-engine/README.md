# AgentShield AI Policy Engine

Standalone Spring Boot 4.1.2 policy service for organization-scoped, deterministic authorization. It runs on Java 21 and owns a dedicated `policy_engine` database. It does not use an LLM to authorize actions.

## Build and run

Set `POLICY_DB_URL`, `POLICY_DB_USERNAME`, `POLICY_DB_PASSWORD`, `IDENTITY_ISSUER`, `IDENTITY_JWKS_URI`, and `RUNTIME_GATEWAY_CLIENT_ID`. `POLICY_ENGINE_ALLOWED_AUDIENCES` controls accepted user/API audiences (default `agentshield-api,policy-engine-api`); `POLICY_ENGINE_AUDIENCE` is the dedicated gateway service-token audience (default `policy-engine-api`); `AGENT_TOKEN_AUDIENCE` is the expected agent assertion audience (default `agentshield-runtime-api`). Set `POLICY_CORS_ALLOWED_ORIGINS` for exact dashboard origins. Do not place production secrets in source control.

Run `mvn clean verify`. For local development, activate the `local` profile with `SPRING_PROFILES_ACTIVE=local`; database credentials remain environment supplied. Flyway applies schema migrations and Hibernate validates the schema. Health is available at `/actuator/health`.

## API

- `POST /api/v1/policies`: create version 1 as DRAFT (OWNER/ADMIN).
- `GET /api/v1/policies`: list latest organization versions.
- `GET /api/v1/policies/{policyId}`: get the latest version and rules.
- `PUT /api/v1/policies/{policyId}`: create the next DRAFT version.
- `PATCH /api/v1/policies/{policyId}/status`: create an ACTIVE or DISABLED version.
- `GET /api/v1/policies/{policyId}/versions`: list retained versions.
- `POST /api/v1/policies/evaluate`: evaluation boundary reserved for the Runtime Security Gateway.

JWT signature (RS256), issuer, audience and expiry are validated against Identity JWKS. Policy administration accepts user tokens only and derives the tenant and OWNER/ADMIN/MEMBER role from verified claims; every policy query is organization-scoped. The evaluation route requires the configured gateway client ID, matching `sub`/`client_id`, `identity_type=service`, `token_type=service`, and `service_role=RUNTIME_GATEWAY`, so user and agent tokens cannot call it. It also requires `X-Agent-Assertion` and `X-Organization-ID`: the signed agent assertion is independently validated for issuer, signature, expiry, audience and agent type, then its subject, organization and agent claims are checked against the header and evaluation body. Runtime Gateway checks the agent is active, organization-bound and supports the requested capability through Agent Management before calling Policy Engine. Request-body tenant or role values are not used as authority. The service audience and gateway client ID, and the agent audience and Identity JWKS/issuer must match deployment configuration.

Rules use a constrained JSON condition format (`ALL`/`ANY`, `resource` or `context.*` fields, and a fixed operator enum); expressions and scripts are not accepted. A matching DENY takes precedence; otherwise a matching ALLOW is required. Evaluation failures deny.

The user allowlist (`POLICY_ENGINE_ALLOWED_AUDIENCES`) and gateway service audience (`POLICY_ENGINE_AUDIENCE`) are configured independently. The Runtime Gateway requests a dedicated `policy.evaluate` service token and forwards the original signed agent token only in `X-Agent-Assertion`, never as the Policy Engine bearer token. Automated tests exercise this boundary with signed test JWTs; the live local integration flow is separate and uses H2 databases and a mock protected tool.
