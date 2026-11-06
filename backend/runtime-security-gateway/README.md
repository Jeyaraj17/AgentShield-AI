# AgentShield AI Runtime Security Gateway

The Runtime Security Gateway is the enforcement point for AI agent tool actions. It validates a signed access token, checks that the requested agent is active and belongs to the token's organization, checks the agent's registered capabilities, asks the Policy Engine for a deterministic decision, then executes an allowed action only through a pre-registered destination.

## Runtime flow

`POST /api/v1/runtime/execute` accepts an `agentId`, `action`, `resourceId`, input payload and optional correlation ID. Only verified agent tokens are accepted: `identity_type=agent`, `token_type=agent`, `agent_role=AGENT`, matching `sub` and `agent_id`, plus a verified `organization_id` and required runtime audience. The gateway does not accept a destination URL, organization ID, user ID or role as trusted request data. It fetches the agent using its own short-lived Client Credentials token for `agents.read`, and sends the verified organization as a scoped header. If input contains a string `prompt`, the gateway sends it to AI Analysis using a separate analysis-only Client Credentials token and the signed agent assertion in `X-Agent-Assertion`, with verified organization/agent IDs as consistency headers. If an approved tool returns a string `response` field, that content is sent for response analysis after execution. Analysis output is advisory and never changes, grants, or substitutes for the Policy Engine decision. Analysis timeouts and service errors are recorded only as safe correlation-only warnings; the independent Policy Engine decision and fail-closed execution path remain authoritative. Before execution, it obtains a separate `policy.evaluate` token and calls Policy Engine with that service bearer plus the signed agent JWT in `X-Agent-Assertion`; the assertion is never forwarded to tools. Policy Engine independently validates both identities and verifies the agent organization and ID against the request. It must return a structurally valid `ALLOW` response, including a matched allow rule, before execution starts. Policy token acquisition failure, denial, malformed response or integration failure is audited and fails closed. Authorization and execution outcomes are stored separately. `GET /api/v1/runtime/executions/{executionId}` returns an execution only within the verified organization; agent principals are bound to their own agent records.

## Configuration

Required environment variables:

| Variable | Purpose |
| --- | --- |
| `RUNTIME_DB_URL` | JDBC URL for the dedicated runtime database/schema |
| `RUNTIME_DB_USERNAME` | Runtime database user |
| `RUNTIME_DB_PASSWORD` | Runtime database password |
| `IDENTITY_ISSUER_URI` | Expected JWT issuer |
| `IDENTITY_JWKS_URI` | Identity Service JWKS endpoint |
| `RUNTIME_JWT_AUDIENCE` | Audience required on access tokens |
| `IDENTITY_TOKEN_URI` | Identity Service OAuth token endpoint |
| `RUNTIME_GATEWAY_CLIENT_ID` | Dedicated confidential Runtime Gateway OAuth client ID |
| `RUNTIME_GATEWAY_CLIENT_SECRET` | Its secret, supplied by deployment secret management |
| `RUNTIME_GATEWAY_ANALYSIS_CLIENT_ID` | Separate analysis-only confidential OAuth client ID |
| `RUNTIME_GATEWAY_ANALYSIS_CLIENT_SECRET` | Separate secret with only the `analysis.evaluate` permission |
| `AGENT_MANAGEMENT_BASE_URL` | Agent Management Service base URL |
| `POLICY_ENGINE_BASE_URL` | Policy Engine base URL |
| `AI_ANALYSIS_BASE_URL` | AI Analysis Service base URL |
| `AI_ANALYSIS_AUDIENCE` | AI Analysis service-token audience; defaults to `ai-analysis-api` in Identity |
| `AI_ANALYSIS_CONNECT_TIMEOUT` | Analysis-service connection timeout; defaults to `2s` |
| `AI_ANALYSIS_RESPONSE_TIMEOUT` | Analysis-service response timeout; defaults to `3s` |
| `RUNTIME_TOOL_DESTINATIONS` | Allowlisted `action=absolute-URL` mappings, comma-separated |

Configure timeouts with `RUNTIME_CONNECT_TIMEOUT` and `RUNTIME_READ_TIMEOUT`. Database passwords and tool destinations must come from the deployment environment or a local, uncommitted environment file. Production service URLs and JWKS must use HTTPS. Localhost HTTP is permitted only with the `local` or `test` profile. Tool destinations reject credentials, query strings and fragments, and HTTP clients do not follow redirects.

For local development, set the database credentials and activate `local` (for example, `SPRING_PROFILES_ACTIVE=local`). The local profile supplies localhost service URL defaults and a mock `tool.echo` destination on port 8090. Start that mock protected tool separately. Tests use H2 and do not require MySQL credentials.

Run the service from this directory with:

```sh
mvn spring-boot:run
```

Flyway creates the runtime execution audit table. Hibernate validates the migrated schema and does not update it. Only `/actuator/health` is public; runtime endpoints require a valid bearer token.

## Integration boundary

Automated tests use mocked JWT decoding, token acquisition, Agent Management and Policy Engine clients, plus in-process mock tool and AI Analysis HTTP services. Identity tests separately exercise credential and OAuth token issuance; Policy Engine tests separately exercise the gateway-only evaluation boundary. These tests do not demonstrate a live multi-service deployment. For live use, configure matching Identity issuer/JWKS, agent/runtime audiences, both Runtime Gateway client IDs and secrets, `AI_ANALYSIS_AUDIENCE`, the AI Analysis URL, Agent Management and Policy Engine URLs, TLS, and registered agent credentials. The analysis client can request only `analysis.evaluate`; its short-lived token is sent as the AI Analysis bearer. The agent JWT is sent only as the separately named signed assertion header. The existing Runtime Gateway token remains separately requested for `agents.read` and `policy.evaluate`.

RabbitMQ publication is prepared behind `SecurityEventPublisher`; the current implementation logs structured event metadata and persists execution records. RabbitMQ delivery and durable outbox processing are not included yet.
