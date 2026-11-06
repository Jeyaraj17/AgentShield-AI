# AgentShield AI Analysis Service

Standalone Spring Boot 4.1.2 service for heuristic security analysis and advisory agent trust scoring. Java 21, Maven, Spring AI 2.0.2, MySQL, Flyway and JPA are used. Spring AI 2.0.x supports Spring Boot 4.1.x; the OpenAI chat starter is optional at runtime and disabled by default. [Spring AI compatibility and setup](https://docs.spring.io/spring-ai/reference/getting-started.html), [OpenAI chat configuration](https://docs.spring.io/spring-ai/reference/api/chat/openai-chat.html).

## Run

Set `AI_ANALYSIS_DB_URL`, `AI_ANALYSIS_DB_USERNAME`, `AI_ANALYSIS_DB_PASSWORD`, `IDENTITY_ISSUER`, `IDENTITY_JWKS_URI`, `AI_ANALYSIS_GATEWAY_AUDIENCE`, `AI_ANALYSIS_ALLOWED_AUDIENCES`, `AGENT_TOKEN_AUDIENCE`, and `RUNTIME_GATEWAY_ANALYSIS_CLIENT_ID`. Database credentials and issuer/JWKS settings have no insecure production fallback. Flyway creates tables and Hibernate validates the schema.

LLM analysis is off by default. To enable OpenAI-assisted response moderation, set `AI_LLM_ENABLED=true`, `AI_LLM_PROVIDER=openai`, and provide `OPENAI_API_KEY` from a secret manager or environment. The configured timeout defaults to five seconds and automatic retries are disabled. Sensitive values are redacted before any provider call. Deterministic checks and authorization are independent of LLM output.

For local HTTP identity endpoints, activate `SPRING_PROFILES_ACTIVE=local` and use loopback URLs. Set `AI_ANALYSIS_CORS_ALLOWED_ORIGINS` to exact dashboard origins. Optional custom regex rules use `AI_SENSITIVE_PATTERNS=CATEGORY=REGEX;CATEGORY=REGEX` and `AI_BIAS_TOXICITY_RULES=CATEGORY=REGEX`; choose patterns carefully because invalid expressions fail startup. Run `mvn clean verify`; tests use H2 and mocked JWT/LLM components without paid provider calls.

## APIs

- `POST /api/v1/analysis/prompts` — deterministic injection and sensitive-data analysis. Requires the Runtime Gateway service token and signed agent assertion.
- `POST /api/v1/analysis/responses` — sensitive-data and rule-based bias/toxicity analysis, with optional advisory LLM assistance.
- `POST /api/v1/analysis/hallucinations` — compares response claims heuristically to trusted evidence; it cannot establish truth with certainty.
- `POST /api/v1/analysis/behavior` — persists gateway-supplied metrics and deterministically compares them to recent history.
- `GET /api/v1/agents/{agentId}/trust-score` — OWNER/ADMIN only, scoped to the organization in the user token.
- `GET /api/v1/agents/{agentId}/risk-history` — OWNER/ADMIN only, tenant-scoped.
- `GET /api/v1/agents/{agentId}/drift-history` — OWNER/ADMIN only, tenant-scoped.

Trust score is a normalized weighted average (defaults: security 25%, policy 20%, reliability 20%, output quality 20%, drift stability 15%). Each dimension is returned with its evidence and explanation. The score is advisory only; it never authorizes, denies, or executes actions. Request rate limits are process-local and should be backed by a shared gateway limiter in a multi-instance deployment.

## Security notes

Only the dedicated Runtime Gateway analysis OAuth client with `identity_type=service`, `token_type=service`, `service_role=RUNTIME_GATEWAY_ANALYSIS`, the exact `analysis.evaluate` scope, and the `AI_ANALYSIS_GATEWAY_AUDIENCE` may submit runtime analyses. The service independently validates `X-Agent-Assertion` from Identity JWKS and checks `X-Organization-ID` and `X-Agent-ID` against its verified claims before using those claims for tenant-scoped persistence. These headers are consistency checks, never tenant authority. User analytics use verified organization claims and OWNER/ADMIN roles. Analysis records store result metadata and redacted findings, not raw prompt/response contents. LLM text is advisory and is never used for authorization.

Runtime Gateway requests `analysis.evaluate` using the separate `RUNTIME_GATEWAY_ANALYSIS_CLIENT_ID` and `RUNTIME_GATEWAY_ANALYSIS_CLIENT_SECRET`; do not reuse the broader Runtime Gateway client credentials. `POST /api/v1/analysis/prompts` accepts `{"prompt":"..."}` and `/responses` accepts `{"response":"..."}`. Both require `Authorization: Bearer <analysis-service-token>`, `X-Agent-Assertion: <Identity-signed agent JWT>`, and matching `X-Organization-ID` and `X-Agent-ID` headers. The assertion is accepted only in that dedicated header; agent credentials are not used as the bearer. The Gateway treats returned analysis as advisory and continues to rely on Policy Engine for authorization. Its optional runtime mapping analyzes a string `input.prompt` before policy evaluation and a string `response` field from an approved tool result after execution.
