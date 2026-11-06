# AgentShield AI API Gateway

Reactive Spring Cloud Gateway for routing authenticated platform APIs to Identity Service, Agent Management and Policy Engine. The gateway does not implement Runtime Security Gateway enforcement.

## Versions

- Java 21
- Spring Boot 4.1.2
- Spring Cloud BOM 2025.1.4, which supports Boot 4.1.2 and manages Spring Cloud Gateway 5.0.4

## Configuration and run

Set `IDENTITY_SERVICE_URL`, `AGENT_MANAGEMENT_SERVICE_URL`, `POLICY_ENGINE_SERVICE_URL`, `IDENTITY_ISSUER`, `IDENTITY_JWKS_URI`, `API_GATEWAY_AUDIENCE`, and `GATEWAY_CORS_ALLOWED_ORIGINS`. Production service/JWKS/issuer URLs and frontend origins must use HTTPS. No secrets or URLs are embedded for production.

For local development, activate `local` with `SPRING_PROFILES_ACTIVE=local`. It uses localhost service URL defaults and permits HTTP only for loopback hosts. The frontend origin defaults to `http://localhost:3000`.

First-time organization setup is available at `POST /api/v1/onboarding/organizations` only when `GATEWAY_ORGANIZATION_ONBOARDING_ENABLED=true`; it is enabled by the local profile. Keep it disabled by default in production and enable it deliberately in both Gateway and Identity Service configuration. Identity performs the organization, initial user, and OWNER membership writes atomically.

Run `mvn clean verify` to verify the project. Health is exposed at `/actuator/health`.

## Routes

| Path | Target |
| --- | --- |
| `/api/v1/organizations/**`, `/api/v1/users/**` | Identity Service |
| `/api/v1/onboarding/organizations` | Identity Service (explicit feature flag; public signup) |
| `/api/v1/agents/**` | Agent Management Service |
| `/api/v1/policies/**` | Policy Engine |
| `/oauth2/**`, `/.well-known/**`, `/login` | Identity Service authentication endpoints |

All API traffic requires an RS256 access token with a valid issuer, audience, expiry, user ID, organization ID and OWNER/ADMIN/MEMBER organization role. The gateway removes client supplied identity and tenant headers, then replaces trusted identity headers from verified token claims. It forwards the bearer token for downstream validation. Member users can read their own user record and view organization resources; OWNER/ADMIN can manage them. The Policy Engine's evaluation endpoint is denied on this public API Gateway and is reserved for internal Runtime Security Gateway integration.

CORS uses an exact environment supplied origin allowlist without credentials. Requests receive a validated or generated `X-Correlation-ID`; logs omit credentials and payloads. Connect and response timeouts are 2 seconds and 5 seconds, and downstream 5xx/error responses contain only generic details.
