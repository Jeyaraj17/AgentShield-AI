# Identity Service

AgentShield AI Identity Service manages global user identities, organizations, and organization memberships. It provides OAuth 2.0 Authorization Code authentication for the React single page application and issues tenant-scoped RSA-signed JWT access tokens.

## Requirements

- Java 21
- Maven 3.6.3 or newer
- MySQL 8 available for a local run
- RSA key pair for non-local deployments (managed by a secret manager or KMS workflow)

## Build and test

From this directory, run:

```shell
mvn clean verify
```

The test suite uses an in-memory H2 database so it does not require a running MySQL server.

## Run

Create the `agentshield_identity` database in MySQL and configure these environment variables before starting the service:

| Variable | Required value |
| --- | --- |
| `DB_URL` | JDBC URL for the Identity Service database, such as `jdbc:mysql://localhost:3306/agentshield_identity?preserveInstants=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true` |
| `DB_USERNAME` | A MySQL account for the service with the required database permissions |
| `DB_PASSWORD` | The password for that account |

The application has no default database credentials. If a required setting is missing outside H2-based tests, startup fails with the names of the missing variables and does not print their values. Set credentials through your shell or IDE run configuration. For local file-based configuration, create `application-local-secrets.properties` in this module directory with `spring.datasource.url`, `spring.datasource.username`, and `spring.datasource.password` entries. The local profile loads this optional file, and the repository `.gitignore` excludes it. Never commit credentials or place them in source control. Avoid entering passwords in commands that are saved in shell history.

For PowerShell, set the non-secret URL and configure the credentials in your terminal or IDE environment, then run:

```powershell
$env:DB_URL = "jdbc:mysql://localhost:3306/agentshield_identity"
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

The `local` profile enables Hibernate schema updates for the existing business tables and temporarily permits the existing organization, user, and membership management endpoints without authentication. Use this profile only for local development. The OAuth persistence tables are created by the Flyway migration and do not depend on Hibernate schema update. The test profile uses an in-memory H2 database and does not require MySQL credentials.

## OAuth 2.0 authentication

The Authorization Server uses the configured issuer, publishes public signing keys at `/oauth2/jwks`, and persists client registrations and authorizations in JDBC tables created by Flyway. It registers one public first-party SPA client with the exact redirect URI supplied below. The client is restricted to Authorization Code, no client authentication secret, the `agentshield.api` scope, and PKCE S256. On startup, persisted settings are checked against these values and startup fails on drift. The SPA selects an organization with the `organization_id` authorization request parameter; the service treats it as untrusted and checks the authenticated user's active status, the organization's active status, and the user's active membership before allowing authorization and again when signing the access token.

Access tokens are RSA/RS256 signed, live for ten minutes, and contain `sub`, `user_id`, `organization_id`, `organization_role`, `iss`, and `aud` claims. The decoder validates the key ID, signature algorithm, issuer, expiry, configured audience, and current user, organization, and membership status. User IDs and organization roles are loaded from the database; request-supplied roles are ignored. The SPA is configured as a public client and has no client secret. Refresh tokens are not enabled.

Set these additional environment variables outside local/test profiles:

| Variable | Required value |
| --- | --- |
| `AUTH_ISSUER` | Stable HTTPS issuer URL, for example `https://identity.example.com` |
| `AUTH_AUDIENCE` | API audience expected by downstream Resource Servers |
| `AUTH_SPA_REDIRECT_URI` | Exact registered SPA callback URI; no wildcard or pattern matching |
| `AUTH_SIGNING_PRIVATE_KEY_BASE64` | Base64-encoded PKCS#8 RSA private key bytes |
| `AUTH_SIGNING_PUBLIC_KEY_BASE64` | Base64-encoded X.509 RSA public key bytes matching the private key |
| `AUTH_SIGNING_KEY_ID` | Stable `kid` for the active signing key; use a new unique value for each rotated key |
| `AUTH_SIGNING_PREVIOUS_PUBLIC_KEYS` | Optional semicolon-separated `kid:base64-X509-public-key` entries for previous keys that must remain valid |
| `AUTH_SPA_CLIENT_ID` | Optional stable client ID; defaults to `agentshield-react-spa` |
| `AUTH_CORS_ALLOWED_ORIGINS` | Comma-separated exact HTTPS origins of approved browser clients; no paths, wildcards, or credentials |
| `TRUSTED_PROXY_ADDRESSES` | Optional comma-separated exact IP addresses of reverse proxies permitted to supply forwarded headers |
| `AUTH_RATE_LIMIT_MAX_REQUESTS` | Optional authentication requests per source address per fixed window; defaults to `30` |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS` | Optional fixed-window duration; defaults to `60` seconds |
| `IDENTITY_ONBOARDING_ENABLED` | Set to `true` only when public organization onboarding is intentionally enabled; defaults to `false` outside local/test |
| `ONBOARDING_RATE_LIMIT_MAX_REQUESTS` | Optional onboarding requests per source address per fixed window; defaults to `3` |
| `ONBOARDING_RATE_LIMIT_WINDOW_SECONDS` | Optional onboarding fixed-window duration; defaults to `3600` seconds |

Configure the matching issuer, audience, React callback URI, and exact CORS origins. In local/test profiles, the service creates an ephemeral RSA key at startup; tokens from that key stop validating after restart. Non-local/test profiles reject HTTP issuer and callback URLs, reject ephemeral signing keys, and fail startup when required signing material is missing. Keep private key material in a secret manager or KMS integration and never place it in source control or logs. To rotate keys, deploy the new active key and include each still-valid former key as a previous public key. Remove an old key only after all tokens signed by it have expired and resource-server JWKS caches have refreshed. This supports key overlap but does not implement KMS/HSM signing.

The sign-in page is `/login`. The React SPA begins authorization at `/oauth2/authorize` with `response_type=code`, the registered `client_id` and `redirect_uri`, `scope=agentshield.api`, `organization_id`, `state`, and a PKCE `code_challenge` using `S256`. It exchanges the returned code at `/oauth2/token` with the same redirect URI and `code_verifier`. Restrict the client redirect URI to the actual React origin and callback path.

First-time organization setup uses `POST /api/v1/onboarding/organizations` through the API Gateway. The request carries organization name, initial owner's first/last name, email and password. Identity creates the organization, normalized global user, BCrypt password hash and ACTIVE OWNER membership in one database transaction, and returns only the organization ID after commit. A failed or duplicate-email attempt rolls back the complete operation and returns a generic conflict response. The endpoint is off by default outside local/test; production requires deliberate `IDENTITY_ONBOARDING_ENABLED=true` and `GATEWAY_ORGANIZATION_ONBOARDING_ENABLED=true` opt-in. It uses the existing configurable per-source-address authentication rate limit. The direct organization, user and membership setup endpoints remain local/test-only and do not allow a caller to request OWNER in an existing organization.

Only the OAuth protocol endpoints, the login page needed by the authorization flow, and `/actuator/health` are available without a logged-in user. Existing management APIs remain limited to local/test profiles. Other application routes are denied by default. All non-local/test HTTP requests, including health probes, are rejected unless a configured trusted proxy supplies HTTPS forwarding information. Forwarded headers are ignored unless the immediate peer IP exactly matches `TRUSTED_PROXY_ADDRESSES`; the proxy must strip client-supplied forwarding headers and set its own. The server does not enable container-wide forwarded-header handling. Use a TLS health probe or a trusted TLS-terminating proxy.

The login, authorization, and token endpoints share a configurable fixed-window per-source-address limiter. It returns HTTP 429 with `Retry-After` and resets after the configured window; it does not permanently lock accounts or distinguish unknown users. The limiter is in-memory and per application instance, so production deployments with multiple replicas still need an edge-level shared rate limit. CORS allows only the exact configured origins, `GET`, `POST`, and preflight `OPTIONS`, with `Authorization`, `Content-Type`, and `Accept` headers. Credentialed CORS is disabled. Session cookies are HttpOnly, Secure outside local/test, SameSite=Lax, and cookie-only.

## Machine identities

OWNER/ADMIN users may issue or revoke an agent credential at `POST` or `DELETE /api/v1/organizations/{organizationId}/agents/{agentId}/credentials[/{credentialId}]`. The request must be authenticated as a user with an active membership in the URL organization, and Identity verifies the active agent and its organization through Agent Management before issuing. Issuance returns a 256-bit random Base64url credential once. Identity stores only its BCrypt secret verifier in OAuth client persistence and a separate credential-to-agent/organization/status binding in `agent_credentials`; it does not return the credential again. Revocation disables that binding and future token grants fail. Configure `AGENT_MANAGEMENT_BASE_URL` for this verification.

Agents authenticate to `/oauth2/token` with the `client_credentials` grant, their issued credential, and the `agentshield.agent` scope. Client-supplied agent or organization parameters are ignored. Active credential and organization binding determine token claims. The short-lived RS256 token contains `iss`, `sub` (agent UUID), `aud` (`AGENT_TOKEN_AUDIENCE`), `iat`, `exp`, `agent_id`, `organization_id`, `identity_type=agent`, `token_type=agent`, and `agent_role=AGENT`.

Identity provisions a confidential Runtime Gateway client from `RUNTIME_GATEWAY_CLIENT_ID` and `RUNTIME_GATEWAY_CLIENT_SECRET`. It may request exactly one of `agents.read` or `policy.evaluate`, yielding a short-lived RS256 service token scoped to the Agent Management or Policy Engine audience. Separately, Identity provisions the analysis-only confidential client from `RUNTIME_GATEWAY_ANALYSIS_CLIENT_ID` (default `agentshield-runtime-gateway-analysis`) and `RUNTIME_GATEWAY_ANALYSIS_CLIENT_SECRET`. It may request only `analysis.evaluate` and receives a two-minute RS256 service token with audience `AI_ANALYSIS_AUDIENCE` (default `ai-analysis-api`), `sub` and `client_id` equal to that dedicated client ID, `identity_type=service`, `token_type=service`, `service_role=RUNTIME_GATEWAY_ANALYSIS`, and `scope=[analysis.evaluate]`. Neither service client can impersonate users or agents. Outside local/test both client secrets are required; keep them in a secret manager. Do not reuse one client secret across the separate permission sets. Agent tokens use `AGENT_TOKEN_AUDIENCE` (default `agentshield-runtime-api`), while the existing service audiences default to `agentshield-agent-management-api` and `policy-engine-api`.

Configure `RUNTIME_GATEWAY_ANALYSIS_CLIENT_ID`, `RUNTIME_GATEWAY_ANALYSIS_CLIENT_SECRET`, and `AI_ANALYSIS_AUDIENCE` alongside the existing OAuth variables. The analysis client is validated on startup for Client Credentials only, Basic client authentication, exactly the `analysis.evaluate` scope, the configured secret hash, and a two-minute access-token lifetime. The existing Runtime Gateway registration and its audiences/scopes are unchanged.

Refresh-token rotation/revocation, OAuth consent UX, organization discovery/selection APIs, and a KMS/HSM signing integration remain follow-up work. Agent credential issuance requires Agent Management to be reachable; service-token operation additionally requires matching client ID, secret, issuer, JWKS, and audience configuration in the consuming services. These contracts are covered by service tests but have not been demonstrated with all services running together. JWT validation in this service checks current membership state against its database; downstream services must implement equivalent tenant-aware authorization or use a trusted validation/introspection path. The client must obtain its organization selection through a future membership-aware UI/API; it must not treat the URL parameter as authorization proof.

By default the service listens on port `8080`. The health endpoint is available without authentication at:

```text
http://localhost:8080/actuator/health
```

Organization, user, and membership management endpoints are unauthenticated only in local/test profiles. In all other profiles they remain denied until their authorization model is implemented. Do not expose local/test profiles to an untrusted network.
