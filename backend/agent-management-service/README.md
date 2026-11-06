# Agent Management Service

Agent Management Service registers and manages AI agents for AgentShield AI organizations. It is an independently runnable Java 21 / Spring Boot 4.1.2 microservice with its own database schema and Flyway migration.

## Build and test

```shell
mvn clean verify
```

Tests use H2 and do not require MySQL or a running Identity Service. The production and local profiles use Hibernate schema validation; Flyway owns schema creation.

## Local setup

Create a dedicated MySQL database named `agent_management`. Set its username and password in the environment or IDE run configuration. No database credentials are supplied in this repository.

PowerShell example:

```powershell
$env:AGENT_DB_URL = "jdbc:mysql://localhost:3306/agent_management?connectionTimeZone=UTC"
$env:AGENT_DB_USERNAME = "<your local database user>"
$env:AGENT_DB_PASSWORD = "<your local database password>"
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

The local profile uses `http://localhost:8080` for Identity Service and its `/oauth2/jwks` endpoint. The Agent Management Service listens on port `8082` by default (`SERVER_PORT` can override it). Local development still requires a real Identity Service JWT; there is no development authentication bypass.

## Configuration

| Environment variable | Purpose |
| --- | --- |
| `AGENT_DB_URL` | JDBC URL for the dedicated Agent Management database |
| `AGENT_DB_USERNAME` | Database account name |
| `AGENT_DB_PASSWORD` | Database account password |
| `IDENTITY_ISSUER` | Exact JWT issuer configured by Identity Service |
| `IDENTITY_JWKS_URI` | Identity Service public JWKS URL, typically `/oauth2/jwks` |
| `AGENT_MANAGEMENT_AUDIENCE` | Audience expected in AgentShield access tokens |
| `AGENT_CORS_ALLOWED_ORIGINS` | Comma-separated exact HTTPS frontend origins; wildcards and credentials are not allowed |
| `SERVER_PORT` | Optional service port; defaults to `8082` |

Non-local deployments must use HTTPS issuer and JWKS URLs and configure exact frontend origins. The service pins JWT signatures to RS256 and validates the configured issuer, audience, and token timestamps. AgentShield access tokens must contain matching `sub` and `user_id`, a UUID `organization_id`, and `organization_role` set to `OWNER`, `ADMIN`, or `MEMBER`.

Flyway applies `src/main/resources/db/migration/V1__create_agents.sql`. Hibernate uses `ddl-auto=validate` and will fail startup if the database does not match the migration. Application logging defaults to INFO, Spring Security logging to WARN, and only the Actuator health endpoint is exposed.

## API

Every API request requires `Authorization: Bearer <access-token>`. The service derives the user, organization, and role from the verified JWT. Request bodies cannot set an organization or role. All reads and writes use the authenticated organization ID in their repository queries. A guessed agent UUID from another tenant returns `404`.

| Method | Endpoint | Permission | Behavior |
| --- | --- | --- | --- |
| `POST` | `/api/v1/agents` | OWNER or ADMIN | Register an ACTIVE agent |
| `GET` | `/api/v1/agents?page=0&size=20` | Any organization role | List agents for the current organization |
| `GET` | `/api/v1/agents/{agentId}` | Any organization role | Read an agent in the current organization |
| `PUT` | `/api/v1/agents/{agentId}` | OWNER or ADMIN | Replace agent details |
| `PATCH` | `/api/v1/agents/{agentId}/status` | OWNER or ADMIN | Set ACTIVE, INACTIVE, or SUSPENDED status |
| `DELETE` | `/api/v1/agents/{agentId}` | OWNER or ADMIN | Soft-deactivate as INACTIVE; history remains stored |

The create/update request fields are `name`, `agentCode`, optional `description`, `agentType`, and optional `capabilities` (a JSON array of capability strings). Agent codes are normalized to uppercase and unique within an organization. Listings return `content`, `page`, `size`, `totalElements`, and `totalPages`; page size is limited to 100.

Example:

```json
{
  "name": "Support Assistant",
  "agentCode": "SUPPORT-ASSISTANT",
  "description": "Handles support workflows",
  "agentType": "ASSISTANT",
  "capabilities": ["search", "ticket_summary"]
}
```

The health endpoint is `GET /actuator/health`. No RabbitMQ event publishing is included in this phase.

## Data ownership and limitations

The service owns only its `agents` table. `organization_id` is indexed and participates in the unique organization/code constraint; there is no cross-service foreign key to the Identity Service database. Identity token signing keys are fetched through JWKS and are not stored here. The service validates signed tenant claims but does not perform a live membership lookup; changes to user or membership status are reflected when Identity Service stops issuing valid tokens, and downstream authorization/revocation policy must account for already-issued token lifetimes.
