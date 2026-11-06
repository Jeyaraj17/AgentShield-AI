# AgentShield Audit Service

An independently runnable Java 21 / Spring Boot 4.1.2 service that consumes shared AgentShield events and stores immutable, organization-scoped audit records.

## Build

Build and install `backend/shared-event-infrastructure` first (`mvn clean install` there), because the monorepo currently has separate Maven projects and no root reactor. Then run `mvn clean verify` in this directory. Tests use H2 and do not require a running RabbitMQ broker.

## Local configuration

Create a dedicated MySQL database named `audit`. Supply credentials through your environment or IDE run configuration; this project contains no credentials.

```powershell
$env:AUDIT_DB_URL = "jdbc:mysql://localhost:3306/audit?connectionTimeZone=UTC"
$env:AUDIT_DB_USERNAME = "<local database user>"
$env:AUDIT_DB_PASSWORD = "<local database password>"
$env:IDENTITY_ISSUER = "http://localhost:8080"
$env:IDENTITY_JWKS_URI = "http://localhost:8080/oauth2/jwks"
$env:AUDIT_SERVICE_AUDIENCE = "agentshield-api,audit-service-api"
$env:AUDIT_CORS_ALLOWED_ORIGINS = "http://localhost:3000"
$env:RABBITMQ_ADDRESSES = "localhost:5672"
$env:RABBITMQ_USERNAME = "<broker user>"
$env:RABBITMQ_PASSWORD = "<broker password>"
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

RabbitMQ settings are `RABBITMQ_ADDRESSES`, `RABBITMQ_USERNAME`, `RABBITMQ_PASSWORD`, and optional `RABBITMQ_VIRTUAL_HOST`. The consumer queue defaults to `agentshield.audit-service.events`; override with `EVENT_QUEUE` and `EVENT_DLQ`. `EVENT_CONSUMER_ENABLED` controls consumer startup. Rabbit connectivity does not gate service health or database-backed API availability. A broker outage prevents consumption until reconnect; broker durability and publisher outboxes in source services protect events in flight.

Flyway creates the service-owned `audit_events` table and imports the shared library's inbox migration. Hibernate runs in validation mode. Only the health endpoint is public. JWTs are pinned to RS256 and validated against the configured issuer, JWKS, audience, expiry, and verified user/organization claims.

## API

All endpoints require a user access token with a verified `user_id`, matching `sub`, `organization_id`, and `organization_role`.

| Method | Endpoint | Access |
| --- | --- | --- |
| `GET` | `/api/v1/audit/events` | OWNER/ADMIN all organization events; MEMBER operational runtime and threat events only |
| `GET` | `/api/v1/audit/events/{eventId}` | Same policy; events outside tenant or member visibility return 404 |
| `GET` | `/api/v1/audit/summary` | Tenant-scoped summary, subject to member visibility |

Search accepts optional `eventType`, `agentId`, `from`, `to`, `outcome`, `page`, and `size` parameters. Size is capped at 100. The API has no organization selector; the tenant always comes from the validated JWT.

The audit consumer subscribes to agent lifecycle, policy lifecycle, runtime authorization, tool execution, AI threat, and trust score event types. Records contain only safe envelope and allowlisted metadata, never the original message payload or prompt/response text. Audit records have no update/delete API and are stored under a unique event ID. The shared inbox key makes event delivery idempotent.

`X-Correlation-ID` is accepted only as a UUID; otherwise the service generates one, echoes it, and places it in the logging MDC. Event logs include event, organization, type, and correlation IDs only.

## Limitations

Automated tests exercise the shared inbox consumer and H2 persistence without a live RabbitMQ broker. Runtime events currently do not carry the requested resource identifier in the shared contract, so their resource column falls back to the related agent/execution identifier. Actor attribution is limited to the source service or agent identity available in the event contract; it cannot identify the human who initiated agent or policy lifecycle changes.
