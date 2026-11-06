# AgentShield Notification Service

Tenant-scoped in-app security notifications built with Java 21 and Spring Boot 4.1.2.

## Local configuration

The service requires a dedicated MySQL database and consumes the shared `agentshield.events` exchange. Set `NOTIFICATION_DB_URL`, `NOTIFICATION_DB_USERNAME`, and `NOTIFICATION_DB_PASSWORD`; `IDENTITY_ISSUER`, `IDENTITY_JWKS_URI`, and `NOTIFICATION_SERVICE_AUDIENCE`; and exact `NOTIFICATION_CORS_ALLOWED_ORIGINS` for browser traffic. Configure RabbitMQ with `RABBITMQ_ADDRESSES`, `RABBITMQ_USERNAME`, `RABBITMQ_PASSWORD`, and optionally `RABBITMQ_VIRTUAL_HOST`. Consumer queue/DLQ, bounded retry count, and backoff can be set with `NOTIFICATION_EVENT_QUEUE`, `NOTIFICATION_EVENT_DLQ`, `EVENT_CONSUMER_MAX_ATTEMPTS`, `EVENT_CONSUMER_INITIAL_BACKOFF_MS`, and `EVENT_CONSUMER_MAX_BACKOFF_MS`.

Never put credentials in source control. Flyway creates the notification schema and shared inbox; Hibernate validates it. Automated tests use H2 and disable Rabbit consumption. Start locally with `mvn spring-boot:run` after exporting the required environment variables.

## API

- `GET /api/v1/notifications` — paged tenant-scoped results; supports `category`, `severity`, `unread`, `from`, `to`, `page`, and `size`.
- `GET /api/v1/notifications/{notificationId}` — tenant-scoped detail.
- `PATCH /api/v1/notifications/{notificationId}/read` and `PATCH /api/v1/notifications/read-all` — owner/admin read-state updates.

Only active user identity tokens with OWNER or ADMIN role are admitted by the service. Event IDs are unique and the shared inbox makes event consumption idempotent. Failed processing is retried with bounded backoff and then dead-lettered. Notifications contain safe summaries and identifiers only; prompt content, tokens, credentials, and raw secret values are not copied.
