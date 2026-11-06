# Shared event infrastructure

Versioned event contracts and Spring AMQP/JDBC outbox-inbox support for AgentShield services. Build and install this independent Maven module before building services that depend on it (`mvn clean install` in this directory); the repository currently has no Maven reactor.

Events contain only typed, bounded metadata. Do not add prompts, credentials, tokens, keys, or arbitrary payload fields. The service Flyway scan discovers this dependency's `V1000` migration and creates each service's own outbox/inbox tables in that service's database.

The outbox row is written in the caller's transaction. A scheduled publisher confirms delivery and retries with bounded exponential delay; exhausted rows are retained as `DEAD` for operations to inspect/replay. Delivery is at least once. Consumers persist event IDs in an inbox and acknowledge duplicates. Listener retries are bounded, then broker dead-letter routing applies.

Configure `RABBITMQ_ADDRESSES`, `RABBITMQ_USERNAME`, `RABBITMQ_PASSWORD`, and optionally `RABBITMQ_VIRTUAL_HOST`. Per-service `EVENT_QUEUE`/`EVENT_DLQ` names default to service-specific names. `EVENT_DISPATCHER_ENABLED` and `EVENT_CONSUMER_ENABLED` control publisher/consumer workers. Configure `agentshield.events.outbox.*` and `agentshield.events.consumer.*` for polling, retry limits and backoff. Broker connectivity is not part of application readiness; pending events remain in the local database while the broker is unavailable.
