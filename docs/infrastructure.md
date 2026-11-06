# Local infrastructure and Docker Compose

This guide describes the local development stack in `infrastructure/docker/compose.yaml`. It uses MySQL 8.4, RabbitMQ 4.1, eight Spring Boot services, an API Gateway, and the React dashboard. Local credentials and TLS material must not be reused in shared or production environments.

## Prerequisites

- Docker Desktop with its **Linux Engine** running and Compose v2 available.
- At least 8 GB of memory available to Docker for building/running all services.
- OpenSSL for generating local credentials and the Identity signing key.
- Java 21/Maven for running backend tests outside containers; Node.js 22/npm for local frontend development.

## Prepare local environment

From the repository root, copy `.env.example` to `.env`. Replace every `replace_with_...` value with a unique local value. The Compose file requires the MySQL root password, seven distinct database passwords, RabbitMQ credentials, two separate Runtime Gateway OAuth client secrets, signing keys, and two development TLS store passwords. Compose fails configuration if required variables are absent.

Generate database, RabbitMQ, OAuth client, and TLS store passwords from high-entropy random values. MySQL service passwords in this local script are restricted to letters, digits, `_`, and `-`; hexadecimal output works, for example:

```sh
openssl rand -hex 32
```

Create the local RS256 key pair. The private key is stored only in the ignored `.env`; do not commit it or paste it into logs or chat:

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /tmp/agentshield-local-private.pem
openssl pkey -in /tmp/agentshield-local-private.pem -outform DER | openssl base64 -A
openssl pkey -in /tmp/agentshield-local-private.pem -pubout -outform DER | openssl base64 -A
```

Put the first Base64 output in `AUTH_SIGNING_PRIVATE_KEY_BASE64` and the second in `AUTH_SIGNING_PUBLIC_KEY_BASE64`. Remove the temporary private key after copying it into `.env`. These values are local development keys and must be replaced for every deployment.

The `tls-init` helper generates development-only HTTPS keypairs for each internal backend and a shared truststore into Docker named volumes. Each backend receives only its own private-key volume; consumers receive the public-certificate truststore. This is not a production certificate authority. The token `iss` remains the public local Gateway URL (`http://localhost:8080`); the private JWKS/token network URL is `https://identity-service:8443`.

For the browser registration use:

- `PUBLIC_GATEWAY_URL=http://localhost:8080`
- `PUBLIC_AUTH_REDIRECT_URI=http://localhost:3000/auth/callback`
- `AUTH_SPA_CLIENT_ID=agentshield-react-spa`
- CORS origins `http://localhost:3000`

The public client uses Authorization Code + PKCE and has no browser-held secret. The Compose build leaves `VITE_API_BASE_URL` empty, so the frontend uses its own origin and Nginx proxies API/OAuth paths to the Gateway. For local Vite development, copy `frontend/.env.example` to `frontend/.env.local` and retain the same client ID and redirect origin; Vite proxies `/api`, `/oauth2`, `/.well-known`, and `/login` to `AGENTSHIELD_GATEWAY_TARGET` (default `http://localhost:8080`).

The API Gateway rewrites Identity Service `Location` redirects from the internal Compose origin to `PUBLIC_GATEWAY_URL`, so browser redirects do not expose Docker-only service names.

## Start and stop

Validate the Compose model without starting containers:

```sh
docker compose --env-file .env -f infrastructure/docker/compose.yaml config --quiet
```

Build and start the stack:

```sh
docker compose --env-file .env -f infrastructure/docker/compose.yaml up --build -d
```

Inspect status and logs:

```sh
docker compose --env-file .env -f infrastructure/docker/compose.yaml ps
docker compose --env-file .env -f infrastructure/docker/compose.yaml logs -f identity-service api-gateway
```

Stop containers while preserving MySQL/RabbitMQ/TLS data:

```sh
docker compose --env-file .env -f infrastructure/docker/compose.yaml down
```

`down -v` deletes persistent database, RabbitMQ, Identity TLS, and truststore volumes. Use it only when intentionally resetting all local data. The MySQL initialization script runs only against a new data volume; later `.env` password changes do not rotate already-created database users. Apply credential changes to persistent volumes deliberately or reset local data.

## Ports and exposure

| Component | Container port | Host port | Notes |
|---|---:|---:|---|
| React/Nginx | 80 | `127.0.0.1:3000` | Browser UI; same-origin proxy to Gateway |
| API Gateway | 8080 | `127.0.0.1:8080` | Only public application API entry point |
| Identity Service | 8443 HTTPS | not published | Internal TLS; route through Gateway |
| Agent Management | 8082 HTTPS | not published | Internal only; trusted development certificate |
| Policy Engine | 8083 HTTPS | not published | Internal only; trusted development certificate |
| Runtime Security Gateway | 8084 HTTPS | not published | Internal only; trusted development certificate |
| AI Analysis Service | 8085 HTTPS | not published | Internal only; trusted development certificate |
| Audit Service | 8086 HTTPS | not published | Internal only; trusted development certificate |
| Notification Service | 8087 HTTPS | not published | Internal only; trusted development certificate |
| Mock protected tool | 8443 HTTPS | not published | Private local verification target for `mock.echo` only |
| MySQL | 3306 | `127.0.0.1:${MYSQL_HOST_PORT}` (defaults to 3306) | Local developer access only; change `MYSQL_HOST_PORT` if another local MySQL uses 3306 |
| RabbitMQ AMQP | 5672 | `127.0.0.1:5672` | Local developer access only |
| RabbitMQ Management UI | 15672 | `127.0.0.1:15672` | Local developer access only |

Identity and other business services are intentionally not exposed on host ports; OAuth endpoints and JWKS are routed through the Gateway. Backend health checks use Actuator `/actuator/health` inside each container over HTTP for the Gateway and HTTPS for internal services. The public Gateway health URL is `http://localhost:8080/actuator/health`. Nginx's own health check verifies that it serves the frontend; it does not by itself establish API connectivity.

## MySQL and Flyway

The MySQL 8.4 container persists files in `mysql-data`. First initialization creates seven databases and seven distinct users:

| Database | Dedicated account | Owning service |
|---|---|---|
| `agentshield_identity` | `agentshield_identity` | Identity Service |
| `agent_management` | `agent_management` | Agent Management Service |
| `policy_engine` | `policy_engine` | Policy Engine |
| `ai_analysis` | `ai_analysis` | AI Analysis Service |
| `runtime_security_gateway` | `runtime_security_gateway` | Runtime Security Gateway |
| `audit_service` | `audit_service` | Audit Service |
| `notification_service` | `notification_service` | Notification Service |

The initialization script grants each account privileges only on its own database. It does not create a shared application account. Every data-owning application runs its Flyway migrations during startup, then Hibernate validates the schema. Compose forces `ddl-auto=validate`, including Identity's local profile, which otherwise enables schema update. Startup dependencies wait for MySQL health; application health checks wait for web startup and included database health checks. A container being `running` is not considered healthy until its Compose health check succeeds.

To inspect a migration history after startup:

```sh
docker compose --env-file .env -f infrastructure/docker/compose.yaml exec mysql \
  mysql -u agentshield_identity -p agentshield_identity \
  -e 'SELECT version, success FROM flyway_schema_history ORDER BY installed_rank;'
```

Repeat with each service's database and username. Shared event outbox/inbox migrations are packaged by `shared-event-infrastructure` and run in each participating service's own database.

## RabbitMQ and event delivery

RabbitMQ uses a persistent volume and a health check. Services share the durable topic exchange `agentshield.events` and durable direct dead-letter exchange `agentshield.events.dlx`. Each consumer declares its own durable queue, binds it to `agentshield.events` with `#`, and declares a queue-specific dead-letter queue bound through the DLX. All publishers use the same exchange/routing-key convention from the shared event module.

Publishers write to a transactional outbox in the same local database transaction as the business operation. The dispatcher publishes with broker confirms/mandatory returns, retries with bounded exponential delay, and retains terminal failures as `DEAD`; it attempts dead-letter publication when the configured maximum is reached. Consumers persist an inbox event ID and process the event in the same local transaction, so duplicate deliveries do not repeat effects. Listener processing uses bounded attempts/backoff and rejects after exhaustion; RabbitMQ routes rejected deliveries to that consumer's DLQ. No service accesses another service's database.

RabbitMQ management UI is available locally at `http://localhost:15672` using the values from `.env`. Check the six service queues and their `*.dlq` queues there. Rabbit connectivity is required for healthy deployment readiness in this Compose stack, but application outbox rows remain durable if the broker later becomes unavailable.

## Service connectivity and configuration

All internal requests use Compose DNS names over HTTPS. The API Gateway routes to each backend; Runtime Gateway uses the Agent Management, Policy Engine, AI Analysis, and Identity service names. Identity's public issuer is the Gateway URL, while internal signature/JWKS and token requests use Identity's HTTPS service URL. Java containers receive a generated truststore containing each internal backend certificate, while each service mounts only its own private key. No internal backend port is published to the host.

AI LLM analysis is disabled by default. Set an approved provider and `OPENAI_API_KEY` only when testing that external integration. The key is passed only to AI Analysis. Compose registers `mock.echo` to a TLS-enabled mock protected tool on the private Docker network so runtime ALLOW/DENY paths can be verified locally. The mock discards request payloads and records only execution count, correlation ID, and whether an Authorization header was present. It has no published host port and is a local verification helper, not a production tool. Override `RUNTIME_TOOL_DESTINATIONS` with approved registered destinations in other environments; runtime execution stays fail-closed when no destination is configured.

Compose activates the `local` profile to permit local HTTP at the public Gateway and local onboarding. Signing-key generation via an ephemeral key is explicitly disabled and real `.env` signing keys are required. Database schema updates are explicitly overridden to `validate`. Do not deploy this profile to production.

## Troubleshooting

- **Compose cannot connect to Docker:** start Docker Desktop and switch to the Linux Engine, then retry `docker version` and Compose `ps`.
- **Service exits with missing configuration:** replace all placeholders in `.env`; review the service logs without printing credential values.
- **MySQL init fails:** use unique hex passwords of at least 20 characters. If the volume was previously initialized, the init script will not recreate users; inspect grants or intentionally reset local data.
- **Internal HTTPS/JWKS failures:** confirm `tls-init` completed, the service-specific key volumes and shared truststore exist, and `IDENTITY_JWKS_URI` is `https://identity-service:8443/oauth2/jwks`. Changing the two TLS store passwords requires regenerating the local TLS volumes.
- **Runtime Gateway tool-registration failure:** confirm the private `mock-protected-tool` is healthy and `RUNTIME_TOOL_DESTINATIONS` contains a registered `action=https://host:port/path` destination.
- **Flyway/schema validation fails:** inspect the service's startup logs and `flyway_schema_history`; do not change `ddl-auto` to `update` to hide a migration defect.
- **Rabbit publisher backlog or DLQ messages:** inspect the owning service's outbox rows and queue/DLQ in RabbitMQ Management. Verify all services use the same Rabbit credentials and vhost.
- **OAuth redirect/CORS errors:** ensure the configured redirect URI exactly matches `http://localhost:3000/auth/callback` and the allowed origin is `http://localhost:3000` in Identity and Gateway.
- **Frontend shows gateway errors:** first check Gateway health, then `docker compose logs` for the targeted backend. Frontend Nginx being healthy only means its static assets load.

## Verification boundary

The Compose file includes health checks and startup ordering, but these are not substitutes for a live integration run. Verify container health, Flyway history, RabbitMQ queues/outbox delivery, and browser/API behavior on the actual machine. Docker Desktop's Linux Engine must be running to build images or claim live connectivity; Compose model validation alone does not verify services or migrations.
