# Deployment preparation and operations

## Status and scope

`infrastructure/docker/compose.yaml` is the local development stack. Do not deploy it by itself. Two separate deployment options now exist:

- `compose.yaml` + `compose.single-vm.yaml`: a constrained single-VM profile with private local MySQL/RabbitMQ containers, per-service database and broker accounts, private networking, Caddy HTTPS, and generated private internal certificates. It is prepared, not deployed or production-qualified.
- `compose.yaml` + `compose.production.yaml`: the existing external-managed-database/broker production overlay. It expects provisioned private data services, managed secrets, trusted certificates, and immutable prebuilt images.

Do not treat either Compose configuration as proof of production readiness. No OCI instance, DNS zone, registry, or production secrets have been provisioned.

The historical local development database contains an audit/runtime-history event created before the Runtime Gateway tenant-mismatch fix. It references an agent UUID belonging to another organization. The event is retained for audit integrity; it is not an authorization input and does not grant access to the referenced agent. Organization-scoped authorization and current runtime writes use the verified token organization and agent identity. The legacy row can appear as an identifier in the original development tenant's history. Do not edit or delete it. Use a newly provisioned, isolated set of production/demo databases for a clean dataset; do not point a deployment at local development databases.

## Architecture overview

The public path is `browser -> Caddy HTTPS edge -> React frontend or API Gateway -> private backend services`. Identity issues signed user and agent tokens. Agent Management owns agent records, Policy Engine makes final deterministic ALLOW/DENY decisions, and Runtime Security Gateway executes only explicitly allowed requests against registered tool destinations. AI Analysis is advisory and cannot grant authorization. Audit and Notification consume shared events. Each persistence-owning service uses a separate database identity and schema; no service should receive another service's database credentials.

Only Caddy publishes host ports. MySQL, RabbitMQ, the API Gateway, frontend, and business services must remain on private deployment networking. The production overlay disables the local MySQL, RabbitMQ, TLS-init, and mock-tool services. Provision their replacements before starting application services.

## Prerequisites

- A deployment host/orchestrator running Docker Engine and Docker Compose v2.24.4 or later (the overlay uses `!override`).
- A public DNS name whose A/AAAA records point to the Caddy host; inbound TCP 80/443 (and UDP 443 if HTTP/3 is desired).
- A private MySQL 8-compatible managed cluster with seven new, isolated databases/schemas and seven distinct least-privilege accounts. Require TLS with certificate and hostname verification. The accounts must not be able to access one another's schemas.
- A private RabbitMQ deployment with TLS, durable storage/HA appropriate to the service, a dedicated vhost, and separate service accounts with publisher/consumer permissions limited to required exchanges and queues.
- A production signing key provisioned from a KMS/HSM or managed secret store, with a documented rotation/overlap procedure. Do not copy the local RSA key into production.
- Trusted internal CA material, an internal PKCS#12 truststore, and a separately issued server keystore for each HTTPS backend. Certificates must include the internal DNS names used by Compose and be renewed before expiry.
- A secure first-organization/first-owner bootstrap procedure. The production overlay intentionally disables public onboarding; this repository does not provision an initial production OWNER automatically. Do not re-enable public onboarding as a shortcut.
- Immutable image tags or digests for all nine deployed images (eight backend applications plus frontend) and a pinned Caddy image. Build and scan images in CI; deploy the same immutable artifacts in each environment.
- Encrypted, access-controlled backups for every database and RabbitMQ definitions/data, plus a tested restore destination.

The Compose bridge network provides private service discovery and no backend host ports are published by the production overlay. Place the host and managed services in a private network/VPC with restrictive firewall rules. Restrict outbound access at the host/network layer to the required managed database/broker, identity integrations, certificate authority, and explicitly approved tool/LLM destinations.

## Production environment

Start from `infrastructure/docker/.env.production.example`. It contains names and placeholders only and is intentionally Git-ignored as a populated deployment file pattern. Copy it to a protected location outside the repository, then inject values from the deployment secret manager. Do not commit the populated file or print it in CI logs. The example also lists local-only Compose interpolation variables: Compose resolves some base-file expressions before applying the production overlay, even though those local services are disabled. Give those values unique random values too; they are not production database/broker credentials.

Set and validate at least:

- `PUBLIC_DOMAIN` and `CADDY_EMAIL`; Identity issuer, browser redirect, and exact CORS origin are derived from the HTTPS domain. Register exactly `https://<domain>/auth/callback` with the SPA client. Keep organization onboarding disabled in production and create tenants through the approved controlled operational process.
- Immutable image references for Identity, Agent Management, Policy Engine, AI Analysis, Runtime Gateway, Audit, Notification, API Gateway, frontend, and Caddy.
- Signing key material and key ID from the key manager. Keep the private key unavailable to operators and containers except the Identity process that signs tokens. Retain previous public keys only for the configured overlap needed to validate outstanding tokens.
- Private TLS-only JDBC URLs, unique database usernames/passwords, and certificate validation for each of the seven schemas.
- Private RabbitMQ TLS endpoint/vhost and unique accounts/passwords for each service. Configure permissions at the broker to match each service's actual publishing or consuming role.
- Internal CA/truststore path and password, plus the separately provisioned server keystore paths/passwords for Identity, Agent Management, Policy Engine, AI Analysis, Runtime Gateway, Audit, and Notification.
- An explicit allowlist of registered production tool destinations. Never configure arbitrary request-selected URLs.
- `AI_LLM_ENABLED=false` and `AI_LLM_PROVIDER=none` unless an approved provider, secret-manager API key, data-processing terms, outbound allowlist, usage limits, and cost owner have been documented. External model calls can incur usage charges and send redacted analysis content to a third party.

Use a dedicated Compose project name for each isolated deployment, for example `agentshield-demo`. Project names isolate Compose-managed resources such as Caddy state; they do **not** create or isolate external database schemas. Provision fresh, separate schemas and accounts for a clean demo or production deployment before startup.

The Compose file-based secret entries are read-only mounts, not a cloud secret manager. On a single Docker host, materialize keystores from the secret manager with restrictive host ACLs that permit only the container's service UID (10001) to read them, and protect the Docker host itself. Prefer the deployment platform's native secret facility when available; keep private signing material accessible only to Identity.

## Validate and deploy

Run the commands from the repository root. Keep the environment file outside the repository in real deployments; the path below is illustrative. `config --quiet` validates merged Compose syntax without dumping interpolated secret values.

```powershell
$envFile = 'C:\secure\agentshield\production.env'
$compose = @('docker','compose','--env-file',$envFile,'-p','agentshield-demo','-f','infrastructure/docker/compose.yaml','-f','infrastructure/docker/compose.production.yaml')
$composeArgs = $compose[1..($compose.Length-1)]
& $compose[0] @composeArgs config --quiet
if ($LASTEXITCODE -ne 0) { throw 'Compose configuration validation failed' }
& $compose[0] @composeArgs pull
if ($LASTEXITCODE -ne 0) { throw 'Image pull failed' }
& $compose[0] @composeArgs up -d --no-build
if ($LASTEXITCODE -ne 0) { throw 'Deployment failed' }
```

The exact image publishing/pull process depends on the chosen registry. Do not use mutable `latest` tags. Flyway migrations run as each application starts; Hibernate must validate rather than alter the schema. Before deploying a release with migrations, take and verify database backups, review migration compatibility, and use a maintenance/rollout plan appropriate to the application's availability requirements.

## Health verification

The only intended public application endpoint is the HTTPS site at `https://<PUBLIC_DOMAIN>/`. Caddy obtains and renews its public certificate. OAuth authorization/token, JWKS and application APIs are routed through the API Gateway. Do not expose Actuator, direct backend ports, MySQL, or RabbitMQ to the public internet.

Check deployment state without dumping environment configuration:

```sh
docker compose --env-file /secure/path/production.env -p agentshield-demo \
  -f infrastructure/docker/compose.yaml -f infrastructure/docker/compose.production.yaml ps
curl --fail --silent --show-error https://PUBLIC_DOMAIN/ -o /dev/null -w '%{http_code}\n'
```

Container health is only a first check. Confirm Flyway migration success in each applicable service log, run authenticated end-to-end smoke tests for onboarding policy (disabled), login/PKCE, organization-scoped APIs, agent authentication, Policy Engine ALLOW/DENY, fail-closed behavior, audit, and notifications. Use synthetic non-sensitive data. Do not put bearer tokens, passwords, signing material, or raw prompts in shell history, logs, or reports. Export Actuator/metrics and application logs only to a private monitoring system with access control, retention, redaction, and alerts; this Compose file does not provision a full metrics/alerting stack.

## Backup and recovery

1. Enable managed point-in-time recovery and encrypted scheduled snapshots for each database. Preserve database boundaries and access controls in the backup service.
2. Back up RabbitMQ definitions (vhosts, users/permissions, exchanges, queues, bindings, policies) and durable broker data using the broker/provider's supported method. Transactional outboxes remain the durable source for critical events awaiting delivery; verify outbox age and backlog in monitoring.
3. Before schema changes or key rotations, capture recoverable snapshots and record the deployed image digests, migration versions, and active/previous signing key IDs (never private key bytes).
4. Periodically restore database snapshots and broker definitions/data into an isolated recovery environment, then verify tenant isolation, event idempotency, and application startup. A backup not restore-tested is not a recovery plan.
5. For recovery, stop or isolate writers as needed, restore each service's own database and broker state, deploy compatible application images, and verify migrations/health before reopening traffic. Never restore one tenant's data into another deployment.

## Rollback

Record the previous immutable image digests and database migration state for every release. If an application image must be rolled back, redeploy the previous compatible image and keep the database schema forward-compatible. Do not assume Flyway migrations can be reversed by swapping the image. If a migration is incompatible, use the reviewed database restore/forward-fix plan and preserve audit data. Roll back only the affected deployment and retain logs for incident review. Never run `docker compose down -v`; never delete persistent external database or broker volumes as a rollback method.

## Operational and release limitations

- This repository configuration has not been qualified against a specific cloud provider, managed MySQL/RabbitMQ offering, KMS, certificate manager, registry, or monitoring product. Validate the provider's TLS/JDBC parameters, network paths, backup semantics, and secret injection before use.
- The example overlay interpolates database/broker credentials, OAuth client secrets, and the active signing key into container environment variables. Supply them only at deploy time from a secret manager, restrict Docker-daemon/host access, and do not use a committed or persistent populated `.env` file. For a stronger production boundary, integrate the platform's native mounted-secret/KMS signing interface before deployment; the current Identity implementation loads RSA key material into process memory and does not sign remotely through a KMS/HSM.
- Compose is suitable for a controlled single-host deployment pattern, not a substitute for a highly available orchestrator, multi-zone failure handling, WAF/DDoS protection, centralized secrets, SIEM, incident response, or disaster-recovery exercises.
- The production overlay is prepared configuration; it has not been demonstrated with production infrastructure and does not itself make the application production-ready.
- The local development data limitation described above is handled by preserving the historical record and provisioning a clean, separate dataset. Do not present that old development history as a verified production audit record.

## OCI Always Free single-VM target

OCI currently documents an Always Free Ampere A1 allowance equivalent to 2 OCPUs and 12 GB RAM, with 1,500 OCPU-hours and 9,000 GB-hours monthly, plus 200 GB total block-volume capacity (boot and data volumes combined) and five total volume backups. Capacity is not guaranteed; Always Free shapes can fail to launch in a region because of host-capacity shortages, and eligibility is determined by the tenancy and home region. OCI also documents reclamation of an Always Free compute instance after a 7-day period when the 95th-percentile CPU and network use, and for A1 memory use, are all below 20%. This makes Always Free a best-effort demo target, not a reliable public-service uptime commitment. Check the current OCI console eligibility, quotas, capacity, storage usage, and billing before provisioning. Do not upgrade or select paid resources if the target must remain ₹0/month. Oracle states an eligible free-tier user may need a payment card during signup; free eligibility does not make every service or a domain free. [OCI Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm), [OCI capacity troubleshooting](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/troubleshooting-out-of-host-capacity.htm).

### Architecture and access boundaries

`infrastructure/docker/compose.single-vm.yaml` layers on the unchanged local Compose definitions. It configures production Spring profiles, disables public organization onboarding, sets the public HTTPS issuer and exact same-origin CORS/PKCE callback, enables MySQL secure transport, provisions unique RabbitMQ application accounts, and limits host-published ports to Caddy TCP 80/443 (UDP 443 is optional HTTP/3). MySQL, RabbitMQ and backend services have no public host ports. MySQL and business services share only an internal Docker network; the browser-facing frontend/API Gateway use an internal edge network; Caddy is the only service on the public edge network. Runtime tool destinations are required explicitly, and the mock tool is excluded from normal startup. AI/LLM calls remain disabled unless explicitly configured.

Public DNS must already resolve the chosen hostname to the VM and inbound firewall rules must allow 80/443. Caddy obtains and renews a publicly trusted certificate; this does not require a paid domain certificate. A free subdomain provider may be usable depending on its current terms and availability, but no provider or hostname is assumed here. A registered domain may cost money. The public TLS issuer and OAuth redirect must remain exactly `https://<hostname>` and `https://<hostname>/auth/callback`.

Internal HTTPS uses generated self-signed service leaf certificates copied into a private truststore. The JVMs trust these explicit service certificates for the matching Docker DNS names. This is a single-host private trust arrangement; it is not a public CA, KMS, HSM, or a general-purpose internal PKI. The existing TLS init script creates certificates once and does not detect or renew expired certificates; expiry monitoring and a tested rotation procedure are required before deployment. MySQL requires encrypted transport, but the driver uses `sslMode=REQUIRED` rather than server identity verification because the Compose MySQL image's generated certificate is not provisioned from a hostname-valid private CA. RabbitMQ remains on the private internal Docker network without TLS in this profile. For stronger production controls, configure MySQL and RabbitMQ TLS with a managed private CA and verify certificates; use the external-infrastructure overlay or implement/qualify these changes before handling sensitive production workloads.

The profile's `rabbitmq-provision` one-shot service creates distinct app credentials, grants each consumer only its event queue/DLQ read permission, and grants shared-exchange publish permission only to the services that write events. The administrator account is never injected into application containers. Broker account permissions remain within one vhost and must be checked when services add new queues/exchanges. The MySQL database initialization script only provisions users on a new data directory; environment changes do not rotate already-created MySQL users.

Only Runtime Gateway joins the additional `approved-tool-egress` bridge because it executes configured external tool destinations. This does not filter traffic by destination. Runtime code checks its registered-tool allowlist, but host/network-level egress restriction or a controlled egress proxy is still required for defense in depth; an OCI NSG egress allowlist is IP/CIDR-based and cannot automatically follow changing third-party hostnames. This profile does not ship an egress proxy.

### ARM64 compatibility and build strategy

The current Dockerfiles use Maven `3.9.9-eclipse-temurin-21`, Temurin `21-jre-jammy`, Node `22-alpine`, and Nginx `1.28-alpine`; the local stack uses MySQL `8.4`, RabbitMQ `4.1-management-alpine`, and the TLS init Temurin Java 21 image. Official image registries publish ARM64 variants for Maven/Temurin, MySQL 8.4, RabbitMQ 4.1, Node 22, and Caddy. This is manifest-level compatibility evidence, not an ARM64 build or full-stack runtime test. The Docker daemon available during this preparation reports `x86_64`; Identity Service and frontend images were built for that local daemon, not ARM64. No ARM64 application image build or end-to-end ARM64 runtime test has been completed. Build and test on an ARM64 host before deployment; see the official [Maven image tags](https://hub.docker.com/_/maven/tags?name=3.9.9-eclipse-temurin-21), [Temurin image tags](https://hub.docker.com/_/eclipse-temurin/tags?name=21-jre-jammy), [MySQL image tags](https://hub.docker.com/_/mysql/tags?name=8.4), [RabbitMQ image tags](https://hub.docker.com/_/rabbitmq/tags?name=4.1-management-alpine), [Node image documentation](https://hub.docker.com/_/node/), [Nginx image documentation](https://hub.docker.com/_/nginx), and [Caddy image documentation](https://hub.docker.com/_/caddy).

On a 2-OCPU VM, build images sequentially and before application containers are running. `scripts/build-single-vm-images.sh` refuses to build unless Docker reports ARM64. Prefer building on a separate ARM64 machine, pushing immutable tags to a registry you control, then running the deployment script with `BUILD_IMAGES_ON_HOST=false`; registry storage/transfer terms may create charges. Never deploy a mutable `latest` tag. Multi-architecture and native dependencies must still be confirmed by the actual image build and smoke tests.

### Resource plan and feasibility

The overlay keeps conservative hard limits close to the existing local stack: each Java service is capped at 768 MiB with `-Xms128m -Xmx384m` (eight Java processes; roughly 6 GiB maximum container allocation), MySQL at 1 GiB with a 256 MiB InnoDB buffer pool, RabbitMQ at 512 MiB, and frontend/Caddy/provisioner at 128/128/64 MiB. Approximate configured container ceilings are 8.0 GiB, before the OS, Docker daemon, filesystem cache, transient TLS/bootstrap work, and monitoring. The remaining RAM is a limited safety margin, not a measured workload profile. The 2-OCPU budget can produce substantial startup, migration, and request latency. Do not run local image builds concurrently with the full stack on this VM. Load-test and observe actual heap, native memory, CPU, disk I/O and storage before relying on this profile; if headroom or latency is inadequate, the smallest practical alternative is a larger paid VM or moving MySQL/RabbitMQ to separately managed services (which may add costs).

## Single-VM setup

Prerequisites: eligible ARM64 Ubuntu VM already provisioned by the operator; Docker Engine and Compose v2.24.4+; a DNS hostname pointing to the VM; ports 80/443 allowed; `age` installed for encrypted backups; access to a secret manager; pinned Caddy/image references; and a reviewed tool destination allowlist. OCI provisioning and DNS registration are intentionally manual.

### Manual OCI and Ubuntu actions

In the OCI Console, select the tenancy's home region; verify the VM.Standard.A1.Flex shape and Always Free label/quota; inspect current host capacity; create an Ubuntu ARM64 boot volume within the current block-volume allowance; create/select a VCN with an Internet Gateway and public-subnet route; create an NSG permitting only TCP 22 from your management CIDR, TCP 80/443 from the internet, and optional UDP 443; launch the VM with an ephemeral public IPv4 only after reviewing the displayed cost/eligibility; and note its public IP. Create DNS A/AAAA records with a DNS provider you chose, then check the selected free-subdomain terms and renewal conditions. Do not open app, SSH, database or broker ports to the internet. The free-tier console availability label is authoritative for that tenancy; no provider resource is allocated by this repository.

On the provisioned Ubuntu VM, apply updates and install host tools (Docker Engine/Compose should be installed using Docker's current official Ubuntu instructions for the ARM64 architecture):

```sh
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y age curl ca-certificates ufw
sudo systemctl enable --now docker
docker version
docker compose version
```

Configure the host firewall using your real management CIDR before enabling it (these are sample commands; do not replace the CIDR with `0.0.0.0/0`):

```sh
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from <ADMIN_CIDR> to any port 22 proto tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp
sudo ufw enable
sudo ufw status verbose
```

Also configure OCI NSG/security-list rules; UFW alone does not protect a misconfigured cloud ingress rule and vice versa. Confirm an SSH session remains available before closing the setup connection. Docker group membership is root-equivalent; grant it only to trusted operators.

1. Secure the host: use SSH keys only, disable password/root SSH login, patch Ubuntu, allow inbound SSH only from a trusted management address plus TCP 80/443 (optional UDP 443), deny public ports 3000/3306/5672/8080/8443/15672/8082-8087, and use OCI Security Lists/NSGs plus host firewall. Do not put Docker's socket on a public interface. Keep Docker volumes on protected persistent storage and monitor disk space.
2. Copy `infrastructure/docker/single-vm.env.example` to a root-owned location outside Git, e.g. `/etc/agentshield/agentshield.env`, and set mode `600`. Replace every placeholder with unique generated passwords, OAuth client secrets, a production RSA signing key injected from the secret manager, and the public hostname. The example contains no actual credentials. Set a release tag containing the source commit, and configure the registry to reject tag overwrites; Docker tags alone are mutable. Set a registry namespace, and pinned ARM64 image digests for MySQL, RabbitMQ, TLS init, RabbitMQ provisioner, and Caddy. Do not copy the repository's local `.env` or local signing key into this deployment.
3. Generate a dedicated RSA key pair with a supported secure process and store private DER/Base64 material in the secret manager. Inject it only for Identity. Restrict keystore/truststore volume access and Docker-host access. This Identity implementation reads the signing key into process memory; no remote KMS signing integration is provided.
4. Set `RUNTIME_TOOL_DESTINATIONS` to approved, fixed HTTPS tool IDs/URLs. Leave `AI_LLM_ENABLED=false`, `AI_LLM_PROVIDER=none`, and `OPENAI_API_KEY` empty until a provider, data handling review, outbound firewall allowlist, budget/usage limit, and cost owner are approved. Any external model call may create charges and send redacted analysis text to that provider.
5. Resolve the **first OWNER bootstrap blocker before opening the site**. The overlay sets both Identity onboarding and Gateway organization onboarding to false. This repository has no authenticated, production-safe first-OWNER recovery/bootstrap operation. Do not enable public onboarding or create a fake user. Implement an audited, one-time operator-controlled bootstrap path or have the product owner approve an equivalent secure operational procedure before public sign-in is enabled.
6. Build ARM64 images on an ARM64 builder or load immutable ARM64 images into the selected registry. Set `IMAGE_NAMESPACE`, `RELEASE_TAG` and all secrets in the protected environment file. The profile includes the existing app builds, so build-only tooling and dependency image pulls remain necessary.
7. Validate and deploy. Run from the repository root (replace the example path):

```sh
chmod 600 /etc/agentshield/agentshield.env
chmod +x infrastructure/docker/scripts/*.sh
docker compose --env-file /etc/agentshield/agentshield.env -p agentshield \
  -f infrastructure/docker/compose.yaml -f infrastructure/docker/compose.single-vm.yaml config --quiet
infrastructure/docker/scripts/deploy-single-vm.sh /etc/agentshield/agentshield.env
```

For an initial on-host build only, set `BUILD_IMAGES_ON_HOST=true` in the shell before the script; it serializes builds and requires an ARM64 Docker host. Subsequent updates should pull already-built immutable images. The deployment script validates environment-file permissions/placeholders/config, backs up an existing stack before an update, and waits for container health plus public HTTPS. Health is not proof of migrations, authorization or end-to-end correctness.

8. Verify each service migration, authenticate with the approved production owner, run a minimal tenant-scoped runtime ALLOW and DENY smoke test, prove DENY does not execute tools, inspect audit and notification records, and verify fail-closed behavior. Do not expose Actuator directly. Do not enable external LLM tests as part of an unpaid deployment.

## Update, backup, recovery and rollback

- Before each application update, run `infrastructure/docker/scripts/backup-single-vm.sh /etc/agentshield/agentshield.env`. It dumps MySQL and RabbitMQ definitions and age-encrypts both outputs using `BACKUP_AGE_RECIPIENT`; keep the age private identity off the VM and outside the repository. Encrypted exports do not replace tested OCI boot/block-volume snapshots or off-host backups. OCI currently documents five total volume backups in its free allowance; keep storage and retention within current quotas. Longer retention or off-site copies may require paid storage.
- For restore, stop writes and verify backup checksums, then run `infrastructure/docker/scripts/restore-single-vm.sh ENV MYSQL_BACKUP.sql.gz.age RABBITMQ_DEFINITIONS.json.age AGE_IDENTITY_FILE --confirm-restore`. It stops application services, restores all MySQL schemas and RabbitMQ definitions, and starts the stack. Practice only in an isolated recovery deployment first; restoration overwrites the selected deployment's data. Never run `docker compose down -v`.
- For an application rollback, restore the prior immutable `RELEASE_TAG`/Compose environment and deploy the previous image set only if the schema remains backward-compatible. The script backs up but does not reverse Flyway migrations. If rollback is not migration-compatible, follow the tested restore/forward-fix plan. Keep prior signing public keys published for token overlap and use the Identity key-rotation procedure; never restore a stale signing private key without explicit incident review.
- Preserve named volumes. Do not use volume deletion as a rollback method.

The first-time MySQL root/account setup occurs only when its named data directory is empty. To rotate existing MySQL passwords, perform a reviewed `ALTER USER` operation and update the protected secret material in a controlled maintenance window; editing the env file alone does not rotate database accounts. RabbitMQ service passwords are reconciled by the provisioning job when its environment changes; protect the admin account and rotate it through RabbitMQ's supported administrative workflow.

See [deployment checklist](deployment-checklist.md) and [backup and recovery guide](backup-and-recovery.md) before opening any public listener.
