# AgentShield AI single-VM deployment checklist

Use this checklist with [deployment.md](deployment.md). A checked item means evidence has been collected for the selected release; container status alone is not sign-off.

## Provider and host

- [ ] Confirm the account, home region, Ampere A1 Always Free eligibility, service limits, and live capacity in OCI. Set a budget/usage alert and avoid paid shapes/add-ons when the target is ₹0.
- [ ] Confirm the current block-volume allowance can hold the boot volume, Docker layers, seven databases, RabbitMQ, Caddy state, and backup staging. Keep off-host backups separate.
- [ ] Create Ubuntu ARM64 VM; record instance shape, OS image, boot volume and public IP. No VM is provisioned by repository tooling.
- [ ] Configure DNS A/AAAA records for the selected hostname and verify external resolution before starting Caddy.
- [ ] Restrict the OCI NSG/security list and UFW to SSH from an administrative IP, TCP 80/443, and optional UDP 443. Confirm database, broker, backend, dashboard and Actuator ports are not publicly reachable.
- [ ] Enable unattended security updates or a documented patch cadence, SSH key-only access, non-root operator accounts, protected Docker access, and disk/CPU/memory alerts.

## Secrets, TLS and identity

- [ ] Create a protected env file outside the repository with mode 600; no placeholders remain and no secret is in shell history, source control, a build arg, or a report.
- [ ] Use unique generated credentials for MySQL root, seven service database accounts, RabbitMQ administrator, eight app RabbitMQ accounts, and both OAuth confidential clients.
- [ ] Load the signing private key from the secret manager into Identity only. Record key ID, public-key overlap/rotation, and recovery plan; do not claim KMS/HSM signing.
- [ ] Set exact HTTPS issuer, redirect URI `https://<hostname>/auth/callback`, and same-origin CORS. Confirm the SPA client uses Authorization Code + PKCE with S256 and no browser client secret.
- [ ] Keep organization onboarding disabled. Resolve the secure first-OWNER provisioning blocker before exposing a usable production service.
- [ ] Review runtime tool allowlist; no arbitrary URL destination or local mock tool is configured.
- [ ] Keep LLM integration disabled until provider cost, data handling, retention, outbound access, rate/usage budgets, and owner are explicitly approved.

## Image and deployment

- [ ] Build each existing service image for `linux/arm64` on an ARM64 builder and execute the image; record digest, SBOM, vulnerability scan, source revision and release tag.
- [ ] Pin Caddy and application artifacts. Do not use `latest` or mutable tags.
- [ ] Inspect merged Compose config with `config --quiet`; verify only Caddy has public host bindings and all other services use the intended private network.
- [ ] Confirm fresh project-specific volumes are used. Never point at local development data or reuse its signing key.
- [ ] Before an update, verify an age-encrypted MySQL backup and RabbitMQ definitions backup exists and its checksum passes.
- [ ] Start/upgrade only through the documented deployment script; preserve volumes and capture migration/image versions.

## Runtime verification and operations

- [ ] Verify all container health checks and public HTTPS separately. Confirm Flyway history/success for every database-owning service.
- [ ] Complete controlled first-owner bootstrap and test OAuth login, PKCE callback, and one authenticated organization-scoped read.
- [ ] Test tenant A vs tenant B read/write attempts and forged tenant/role headers.
- [ ] Exercise an explicit Policy Engine ALLOW and DENY, default DENY, service token audience separation, fail-closed outage, and confirm denied actions never reach tools.
- [ ] Confirm RabbitMQ outbox delivery, inbox idempotency, retries and DLQ with real application-generated events.
- [ ] Verify audit records, notification behavior, AI advisory behavior, and that AI never authorizes.
- [ ] Configure private log/metrics/alert collection with redaction, retention and access controls. Monitor CPU, memory, swap, disk, DB usage, broker depth, outbox age, certificate expiry, and backup age.
- [ ] Conduct a restore test into a separate project and document recovery time/data loss objectives. Review the rollback compatibility of each Flyway migration.
- [ ] Record unresolved gaps and obtain a release decision. The single-VM profile is a best-effort single-host deployment; it has no HA, WAF, DDoS protection, multi-zone recovery, or production qualification.
