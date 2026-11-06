# Backup and recovery

## Scope

The single-VM profile stores MySQL, RabbitMQ and Caddy state in Docker named volumes. A Docker volume on one VM is persistent across container replacement, but it is not an independent backup. This guide never removes volumes and does not use `docker compose down -v`.

The repository backup script exports all MySQL schemas and RabbitMQ definitions, then encrypts each artifact with [age](https://age-encryption.org/) using a recipient public key. It does not back up every RabbitMQ message as a portable dump; the broker's persistent volume and the application transactional outboxes remain important for recovery. Take OCI volume snapshots and off-host encrypted copies under separately protected retention rules.

## Create encrypted backups

1. Install `age` on the administration host and generate an age identity offline or in an approved secret manager. Keep the private identity off the VM; put only its `age1...` recipient public key in the protected environment file as `BACKUP_AGE_RECIPIENT`.
2. Ensure all service containers are healthy, the destination has adequate free space, and `/var/backups/agentshield` is on protected storage. The script sets restrictive file permissions and encrypts the database dump and broker definitions before writing them.
3. Run:

```sh
infrastructure/docker/scripts/backup-single-vm.sh /etc/agentshield/agentshield.env
```

4. Copy encrypted files and checksum manifest to a separate protected backup location. Verify:

```sh
cd /var/backups/agentshield
sha256sum -c SHA256SUMS-<UTC-stamp>
```

Do not archive or send unencrypted dump output. Do not put an age private identity in the repository or on the same VM as the only encrypted backup.

## Restore

Restore is destructive to the chosen deployment's current databases and RabbitMQ definitions. First test a restore under a distinct Compose project name and separate volumes; do not test recovery against the only live dataset.

1. Verify encrypted file checksums and identify the matching age identity from the approved offline/secret-manager recovery process.
2. Ensure database and broker capacity. Stop writes (the script stops application containers), then run with explicit confirmation:

```sh
infrastructure/docker/scripts/restore-single-vm.sh \
  /etc/agentshield/agentshield.env \
  /secure/backup/mysql-<stamp>.sql.gz.age \
  /secure/backup/rabbitmq-<stamp>.json.age \
  /secure/recovery/agentshield-backup-identity.txt \
  --confirm-restore
```

3. Verify MySQL databases, Flyway versions, RabbitMQ users/vhost/exchanges/queues/bindings, service health, tenant isolation, OAuth signing key compatibility, outbox backlog and audit records. Use an isolated environment until checks pass.
4. Reopen traffic only after the deployment owner approves the recovery evidence. Preserve pre-restore data and incident records.

## Recovery and rollback notes

- Snapshot the VM/block volume before high-risk updates, while also maintaining encrypted logical MySQL and broker-definition backups. Snapshots and exports have independent failure modes.
- Do not restore data into a different deployment or tenant context. Keep the project name and protected environment mapping recorded without recording secret values.
- The MySQL export includes system tables because it uses `--all-databases`; restoring restores database users/grants as well as schemas. Keep it encrypted and access-restricted.
- Flyway migrations are not reversed by selecting an old image. Roll back only where the previous application version supports the current schema. Otherwise perform a reviewed forward fix or restore a complete, consistent backup into an isolated recovery environment.
- RabbitMQ definitions contain security-sensitive user hashes and permissions; the script encrypts the export. The broker data volume contains messages and must be protected and snapshotted through an appropriate broker-consistent procedure.
- Periodically perform and document a full restore drill, including measured recovery time, recovered event consistency, and point-in-time/data-loss boundary.
