#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ENV_FILE="${1:-}"
MYSQL_BACKUP="${2:-}"
RABBIT_BACKUP="${3:-}"
AGE_IDENTITY="${4:-}"
CONFIRM="${5:-}"
PROJECT="${COMPOSE_PROJECT_NAME:-agentshield}"
if [[ "$CONFIRM" != "--confirm-restore" ]]; then
  echo "Usage: $0 ENV_FILE mysql-backup.sql.gz.age rabbitmq-definitions.json.age AGE_IDENTITY_FILE --confirm-restore" >&2
  echo "Restore overwrites data in the selected database and broker; first take a fresh backup." >&2
  exit 2
fi
[[ -f "$ENV_FILE" && -f "$MYSQL_BACKUP" && -f "$RABBIT_BACKUP" && -f "$AGE_IDENTITY" ]] || { echo "Required file is missing." >&2; exit 2; }
command -v age >/dev/null || { echo "Install age before restoring encrypted backups." >&2; exit 2; }
ENV_FILE="$(realpath "$ENV_FILE")"
MYSQL_BACKUP="$(realpath "$MYSQL_BACKUP")"
RABBIT_BACKUP="$(realpath "$RABBIT_BACKUP")"
AGE_IDENTITY="$(realpath "$AGE_IDENTITY")"
env_mode="$(stat -c '%a' "$ENV_FILE")"
[[ "$env_mode" == "600" || "$env_mode" == "400" ]] || { echo "Protect the environment file with chmod 600." >&2; exit 2; }
key_mode="$(stat -c '%a' "$AGE_IDENTITY")"
[[ "$key_mode" == "600" || "$key_mode" == "400" ]] || { echo "Protect the age identity file with chmod 600." >&2; exit 2; }
compose=(docker compose --env-file "$ENV_FILE" -p "$PROJECT" -f "$ROOT/infrastructure/docker/compose.yaml" -f "$ROOT/infrastructure/docker/compose.single-vm.yaml")
"${compose[@]}" stop edge identity-service agent-management-service policy-engine ai-analysis-service runtime-security-gateway audit-service notification-service api-gateway frontend
age -d -i "$AGE_IDENTITY" "$MYSQL_BACKUP" | gzip -dc | "${compose[@]}" exec -T mysql sh -ec 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --user=root'
age -d -i "$AGE_IDENTITY" "$RABBIT_BACKUP" | "${compose[@]}" exec -T rabbitmq sh -ec 'umask 077; cat > /tmp/agentshield-definitions.json'
"${compose[@]}" exec -T rabbitmq rabbitmqctl import_definitions /tmp/agentshield-definitions.json >/dev/null
"${compose[@]}" exec -T rabbitmq rm -f /tmp/agentshield-definitions.json
"${compose[@]}" up -d --no-build
echo "Restore commands completed; independently verify migrations, health, tenant isolation, and event flow before reopening traffic."
