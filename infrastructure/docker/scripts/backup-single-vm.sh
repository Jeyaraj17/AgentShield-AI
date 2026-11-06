#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ENV_FILE="${1:-}"
BACKUP_DIR="${2:-/var/backups/agentshield}"
AGE_RECIPIENT="${3:-}"
PROJECT="${COMPOSE_PROJECT_NAME:-agentshield}"
[[ -n "$ENV_FILE" && -f "$ENV_FILE" ]] || { echo "Pass the protected environment file." >&2; exit 2; }
ENV_FILE="$(realpath "$ENV_FILE")"
mode="$(stat -c '%a' "$ENV_FILE")"
[[ "$mode" == "600" || "$mode" == "400" ]] || { echo "Protect the environment file with chmod 600." >&2; exit 2; }
if [[ -z "$AGE_RECIPIENT" ]]; then
  AGE_RECIPIENT="$(awk -F= '$1 == "BACKUP_AGE_RECIPIENT" { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE")"
fi
command -v age >/dev/null || { echo "Install age before creating encrypted backups." >&2; exit 2; }
[[ "$AGE_RECIPIENT" =~ ^age1[0-9a-z]+$ ]] || { echo "BACKUP_AGE_RECIPIENT is missing or malformed." >&2; exit 2; }
umask 077
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
compose=(docker compose --env-file "$ENV_FILE" -p "$PROJECT" -f "$ROOT/infrastructure/docker/compose.yaml" -f "$ROOT/infrastructure/docker/compose.single-vm.yaml")
mysql_final="$BACKUP_DIR/mysql-$stamp.sql.gz.age"
rabbit_final="$BACKUP_DIR/rabbitmq-$stamp.json.age"
manifest_final="$BACKUP_DIR/SHA256SUMS-$stamp"
mysql_tmp="$BACKUP_DIR/.mysql-$stamp.sql.gz.age.tmp"
rabbit_tmp="$BACKUP_DIR/.rabbitmq-$stamp.json.age.tmp"
manifest_tmp="$BACKUP_DIR/.SHA256SUMS-$stamp.tmp"
[[ ! -e "$mysql_final" && ! -e "$rabbit_final" && ! -e "$manifest_final" \
   && ! -e "$mysql_tmp" && ! -e "$rabbit_tmp" && ! -e "$manifest_tmp" ]] || {
  echo "A backup with this UTC timestamp already exists; retry after the next second." >&2
  exit 1
}
completed=false
cleanup() {
  rm -f "$mysql_tmp" "$rabbit_tmp" "$manifest_tmp"
  if [[ "$completed" != true ]]; then
    rm -f "$mysql_final" "$rabbit_final" "$manifest_final"
  fi
}
trap cleanup EXIT

"${compose[@]}" exec -T mysql sh -ec 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysqldump --user=root --all-databases --single-transaction --routines --events --triggers --hex-blob' \
  | gzip -9 | age -r "$AGE_RECIPIENT" -o "$mysql_tmp"
"${compose[@]}" exec -T rabbitmq sh -ec 'umask 077; file="$(mktemp /tmp/agentshield-definitions.XXXXXX)"; trap '\''rm -f "$file"'\'' EXIT; rabbitmqctl export_definitions "$file" >/dev/null; cat "$file"' \
  | age -r "$AGE_RECIPIENT" -o "$rabbit_tmp"
test -s "$mysql_tmp"
test -s "$rabbit_tmp"
mv "$mysql_tmp" "$mysql_final"
mv "$rabbit_tmp" "$rabbit_final"
(
  cd "$BACKUP_DIR"
  sha256sum "$(basename "$mysql_final")" "$(basename "$rabbit_final")" > "$(basename "$manifest_tmp")"
)
mv "$manifest_tmp" "$manifest_final"
chmod 600 "$mysql_final" "$rabbit_final" "$manifest_final"
completed=true
echo "Database and RabbitMQ definition backups completed: $stamp"
