#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ENV_FILE="${1:-}"
PROJECT="${COMPOSE_PROJECT_NAME:-agentshield}"
if [[ -z "$ENV_FILE" ]]; then
  echo "Usage: $0 /secure/path/agentshield.env [compose arguments...]" >&2
  exit 2
fi
shift
[[ -f "$ENV_FILE" ]] || { echo "Environment file not found." >&2; exit 2; }
ENV_FILE="$(realpath "$ENV_FILE")"

docker compose --env-file "$ENV_FILE" -p "$PROJECT" \
  -f "$ROOT/infrastructure/docker/compose.yaml" \
  -f "$ROOT/infrastructure/docker/compose.single-vm.yaml" "$@"
