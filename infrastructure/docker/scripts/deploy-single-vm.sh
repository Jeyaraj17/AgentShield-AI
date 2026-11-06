#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ENV_FILE="${1:-}"
PROJECT="${COMPOSE_PROJECT_NAME:-agentshield}"
[[ -n "$ENV_FILE" && -f "$ENV_FILE" ]] || { echo "Usage: $0 /secure/path/agentshield.env" >&2; exit 2; }
ENV_FILE="$(realpath "$ENV_FILE")"
mode="$(stat -c '%a' "$ENV_FILE")"
[[ "$mode" == "600" || "$mode" == "400" ]] || { echo "Protect the environment file with chmod 600 before deployment." >&2; exit 2; }
if grep -q 'replace_with_' "$ENV_FILE"; then
  echo "Deployment environment still contains placeholders; no values were displayed." >&2
  exit 2
fi

for key in CADDY_IMAGE MYSQL_IMAGE RABBITMQ_IMAGE TLS_INIT_IMAGE RABBITMQ_PROVISION_IMAGE; do
  image="$(awk -F= -v name="$key" '$1 == name { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE")"
  [[ "$image" =~ @sha256:[0-9a-fA-F]{64}$ ]] || { echo "$key must be pinned by a sha256 digest." >&2; exit 2; }
done

domain="$(awk -F= '$1 == "PUBLIC_DOMAIN" { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE")"
[[ "$domain" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "PUBLIC_DOMAIN must be a hostname without a scheme or path." >&2; exit 2; }
destinations="$(awk -F= '$1 == "RUNTIME_TOOL_DESTINATIONS" { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE")"
[[ "$destinations" == *https://* && "$destinations" != *localhost* && "$destinations" != *mock-protected-tool* ]] || { echo "RUNTIME_TOOL_DESTINATIONS must contain approved external HTTPS destinations only." >&2; exit 2; }
compose=(docker compose --env-file "$ENV_FILE" -p "$PROJECT" -f "$ROOT/infrastructure/docker/compose.yaml" -f "$ROOT/infrastructure/docker/compose.single-vm.yaml")
"${compose[@]}" config --quiet

if [[ -n "$("${compose[@]}" ps -q mysql 2>/dev/null || true)" ]]; then
  "$ROOT/infrastructure/docker/scripts/backup-single-vm.sh" "$ENV_FILE"
fi

if [[ "${BUILD_IMAGES_ON_HOST:-false}" == "true" ]]; then
  "${compose[@]}" build --parallel 1 identity-service agent-management-service policy-engine ai-analysis-service runtime-security-gateway audit-service notification-service api-gateway frontend
else
  "${compose[@]}" pull mysql rabbitmq tls-init rabbitmq-provision edge identity-service agent-management-service policy-engine ai-analysis-service runtime-security-gateway audit-service notification-service api-gateway frontend
fi
"${compose[@]}" up -d --no-build

services=(mysql rabbitmq identity-service agent-management-service policy-engine ai-analysis-service runtime-security-gateway audit-service notification-service api-gateway frontend edge)
for _ in $(seq 1 180); do
  all_healthy=true
  for service in "${services[@]}"; do
    id="$("${compose[@]}" ps -q "$service")"
    if [[ -z "$id" ]] || [[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id")" != "healthy" ]]; then
      all_healthy=false
      break
    fi
  done
  if [[ "$all_healthy" == true ]]; then
    for _ in $(seq 1 60); do
      if curl --fail --silent --max-time 20 "https://$domain/" -o /dev/null; then
        echo "All configured containers report healthy and the public HTTPS frontend answered successfully. Review migration logs and authenticated smoke tests separately."
        exit 0
      fi
      sleep 5
    done
    echo "Public HTTPS did not become reachable after service health checks." >&2
    "${compose[@]}" ps
    exit 1
  fi
  sleep 5
done
"${compose[@]}" ps
echo "Timed out waiting for service health; inspect redacted application logs before retrying." >&2
exit 1
