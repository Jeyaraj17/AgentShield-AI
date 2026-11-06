#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ENV_FILE="${1:-}"
PROJECT="${COMPOSE_PROJECT_NAME:-agentshield}"
[[ -n "$ENV_FILE" && -f "$ENV_FILE" ]] || { echo "Usage: $0 /secure/path/agentshield.env" >&2; exit 2; }
ENV_FILE="$(realpath "$ENV_FILE")"
mode="$(stat -c '%a' "$ENV_FILE")"
[[ "$mode" == "600" || "$mode" == "400" ]] || { echo "Protect the environment file with chmod 600." >&2; exit 2; }
compose=(docker compose --env-file "$ENV_FILE" -p "$PROJECT" -f "$ROOT/infrastructure/docker/compose.yaml" -f "$ROOT/infrastructure/docker/compose.single-vm.yaml")
"${compose[@]}" config --quiet
arch="$(docker info --format '{{.Architecture}}')"
[[ "$arch" == "aarch64" || "$arch" == "arm64" ]] || { echo "Run this image build on an ARM64 host or use a separately tested ARM64 build pipeline." >&2; exit 2; }
namespace="$(awk -F= '$1 == "IMAGE_NAMESPACE" { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE")"
tag="$(awk -F= '$1 == "RELEASE_TAG" { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE")"
[[ "$namespace" =~ ^[A-Za-z0-9._/-]+$ && "$tag" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "IMAGE_NAMESPACE or RELEASE_TAG is missing or malformed." >&2; exit 2; }
"${compose[@]}" build --parallel 1 identity-service agent-management-service policy-engine ai-analysis-service runtime-security-gateway audit-service notification-service api-gateway frontend
if [[ "${PUSH_IMAGES:-false}" == "true" ]]; then
  for image in identity-service agent-management-service policy-engine ai-analysis-service runtime-security-gateway audit-service notification-service api-gateway frontend; do
    docker image push "$namespace/$image:$tag"
  done
fi
echo "Sequential ARM64 image build completed. Validate image architecture and scan artifacts before deployment."
