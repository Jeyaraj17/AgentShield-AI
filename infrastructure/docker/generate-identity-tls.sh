#!/usr/bin/env sh
set -eu

if [ -z "${DEV_TLS_KEYSTORE_PASSWORD:-}" ] || [ -z "${DEV_TLS_TRUSTSTORE_PASSWORD:-}" ]; then
  echo "Development TLS store passwords must be configured in the ignored .env file." >&2
  exit 1
fi

mkdir -p /keys /agent-keys /policy-keys /ai-keys /runtime-keys /audit-keys /notification-keys /mock-keys /trust

ensure_certificate() {
  alias_name="$1"
  common_name="$2"
  dns_name="$3"
  keystore="$4"
  certificate="$5"
  if [ ! -f "$keystore" ]; then
    keytool -genkeypair -noprompt -alias "$alias_name" -keyalg RSA -keysize 3072 \
      -validity 825 -storetype PKCS12 -keystore "$keystore" \
      -storepass "$DEV_TLS_KEYSTORE_PASSWORD" -keypass "$DEV_TLS_KEYSTORE_PASSWORD" \
      -dname "CN=$common_name, OU=AgentShield Local Development" \
      -ext "SAN=dns:$dns_name,dns:localhost,ip:127.0.0.1"
  fi
  if [ ! -f "$certificate" ]; then
    keytool -exportcert -rfc -alias "$alias_name" -keystore "$keystore" \
      -storepass "$DEV_TLS_KEYSTORE_PASSWORD" -file "$certificate"
  fi
}

ensure_certificate agentshield-identity identity-service identity-service \
  /keys/identity.p12 /keys/identity.crt
ensure_certificate agentshield-agent-management agent-management-service agent-management-service \
  /agent-keys/agent-management.p12 /agent-keys/agent-management.crt
ensure_certificate agentshield-policy-engine policy-engine policy-engine \
  /policy-keys/policy-engine.p12 /policy-keys/policy-engine.crt
ensure_certificate agentshield-ai-analysis ai-analysis-service ai-analysis-service \
  /ai-keys/ai-analysis.p12 /ai-keys/ai-analysis.crt
ensure_certificate agentshield-runtime-gateway runtime-security-gateway runtime-security-gateway \
  /runtime-keys/runtime-gateway.p12 /runtime-keys/runtime-gateway.crt
ensure_certificate agentshield-audit-service audit-service audit-service \
  /audit-keys/audit-service.p12 /audit-keys/audit-service.crt
ensure_certificate agentshield-notification-service notification-service notification-service \
  /notification-keys/notification-service.p12 /notification-keys/notification-service.crt
ensure_certificate agentshield-mock-protected-tool mock-protected-tool mock-protected-tool \
  /mock-keys/mock-protected-tool.p12 /mock-keys/mock-protected-tool.crt

if [ ! -f /trust/identity-truststore.p12 ]; then
  keytool -importcert -noprompt -alias agentshield-identity -file /keys/identity.crt \
    -storetype PKCS12 -keystore /trust/identity-truststore.p12 \
    -storepass "$DEV_TLS_TRUSTSTORE_PASSWORD"
fi

import_certificate() {
  alias_name="$1"
  certificate="$2"
  if ! keytool -list -keystore /trust/identity-truststore.p12 \
      -storepass "$DEV_TLS_TRUSTSTORE_PASSWORD" -alias "$alias_name" >/dev/null 2>&1; then
    keytool -importcert -noprompt -alias "$alias_name" -file "$certificate" \
      -storetype PKCS12 -keystore /trust/identity-truststore.p12 \
      -storepass "$DEV_TLS_TRUSTSTORE_PASSWORD"
  fi
}

import_certificate agentshield-identity /keys/identity.crt
import_certificate agentshield-agent-management /agent-keys/agent-management.crt
import_certificate agentshield-policy-engine /policy-keys/policy-engine.crt
import_certificate agentshield-ai-analysis /ai-keys/ai-analysis.crt
import_certificate agentshield-runtime-gateway /runtime-keys/runtime-gateway.crt
import_certificate agentshield-audit-service /audit-keys/audit-service.crt
import_certificate agentshield-notification-service /notification-keys/notification-service.crt
import_certificate agentshield-mock-protected-tool /mock-keys/mock-protected-tool.crt

chmod 0644 /keys/identity.p12 /keys/identity.crt \
  /agent-keys/agent-management.p12 /agent-keys/agent-management.crt \
  /policy-keys/policy-engine.p12 /policy-keys/policy-engine.crt \
  /ai-keys/ai-analysis.p12 /ai-keys/ai-analysis.crt \
  /runtime-keys/runtime-gateway.p12 /runtime-keys/runtime-gateway.crt \
  /audit-keys/audit-service.p12 /audit-keys/audit-service.crt \
  /notification-keys/notification-service.p12 /notification-keys/notification-service.crt \
  /mock-keys/mock-protected-tool.p12 /mock-keys/mock-protected-tool.crt \
  /trust/identity-truststore.p12
