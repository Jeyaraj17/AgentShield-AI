#!/usr/bin/env bash
set -euo pipefail

# Passwords use generated alphanumeric/underscore/hyphen strings so they can be
# safely placed in SQL string literals. Reject unexpected input instead of
# interpolating arbitrary SQL into this first-boot initialization script.
create_service_database() {
  local database="$1" username="$2" password="$3"
  if [[ ! "$password" =~ ^[A-Za-z0-9_-]{20,}$ ]]; then
    echo "A service database password is missing or does not meet the local format requirement." >&2
    exit 1
  fi
  mysql --protocol=socket -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE DATABASE IF NOT EXISTS \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER IF NOT EXISTS '${username}'@'%' IDENTIFIED BY '${password}';
ALTER USER '${username}'@'%' IDENTIFIED BY '${password}';
GRANT ALL PRIVILEGES ON \`${database}\`.* TO '${username}'@'%';
SQL
}

create_service_database agentshield_identity agentshield_identity "${IDENTITY_DB_PASSWORD:?IDENTITY_DB_PASSWORD is required}"
create_service_database agent_management agent_management "${AGENT_DB_PASSWORD:?AGENT_DB_PASSWORD is required}"
create_service_database policy_engine policy_engine "${POLICY_DB_PASSWORD:?POLICY_DB_PASSWORD is required}"
create_service_database ai_analysis ai_analysis "${AI_ANALYSIS_DB_PASSWORD:?AI_ANALYSIS_DB_PASSWORD is required}"
create_service_database runtime_security_gateway runtime_security_gateway "${RUNTIME_DB_PASSWORD:?RUNTIME_DB_PASSWORD is required}"
create_service_database audit_service audit_service "${AUDIT_DB_PASSWORD:?AUDIT_DB_PASSWORD is required}"
create_service_database notification_service notification_service "${NOTIFICATION_DB_PASSWORD:?NOTIFICATION_DB_PASSWORD is required}"
