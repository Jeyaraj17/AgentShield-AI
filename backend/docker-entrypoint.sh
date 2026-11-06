#!/bin/sh
set -eu

set -- java -XX:MaxRAMPercentage=75.0 "$@"
if [ -f /run/agentshield/identity-truststore.p12 ]; then
  : "${DEV_TLS_TRUSTSTORE_PASSWORD:?Development truststore password is required}"
  set -- "$@" \
    -Djavax.net.ssl.trustStore=/run/agentshield/identity-truststore.p12 \
    -Djavax.net.ssl.trustStoreType=PKCS12 \
    "-Djavax.net.ssl.trustStorePassword=${DEV_TLS_TRUSTSTORE_PASSWORD}"
fi
exec "$@" -jar /app/service.jar
