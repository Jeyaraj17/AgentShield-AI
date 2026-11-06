# Shared build recipe for all Java 21 services. Compose sets SERVICE_MODULE.
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace
ARG SERVICE_MODULE
COPY backend/shared-event-infrastructure/pom.xml backend/shared-event-infrastructure/pom.xml
COPY backend/shared-event-infrastructure/src backend/shared-event-infrastructure/src
RUN mvn -B -f backend/shared-event-infrastructure/pom.xml clean install -DskipTests
COPY backend/${SERVICE_MODULE}/pom.xml backend/${SERVICE_MODULE}/pom.xml
COPY backend/${SERVICE_MODULE}/src backend/${SERVICE_MODULE}/src
RUN mvn -B -f backend/${SERVICE_MODULE}/pom.xml clean package -DskipTests

FROM eclipse-temurin:21-jre-jammy
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home agentshield
WORKDIR /app
ARG SERVICE_MODULE
COPY --from=build --chown=agentshield:agentshield /workspace/backend/${SERVICE_MODULE}/target/*-SNAPSHOT.jar /app/service.jar
COPY --chown=agentshield:agentshield backend/docker-entrypoint.sh /app/docker-entrypoint.sh
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]
