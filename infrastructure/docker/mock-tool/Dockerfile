FROM node:22-alpine
RUN apk add --no-cache curl \
    && addgroup -S agentshield \
    && adduser -S -G agentshield agentshield
WORKDIR /app
COPY --chown=agentshield:agentshield server.mjs /app/server.mjs
USER agentshield
EXPOSE 8443
CMD ["node", "/app/server.mjs"]
