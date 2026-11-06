package com.agentshield.identity.agentcredential.api;

import java.time.Instant;
import java.util.UUID;

public record AgentCredentialResponse(UUID credentialId, String clientId, String clientSecret,
        UUID agentId, UUID organizationId, Instant createdAt) { }
