package com.agentshield.identity.agentcredential;

import java.util.UUID;

public interface AgentDirectoryVerifier {
    boolean isActiveAgent(UUID agentId, UUID organizationId, String userAccessToken);
}
