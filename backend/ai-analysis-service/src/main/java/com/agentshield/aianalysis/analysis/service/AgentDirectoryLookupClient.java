package com.agentshield.aianalysis.analysis.service;

import java.util.UUID;

public interface AgentDirectoryLookupClient {
    AgentOwnershipDescriptor findAgent(UUID agentId, String userAccessToken);
}
