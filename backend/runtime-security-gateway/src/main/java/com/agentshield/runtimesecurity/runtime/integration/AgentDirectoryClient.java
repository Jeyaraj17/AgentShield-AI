package com.agentshield.runtimesecurity.runtime.integration;

import java.util.List;
import java.util.UUID;

public interface AgentDirectoryClient {
    AgentDescriptor findAgent(UUID agentId,UUID organizationId,String serviceToken,String correlationId);
    record AgentDescriptor(UUID id,UUID organizationId,String status,List<String> capabilities) {
        public AgentDescriptor { capabilities=capabilities==null?List.of():List.copyOf(capabilities); }
    }
}
