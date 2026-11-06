package com.agentshield.agentmanagement.agent.api;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.agentshield.agentmanagement.agent.domain.Agent;
import com.agentshield.agentmanagement.agent.domain.AgentStatus;

public record AgentResponse(
        UUID id,
        UUID organizationId,
        String name,
        String agentCode,
        String description,
        String agentType,
        AgentStatus status,
        List<String> capabilities,
        Instant createdAt,
        Instant updatedAt) {

    public static AgentResponse from(Agent agent) {
        return new AgentResponse(agent.getId(), agent.getOrganizationId(), agent.getName(), agent.getAgentCode(),
                agent.getDescription(), agent.getAgentType(), agent.getStatus(),
                List.copyOf(agent.getCapabilities()), agent.getCreatedAt(), agent.getUpdatedAt());
    }
}
