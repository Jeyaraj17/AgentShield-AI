package com.agentshield.agentmanagement.agent.api;

import com.agentshield.agentmanagement.agent.domain.AgentStatus;
import jakarta.validation.constraints.NotNull;

public record ChangeAgentStatusRequest(@NotNull(message = "Status is required") AgentStatus status) {
}
