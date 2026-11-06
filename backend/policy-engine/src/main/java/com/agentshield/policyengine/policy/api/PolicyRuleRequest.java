package com.agentshield.policyengine.policy.api;

import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import com.agentshield.policyengine.policy.domain.AgentScope;
import com.agentshield.policyengine.policy.domain.RuleConditions;
import com.agentshield.policyengine.policy.domain.RuleEffect;

public record PolicyRuleRequest(@NotBlank @Size(max=150) String name, @NotNull AgentScope agentScope,
        UUID targetAgentId, @NotBlank @Size(max=150) String action, @NotNull RuleEffect effect,
        @Valid RuleConditions conditions) {}
