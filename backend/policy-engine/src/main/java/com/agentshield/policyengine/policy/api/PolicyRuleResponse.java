package com.agentshield.policyengine.policy.api;

import java.time.Instant;
import java.util.UUID;
import com.agentshield.policyengine.policy.domain.AgentScope;
import com.agentshield.policyengine.policy.domain.RuleConditions;
import com.agentshield.policyengine.policy.domain.RuleEffect;

public record PolicyRuleResponse(UUID id, String name, AgentScope agentScope, UUID targetAgentId,
        String action, RuleEffect effect, RuleConditions conditions, Instant createdAt) {}
