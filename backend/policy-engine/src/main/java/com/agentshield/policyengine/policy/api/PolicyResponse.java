package com.agentshield.policyengine.policy.api;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import com.agentshield.policyengine.policy.domain.PolicyStatus;

public record PolicyResponse(UUID policyId, UUID versionId, UUID organizationId, String name,
        String description, int version, PolicyStatus status, int priority, Instant createdAt,
        Instant updatedAt, List<PolicyRuleResponse> rules) {}
