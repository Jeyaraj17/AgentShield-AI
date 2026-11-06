package com.agentshield.policyengine.policy.api;

import java.time.Instant;
import java.util.UUID;
import com.agentshield.policyengine.policy.domain.PolicyStatus;

public record PolicyVersionResponse(UUID policyId, UUID versionId, int version, PolicyStatus status,
        boolean latest, Instant createdAt, Instant updatedAt) {}
