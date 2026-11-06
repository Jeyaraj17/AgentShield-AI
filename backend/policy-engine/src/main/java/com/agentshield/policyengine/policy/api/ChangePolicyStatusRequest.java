package com.agentshield.policyengine.policy.api;

import com.agentshield.policyengine.policy.domain.PolicyStatus;
import jakarta.validation.constraints.NotNull;

public record ChangePolicyStatusRequest(@NotNull PolicyStatus status) {}
