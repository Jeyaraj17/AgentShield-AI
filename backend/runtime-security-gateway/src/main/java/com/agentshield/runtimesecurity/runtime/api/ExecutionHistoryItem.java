package com.agentshield.runtimesecurity.runtime.api;

import java.time.Instant;
import java.util.UUID;
import com.agentshield.runtimesecurity.runtime.domain.AuthorizationDecision;
import com.agentshield.runtimesecurity.runtime.domain.ExecutionResult;

public record ExecutionHistoryItem(UUID executionId, UUID agentId, String agentName, String tool,
        String resource, AuthorizationDecision policyDecision, String reasonCode,
        ExecutionResult executionOutcome, String correlationId, Instant requestedAt, Instant completedAt) { }
