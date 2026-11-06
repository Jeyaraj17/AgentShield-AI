package com.agentshield.runtimesecurity.runtime.api;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import com.agentshield.runtimesecurity.runtime.domain.AuthorizationDecision;
import com.agentshield.runtimesecurity.runtime.domain.ExecutionResult;

public record RuntimeExecutionResponse(UUID executionId,UUID organizationId,UUID agentId,String action,
        AuthorizationDecision policyDecision,String reasonCode,ExecutionResult executionResult,
        String correlationId,Instant createdAt,Map<String,Object> toolResult) {}
