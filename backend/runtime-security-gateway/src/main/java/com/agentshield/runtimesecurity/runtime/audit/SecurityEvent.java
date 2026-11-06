package com.agentshield.runtimesecurity.runtime.audit;

import java.time.Instant;
import java.util.UUID;
import com.agentshield.runtimesecurity.runtime.domain.AuthorizationDecision;
import com.agentshield.runtimesecurity.runtime.domain.ExecutionResult;

public record SecurityEvent(String eventType,UUID organizationId,UUID agentId,String action,
        AuthorizationDecision policyDecision,String reasonCode,ExecutionResult executionResult,
        Instant timestamp,UUID correlationId) {}
