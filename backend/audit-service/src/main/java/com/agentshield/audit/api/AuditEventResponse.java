package com.agentshield.audit.api;

import java.time.Instant;
import java.util.UUID;
import com.agentshield.audit.persistence.AuditEventEntity;
import com.agentshield.events.contract.EventType;

public record AuditEventResponse(UUID eventId,UUID organizationId,EventType eventType,String actorIdentity,String actorType,
        UUID agentId,UUID executionId,String action,String resource,String decision,String reason,String executionOutcome,UUID correlationId,
        Instant eventTimestamp,Instant receivedTimestamp) {
    public static AuditEventResponse from(AuditEventEntity e) {
        return new AuditEventResponse(e.getEventId(),e.getOrganizationId(),e.getEventType(),e.getActorIdentity(),e.getActorType(),e.getAgentId(),e.getExecutionId(),
                e.getAction(),e.getResource(),e.getDecision(),e.getReason(),e.getExecutionOutcome(),e.getCorrelationId(),e.getEventTimestamp(),e.getReceivedTimestamp());
    }
}
