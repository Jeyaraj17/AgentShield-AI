package com.agentshield.audit.event;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.contract.SecurityEvent;
import com.agentshield.events.inbox.EventHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.agentshield.audit.persistence.AuditEventEntity;
import com.agentshield.audit.persistence.AuditEventRepository;

/** Converts only the allowlisted shared event fields into an immutable audit row. */
@Component
public class AuditEventHandler implements EventHandler {
    private static final Logger log=LoggerFactory.getLogger(AuditEventHandler.class);
    private static final Set<EventType> ACCEPTED = Set.of(EventType.values());
    private final AuditEventRepository repository;
    public AuditEventHandler(AuditEventRepository repository) { this.repository=repository; }

    @Override @Transactional
    public void handle(SecurityEvent event) {
        if (event == null || !ACCEPTED.contains(event.eventType()) || event.schemaVersion()<1 || event.schemaVersion()>2)
            throw new InvalidAuditEventException("Unsupported audit event");
        Map<String,String> data=event.metadata();
        String agentId=data.get("agentId");
        String action=data.getOrDefault("action", event.eventType().name());
        String resource=first(data,"resourceId","analysisId","policyId","agentId");
        java.util.UUID executionId=parseUuid(data.get("executionId"));
        String decision=switch(event.eventType()) {
            case RUNTIME_AUTHORIZATION_ALLOW -> "ALLOW";
            case RUNTIME_AUTHORIZATION_DENY -> "DENY";
            default -> null;
        };
        String reason=first(data,"reasonCode","category","status","score");
        String outcome=switch(event.eventType()) {
            case TOOL_EXECUTION_SUCCEEDED -> "SUCCEEDED";
            case TOOL_EXECUTION_FAILED -> "FAILED";
            default -> null;
        };
        String actorType=data.getOrDefault("actorType",isAgentEvent(event.eventType()) ? "AGENT" : "SERVICE");
        String actorIdentity=data.getOrDefault("actorId","AGENT".equals(actorType) ? agentId : source(event.eventType()));
        repository.save(new AuditEventEntity(event.eventId(),event.organizationId(),event.eventType(),actorIdentity,actorType,
                parseUuid(agentId),executionId,action,resource,decision,reason,outcome,event.correlationId(),event.timestamp(),Instant.now()));
        log.info("Audit event recorded eventId={} organizationId={} eventType={} correlationId={}",event.eventId(),event.organizationId(),event.eventType(),event.correlationId());
    }

    private static boolean isAgentEvent(EventType type) {
        return switch(type) {
            case RUNTIME_AUTHORIZATION_ALLOW,RUNTIME_AUTHORIZATION_DENY,TOOL_EXECUTION_SUCCEEDED,TOOL_EXECUTION_FAILED,AI_THREAT_DETECTED -> true;
            default -> false;
        };
    }
    private static String source(EventType type) {
        return switch(type) {
            case AGENT_REGISTERED,AGENT_UPDATED,AGENT_DEACTIVATED -> "agent-management-service";
            case POLICY_CREATED,POLICY_UPDATED,POLICY_ACTIVATED -> "policy-engine";
            case AGENT_TRUST_SCORE_UPDATED,AI_THREAT_DETECTED -> "ai-analysis-service";
            default -> "runtime-security-gateway";
        };
    }
    private static String first(Map<String,String> data,String... keys) { for(String key:keys) if(data.containsKey(key)) return data.get(key); return null; }
    private static java.util.UUID parseUuid(String value) { return value==null?null:java.util.UUID.fromString(value); }
}
