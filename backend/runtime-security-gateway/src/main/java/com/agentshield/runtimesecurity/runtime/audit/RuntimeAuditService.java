package com.agentshield.runtimesecurity.runtime.audit;

import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import com.agentshield.runtimesecurity.runtime.domain.AuthorizationDecision;
import com.agentshield.runtimesecurity.runtime.domain.ExecutionResult;
import com.agentshield.runtimesecurity.runtime.domain.RuntimeExecution;
import com.agentshield.runtimesecurity.runtime.persistence.RuntimeExecutionRepository;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.outbox.OutboxEventWriter;

@Service
public class RuntimeAuditService {
    private final RuntimeExecutionRepository repository;
    private final SecurityEventPublisher publisher;
    private final OutboxEventWriter outbox;
    public RuntimeAuditService(RuntimeExecutionRepository repository,SecurityEventPublisher publisher,OutboxEventWriter outbox) { this.repository=repository; this.publisher=publisher; this.outbox=outbox; }
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public RuntimeExecution record(UUID org,UUID agent,UUID user,String action,String resource,
            AuthorizationDecision decision,String reason,ExecutionResult result,UUID correlation) {
        RuntimeExecution stored=repository.saveAndFlush(new RuntimeExecution(org,agent,user,action,resource,decision,reason,result,correlation));
        EventType type = decision == AuthorizationDecision.ALLOW ? EventType.RUNTIME_AUTHORIZATION_ALLOW : EventType.RUNTIME_AUTHORIZATION_DENY;
        UUID actorId=user==null?agent:user;
        outbox.append(com.agentshield.events.contract.SecurityEvent.createV2(org, type, stored.getCorrelationId(), java.util.Map.of(
                "agentId", agent.toString(), "actorId", actorId.toString(), "actorType", user==null?"AGENT":"USER",
                "executionId", stored.getId().toString(), "action", safe(action, 120), "resourceId", stored.getResourceId(), "reasonCode", safe(reason, 80))));
        publisher.publish(event("AUTHORIZATION_RECORDED",stored));
        return stored;
    }
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public RuntimeExecution complete(UUID org,UUID executionId,ExecutionResult result) {
        RuntimeExecution stored=repository.findByIdAndOrganizationId(executionId,org).orElseThrow();
        stored.complete(result);
        RuntimeExecution updated=repository.saveAndFlush(stored);
        if (result == ExecutionResult.SUCCEEDED || result == ExecutionResult.FAILED) {
            EventType type = result == ExecutionResult.SUCCEEDED ? EventType.TOOL_EXECUTION_SUCCEEDED : EventType.TOOL_EXECUTION_FAILED;
            UUID actorId=updated.getUserId()==null?updated.getAgentId():updated.getUserId();
            outbox.append(com.agentshield.events.contract.SecurityEvent.createV2(org, type, updated.getCorrelationId(), java.util.Map.of(
                    "agentId", updated.getAgentId().toString(), "actorId", actorId.toString(), "actorType", updated.getUserId()==null?"AGENT":"USER",
                    "executionId", updated.getId().toString(), "action", safe(updated.getAction(), 120),
                    "resourceId", updated.getResourceId(), "result", result.name())));
        }
        publisher.publish(event("EXECUTION_COMPLETED",updated));
        return updated;
    }
    private static SecurityEvent event(String type,RuntimeExecution e) {
        return new SecurityEvent(type,e.getOrganizationId(),e.getAgentId(),e.getAction(),e.getAuthorizationDecision(),
                e.getReasonCode(),e.getExecutionResult(),e.getCompletedAt()==null?e.getCreatedAt():e.getCompletedAt(),e.getCorrelationId());
    }
    private static String safe(String value,int max) {
        if (value == null) return "UNKNOWN";
        String safe=value.replaceAll("[^A-Za-z0-9._:-]", "_");
        return safe.length()>max?safe.substring(0,max):safe;
    }
}
