package com.agentshield.runtimesecurity.runtime;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.UUID;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.contract.SecurityEvent;
import com.agentshield.events.outbox.OutboxEventWriter;
import com.agentshield.runtimesecurity.runtime.audit.RuntimeAuditService;
import com.agentshield.runtimesecurity.runtime.audit.SecurityEventPublisher;
import com.agentshield.runtimesecurity.runtime.domain.AuthorizationDecision;
import com.agentshield.runtimesecurity.runtime.domain.ExecutionResult;
import com.agentshield.runtimesecurity.runtime.domain.RuntimeExecution;
import com.agentshield.runtimesecurity.runtime.persistence.RuntimeExecutionRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class RuntimeAuditServiceTests {
    @Test void authorizationAndExecutionEventsShareExecutionAndCorrelationWithoutIncludingPayload(){
        RuntimeExecutionRepository repository=mock(RuntimeExecutionRepository.class);SecurityEventPublisher publisher=mock(SecurityEventPublisher.class);
        OutboxEventWriter outbox=mock(OutboxEventWriter.class);RuntimeAuditService service=new RuntimeAuditService(repository,publisher,outbox);
        UUID org=UUID.randomUUID(),agent=UUID.randomUUID(),user=UUID.randomUUID(),correlation=UUID.randomUUID();
        when(repository.saveAndFlush(any(RuntimeExecution.class))).thenAnswer(call->call.getArgument(0));
        RuntimeExecution execution=service.record(org,agent,user,"invoice.read","invoice-table",AuthorizationDecision.ALLOW,
                "POLICY_ALLOW",ExecutionResult.PENDING,correlation);
        when(repository.findByIdAndOrganizationId(execution.getId(),org)).thenReturn(java.util.Optional.of(execution));
        service.complete(org,execution.getId(),ExecutionResult.SUCCEEDED);
        ArgumentCaptor<SecurityEvent> captor=ArgumentCaptor.forClass(SecurityEvent.class);verify(outbox,times(2)).append(captor.capture());
        var decision=captor.getAllValues().get(0);var outcome=captor.getAllValues().get(1);
        assertEquals(EventType.RUNTIME_AUTHORIZATION_ALLOW,decision.eventType());assertEquals(EventType.TOOL_EXECUTION_SUCCEEDED,outcome.eventType());
        assertEquals(2,decision.schemaVersion());assertEquals(execution.getId().toString(),decision.metadata().get("executionId"));
        assertEquals(decision.metadata().get("executionId"),outcome.metadata().get("executionId"));
        assertEquals("invoice-table",decision.metadata().get("resourceId"));assertEquals("USER",decision.metadata().get("actorType"));
        assertEquals(user.toString(),decision.metadata().get("actorId"));assertEquals(correlation,decision.correlationId());assertEquals(correlation,outcome.correlationId());
        assertFalse(decision.metadata().containsKey("inputPayload"));
    }
}
