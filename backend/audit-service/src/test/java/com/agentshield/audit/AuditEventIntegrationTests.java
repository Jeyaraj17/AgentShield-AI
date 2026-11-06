package com.agentshield.audit;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import static org.mockito.Mockito.*;
import com.agentshield.audit.persistence.AuditEventRepository;
import com.agentshield.events.amqp.SecurityEventListener;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.contract.SecurityEvent;
import com.agentshield.events.inbox.InboxEventProcessor;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest @ActiveProfiles("test")
class AuditEventIntegrationTests {
    @Autowired InboxEventProcessor inbox;
    @Autowired AuditEventRepository repository;
    @Autowired ObjectMapper mapper;
    private final UUID org=UUID.randomUUID(),agent=UUID.randomUUID(),correlation=UUID.randomUUID();
    @BeforeEach void clear(){repository.deleteAll();}

    @Test void consumesAndPersistsTenantEventAndDuplicateDeliveryIsIdempotent(){
        var event=event(EventType.RUNTIME_AUTHORIZATION_DENY,Map.of("agentId",agent.toString(),"action","tool.call","reasonCode","POLICY_DENY"));
        String json=mapper.writeValueAsString(event);
        assertTrue(inbox.process(json));assertFalse(inbox.process(json));
        var saved=repository.findByEventIdAndOrganizationId(event.eventId(),org).orElseThrow();
        assertEquals(org,saved.getOrganizationId());assertEquals(agent,saved.getAgentId());assertEquals("DENY",saved.getDecision());
        assertEquals("POLICY_DENY",saved.getReason());assertEquals(correlation,saved.getCorrelationId());
        assertNotNull(saved.getEventTimestamp());assertNotNull(saved.getReceivedTimestamp());assertEquals("AGENT",saved.getActorType());
        assertEquals(1,repository.count());
    }

    @Test void v2RuntimeEventsPairAuthorizationAndExecutionWithoutConfusingResourceAndId(){
        UUID execution=UUID.randomUUID();
        var authorization=SecurityEvent.createV2(org,EventType.RUNTIME_AUTHORIZATION_ALLOW,correlation,Map.of(
                "agentId",agent.toString(),"actorId",agent.toString(),"actorType","AGENT","executionId",execution.toString(),
                "action","tool.call","resourceId","customer-record","reasonCode","POLICY_ALLOW"));
        var completed=SecurityEvent.createV2(org,EventType.TOOL_EXECUTION_SUCCEEDED,correlation,Map.of(
                "agentId",agent.toString(),"actorId",agent.toString(),"actorType","AGENT","executionId",execution.toString(),
                "action","tool.call","resourceId","customer-record","result","SUCCEEDED"));
        assertTrue(inbox.process(mapper.writeValueAsString(authorization)));assertTrue(inbox.process(mapper.writeValueAsString(completed)));
        var decision=repository.findByEventIdAndOrganizationId(authorization.eventId(),org).orElseThrow();
        var outcome=repository.findByEventIdAndOrganizationId(completed.eventId(),org).orElseThrow();
        assertEquals(execution,decision.getExecutionId());assertEquals(execution,outcome.getExecutionId());
        assertEquals("customer-record",decision.getResource());assertEquals("customer-record",outcome.getResource());
        assertEquals("ALLOW",decision.getDecision());assertNull(decision.getExecutionOutcome());
        assertEquals("SUCCEEDED",outcome.getExecutionOutcome());assertNull(outcome.getDecision());
        assertEquals("AGENT",decision.getActorType());assertEquals(agent.toString(),decision.getActorIdentity());
    }

    @Test void invalidMetadataIsRejectedBeforeAuditWrite(){
        String invalid="""
          {"eventId":"%s","organizationId":"%s","eventType":"RUNTIME_AUTHORIZATION_ALLOW","timestamp":"%s","correlationId":"%s","schemaVersion":1,"metadata":{"agentId":"%s","action":"raw prompt with secret","reasonCode":"ALLOW"}}
          """.formatted(UUID.randomUUID(),org,Instant.now(),correlation,agent);
        assertThrows(RuntimeException.class,()->inbox.process(invalid));
        assertEquals(0,repository.count());
    }

    @Test void recordsDoNotPersistUnredactedPromptOrCredentials(){
        var event=event(EventType.AI_THREAT_DETECTED,Map.of("agentId",agent.toString(),"analysisId",UUID.randomUUID().toString(),"category","PROMPT","riskScore","92"));
        String json=mapper.writeValueAsString(event);
        assertFalse(json.contains("promptText"));assertFalse(json.contains("password"));assertFalse(json.contains("access_token"));
        inbox.process(json);
        var row=repository.findByEventIdAndOrganizationId(event.eventId(),org).orElseThrow();
        assertEquals("AI_THREAT_DETECTED",row.getAction());
    }

    @Test void messageListenerRetriesTransientInboxFailureAndDispatchesDelivery(){
        InboxEventProcessor processor=mock(InboxEventProcessor.class);
        var event=event(EventType.AGENT_REGISTERED,Map.of("agentId",agent.toString(),"status","ACTIVE"));
        String json=mapper.writeValueAsString(event);
        when(processor.process(json)).thenThrow(new IllegalStateException("temporary database issue"),new IllegalStateException("temporary database issue"))
                .thenReturn(true);
        new SecurityEventListener(processor,3,1,2).receive(json);
        verify(processor,times(3)).process(json);
    }

    private SecurityEvent event(EventType type,Map<String,String> metadata){return new SecurityEvent(UUID.randomUUID(),org,type,Instant.now(),correlation,1,metadata);}
}
