package com.agentshield.events;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.ObjectMapper;
import com.agentshield.events.amqp.EventAmqpConfiguration;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.contract.SecurityEvent;
import com.agentshield.events.inbox.EventHandler;
import com.agentshield.events.inbox.InboxEventProcessor;
import com.agentshield.events.outbox.EventTransport;
import com.agentshield.events.outbox.OutboxDispatcher;
import com.agentshield.events.outbox.OutboxEventWriter;

class EventInfrastructureTests {
    private JdbcTemplate jdbc;
    private ObjectMapper mapper;
    private SecurityEvent event;

    @BeforeEach void setup() {
        var ds = new DriverManagerDataSource("jdbc:h2:mem:" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa", "");
        jdbc = new JdbcTemplate(ds); mapper = new ObjectMapper();
        jdbc.execute("CREATE TABLE event_outbox(event_id CHAR(36) PRIMARY KEY, organization_id CHAR(36) NOT NULL,event_type VARCHAR(80) NOT NULL,routing_key VARCHAR(120) NOT NULL,schema_version INT NOT NULL,payload_json CLOB NOT NULL,status VARCHAR(16) NOT NULL,attempts INT NOT NULL,available_at TIMESTAMP NOT NULL,locked_until TIMESTAMP,created_at TIMESTAMP NOT NULL,published_at TIMESTAMP,last_error_code VARCHAR(80))");
        jdbc.execute("CREATE TABLE event_inbox(event_id CHAR(36) PRIMARY KEY,organization_id CHAR(36) NOT NULL,event_type VARCHAR(80) NOT NULL,payload_json CLOB NOT NULL,received_at TIMESTAMP NOT NULL,processed_at TIMESTAMP NOT NULL)");
        event = SecurityEvent.create(UUID.randomUUID(), EventType.RUNTIME_AUTHORIZATION_DENY, UUID.randomUUID(),
                Map.of("agentId", UUID.randomUUID().toString(), "action", "invoice.read", "reasonCode", "POLICY_DENY"));
    }

    @Test void eventSerializationKeepsTenantEnvelopeAndRejectsUnapprovedData() {
        String json = mapper.writeValueAsString(event);
        SecurityEvent decoded = mapper.readValue(json, SecurityEvent.class);
        assertEquals(event.eventId(), decoded.eventId());
        assertEquals(event.organizationId(), decoded.organizationId());
        assertEquals(event.correlationId(), decoded.correlationId());
        assertEquals(1, decoded.schemaVersion());
        assertFalse(json.contains("password"));
        assertThrows(IllegalArgumentException.class, () -> SecurityEvent.create(event.organizationId(), EventType.AI_THREAT_DETECTED,
                null, Map.of("prompt", "raw user prompt")));
    }

    @Test void runtimeSchemaV2CarriesActorExecutionAndProtectedResourceWithoutChangingV1() {
        UUID agent=UUID.randomUUID(),execution=UUID.randomUUID();
        SecurityEvent v2=SecurityEvent.createV2(UUID.randomUUID(),EventType.RUNTIME_AUTHORIZATION_ALLOW,UUID.randomUUID(),Map.of(
                "agentId",agent.toString(),"actorId",agent.toString(),"actorType","AGENT","executionId",execution.toString(),
                "action","invoice.read","resourceId","invoice-table","reasonCode","POLICY_ALLOW"));
        SecurityEvent decoded=mapper.readValue(mapper.writeValueAsString(v2),SecurityEvent.class);
        assertEquals(2,decoded.schemaVersion());assertEquals(execution.toString(),decoded.metadata().get("executionId"));
        assertEquals("invoice-table",decoded.metadata().get("resourceId"));assertEquals(agent.toString(),decoded.metadata().get("actorId"));
        assertThrows(IllegalArgumentException.class,()->SecurityEvent.createV2(v2.organizationId(),EventType.RUNTIME_AUTHORIZATION_ALLOW,null,
                Map.of("agentId",agent.toString(),"actorId",agent.toString(),"actorType","AGENT","executionId",execution.toString(),
                        "action","invoice.read","resourceId","resource","reasonCode","OK","prompt","raw secret")));
    }

    @Test void outboxWriterPersistsEventAndDispatcherRetriesThenRetainsDeadLetterRow() {
        new OutboxEventWriter(jdbc, mapper).append(event);
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM event_outbox WHERE organization_id=?", Integer.class, event.organizationId().toString()));
        EventTransport unavailable = (routing, json) -> { throw new IllegalStateException("broker unavailable"); };
        OutboxDispatcher dispatcher = new OutboxDispatcher(jdbc, unavailable, 2, 10, 1);
        dispatcher.dispatchAvailable();
        assertEquals("RETRY", jdbc.queryForObject("SELECT status FROM event_outbox WHERE event_id=?", String.class, event.eventId().toString()));
        jdbc.update("UPDATE event_outbox SET available_at=CURRENT_TIMESTAMP WHERE event_id=?", event.eventId().toString());
        dispatcher.dispatchAvailable();
        assertEquals("DEAD", jdbc.queryForObject("SELECT status FROM event_outbox WHERE event_id=?", String.class, event.eventId().toString()));
        assertEquals(2, jdbc.queryForObject("SELECT attempts FROM event_outbox WHERE event_id=?", Integer.class, event.eventId().toString()));
    }

    @Test void outboxInsertRollsBackWithBusinessTransaction() {
        var transactions = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
        OutboxEventWriter writer = new OutboxEventWriter(jdbc, mapper);
        assertThrows(IllegalStateException.class, () -> transactions.executeWithoutResult(status -> {
            writer.append(event);
            throw new IllegalStateException("rollback test");
        }));
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM event_outbox", Integer.class));
    }

    @Test void inboxDeduplicatesDeliveryAndRunsHandlerOnce() {
        AtomicInteger handled = new AtomicInteger();
        InboxEventProcessor processor = new InboxEventProcessor(jdbc, mapper,
                new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource())),
                java.util.List.<EventHandler>of(ignored -> handled.incrementAndGet()));
        String json = mapper.writeValueAsString(event);
        assertTrue(processor.process(json));
        assertFalse(processor.process(json));
        assertEquals(1, handled.get());
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM event_inbox", Integer.class));
    }

    @Test void topologyDeclaresDeadLetterQueueAndBinding() {
        var topology = new EventAmqpConfiguration().agentShieldEventTopology("service.queue", "service.dlq");
        var queue = topology.getDeclarables().stream().filter(d -> d instanceof org.springframework.amqp.core.Queue q && q.getName().equals("service.queue"))
                .map(d -> (org.springframework.amqp.core.Queue)d).findFirst().orElseThrow();
        assertEquals("agentshield.events.dlx", queue.getArguments().get("x-dead-letter-exchange"));
        assertEquals("service.dlq", queue.getArguments().get("x-dead-letter-routing-key"));
        assertTrue(topology.getDeclarables().stream().anyMatch(d -> d instanceof org.springframework.amqp.core.Binding b && b.getDestination().equals("service.dlq")));
    }
}
