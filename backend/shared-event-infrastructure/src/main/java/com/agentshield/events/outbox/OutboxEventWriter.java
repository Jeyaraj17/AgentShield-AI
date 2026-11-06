package com.agentshield.events.outbox;

import com.agentshield.events.contract.SecurityEvent;
import tools.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Writes event rows in the caller's database transaction. */
@Component
public class OutboxEventWriter {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    public OutboxEventWriter(JdbcTemplate jdbc, ObjectMapper mapper) { this.jdbc = jdbc; this.mapper = mapper; }

    @Transactional
    public void append(SecurityEvent event) {
        String json = mapper.writeValueAsString(event);
        jdbc.update("INSERT INTO event_outbox(event_id, organization_id, event_type, routing_key, schema_version, payload_json, status, attempts, available_at, created_at) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                event.eventId().toString(), event.organizationId().toString(), event.eventType().name(),
                event.eventType().name().toLowerCase().replace('_', '.'), event.schemaVersion(), json);
    }
}
