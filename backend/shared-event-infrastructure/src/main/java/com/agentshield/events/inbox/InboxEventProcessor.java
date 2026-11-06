package com.agentshield.events.inbox;

import java.util.List;
import com.agentshield.events.contract.SecurityEvent;
import tools.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

/** Inserts the inbox key and runs handlers in one local transaction; duplicates are acknowledged. */
@Component
public class InboxEventProcessor {
    private final JdbcTemplate jdbc; private final ObjectMapper mapper;
    private final TransactionTemplate transactions; private final List<EventHandler> handlers;
    public InboxEventProcessor(JdbcTemplate jdbc,ObjectMapper mapper,TransactionTemplate transactions,List<EventHandler> handlers) {
        this.jdbc=jdbc;this.mapper=mapper;this.transactions=transactions;this.handlers=handlers;
    }
    public boolean process(String json) {
        SecurityEvent event = mapper.readValue(json, SecurityEvent.class);
        return transactions.execute(status -> {
            int inserted;
            try { inserted=jdbc.update("INSERT INTO event_inbox(event_id,organization_id,event_type,payload_json,received_at,processed_at) VALUES (?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
                    event.eventId().toString(),event.organizationId().toString(),event.eventType().name(),json); }
            catch (org.springframework.dao.DuplicateKeyException duplicate) { return false; }
            handlers.forEach(handler -> handler.handle(event));
            return inserted == 1;
        });
    }
}
