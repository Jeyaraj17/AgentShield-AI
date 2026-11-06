package com.agentshield.events.outbox;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

/** At-least-once dispatcher: broker failures leave events durable for bounded retry. */
@Component
@ConditionalOnProperty(name="agentshield.events.dispatcher.enabled", havingValue="true", matchIfMissing=true)
public class OutboxDispatcher {
    private final JdbcTemplate jdbc;
    private final EventTransport transport;
    private final int maxAttempts;
    private final int batchSize;
    private final long baseDelaySeconds;
    public OutboxDispatcher(JdbcTemplate jdbc, EventTransport transport,
            @Value("${agentshield.events.outbox.max-attempts:8}") int maxAttempts,
            @Value("${agentshield.events.outbox.batch-size:50}") int batchSize,
            @Value("${agentshield.events.outbox.base-delay-seconds:2}") long baseDelaySeconds) {
        if (maxAttempts < 1 || batchSize < 1 || baseDelaySeconds < 1) throw new IllegalArgumentException("Invalid outbox limits");
        this.jdbc=jdbc; this.transport=transport; this.maxAttempts=maxAttempts; this.batchSize=batchSize; this.baseDelaySeconds=baseDelaySeconds;
    }

    @Scheduled(fixedDelayString="${agentshield.events.outbox.poll-ms:1000}")
    public void dispatchAvailable() {
        List<Row> rows = jdbc.query("SELECT event_id,routing_key,payload_json,attempts FROM event_outbox WHERE (status IN ('PENDING','RETRY') AND available_at <= CURRENT_TIMESTAMP) OR (status='IN_FLIGHT' AND locked_until < CURRENT_TIMESTAMP) ORDER BY created_at LIMIT " + batchSize, (rs, n) -> row(rs));
        for (Row row : rows) dispatch(row);
    }

    private void dispatch(Row row) {
        int claimed = jdbc.update("UPDATE event_outbox SET status='IN_FLIGHT', locked_until=? WHERE event_id=? AND ((status IN ('PENDING','RETRY') AND available_at <= CURRENT_TIMESTAMP) OR (status='IN_FLIGHT' AND locked_until < CURRENT_TIMESTAMP))",
                java.sql.Timestamp.from(java.time.Instant.now().plusSeconds(60)), row.id);
        if (claimed == 0) return;
        try {
            transport.publish(row.routingKey, row.payload);
            jdbc.update("UPDATE event_outbox SET status='PUBLISHED',published_at=CURRENT_TIMESTAMP,locked_until=NULL,last_error_code=NULL WHERE event_id=? AND status='IN_FLIGHT'", row.id);
        } catch (Exception ex) {
            int attempts = row.attempts + 1;
            if (attempts >= maxAttempts) {
                try { transport.deadLetter(row.routingKey, row.payload); } catch (Exception ignored) { /* Durable DEAD row remains available for operator replay. */ }
                jdbc.update("UPDATE event_outbox SET status='DEAD',attempts=?,locked_until=NULL,last_error_code='BROKER_PUBLISH_FAILED' WHERE event_id=?", attempts, row.id);
            } else {
                long delay = Math.min(3600, baseDelaySeconds * (1L << Math.min(attempts - 1, 20)));
                jdbc.update("UPDATE event_outbox SET status='RETRY',attempts=?,available_at=?,locked_until=NULL,last_error_code='BROKER_PUBLISH_FAILED' WHERE event_id=?",
                        attempts, java.sql.Timestamp.from(java.time.Instant.now().plus(Duration.ofSeconds(delay))), row.id);
            }
        }
    }
    private static Row row(ResultSet rs) throws SQLException { return new Row(rs.getString(1), rs.getString(2), rs.getString(3), rs.getInt(4)); }
    private record Row(String id,String routingKey,String payload,int attempts) {}
}
