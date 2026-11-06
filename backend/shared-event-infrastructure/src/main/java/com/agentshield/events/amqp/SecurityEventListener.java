package com.agentshield.events.amqp;

import com.agentshield.events.inbox.InboxEventProcessor;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;

@Component
@ConditionalOnProperty(name="agentshield.events.consumer.enabled", havingValue="true", matchIfMissing=true)
public class SecurityEventListener {
    private final InboxEventProcessor processor;
    private final int maxAttempts;
    private final long initialBackoffMs;
    private final long maxBackoffMs;
    public SecurityEventListener(InboxEventProcessor processor,
            @Value("${agentshield.events.consumer.max-attempts:4}") int maxAttempts,
            @Value("${agentshield.events.consumer.initial-backoff-ms:250}") long initialBackoffMs,
            @Value("${agentshield.events.consumer.max-backoff-ms:3000}") long maxBackoffMs) {
        if (maxAttempts < 1 || initialBackoffMs < 1 || maxBackoffMs < initialBackoffMs) throw new IllegalArgumentException("Invalid event consumer retry limits");
        this.processor=processor; this.maxAttempts=maxAttempts; this.initialBackoffMs=initialBackoffMs; this.maxBackoffMs=maxBackoffMs;
    }
    @RabbitListener(queues="${agentshield.events.queue:agentshield.service.events}", containerFactory="agentshieldEventListenerContainerFactory")
    public void receive(String json) {
        for (int attempt=1; ; attempt++) {
            try { processor.process(json); return; }
            catch (RuntimeException failure) {
                if (attempt >= maxAttempts) throw failure;
                try { Thread.sleep(Math.min(maxBackoffMs, initialBackoffMs * (1L << Math.min(attempt-1, 10)))); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new IllegalStateException("Event retry interrupted"); }
            }
        }
    }
}
