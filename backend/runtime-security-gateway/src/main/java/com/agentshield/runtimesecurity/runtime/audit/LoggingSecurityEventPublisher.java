package com.agentshield.runtimesecurity.runtime.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class LoggingSecurityEventPublisher implements SecurityEventPublisher {
    private static final Logger log=LoggerFactory.getLogger(LoggingSecurityEventPublisher.class);
    @Override public void publish(SecurityEvent event) {
        log.info("event={} organizationId={} agentId={} action={} policyDecision={} reasonCode={} executionResult={} timestamp={} correlationId={}",
                event.eventType(),event.organizationId(),event.agentId(),event.action(),event.policyDecision(),
                event.reasonCode(),event.executionResult(),event.timestamp(),event.correlationId());
    }
}
