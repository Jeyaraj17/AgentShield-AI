package com.agentshield.events.outbox;

@FunctionalInterface
public interface EventTransport {
    void publish(String routingKey, String json) throws Exception;
    default void deadLetter(String routingKey, String json) throws Exception { }
}
