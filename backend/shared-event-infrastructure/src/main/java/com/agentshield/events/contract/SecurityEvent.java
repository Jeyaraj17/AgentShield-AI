package com.agentshield.events.contract;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Versioned, allowlisted cross-service event envelope. Schema v1 remains readable. */
public record SecurityEvent(UUID eventId, UUID organizationId, EventType eventType, Instant timestamp,
                            UUID correlationId, int schemaVersion, Map<String, String> metadata) {
    private static final Map<EventType, Set<String>> V1 = Map.ofEntries(
        Map.entry(EventType.AGENT_REGISTERED, Set.of("agentId", "status")),
        Map.entry(EventType.AGENT_UPDATED, Set.of("agentId", "status")),
        Map.entry(EventType.AGENT_DEACTIVATED, Set.of("agentId", "status")),
        Map.entry(EventType.POLICY_CREATED, Set.of("policyId", "version", "status")),
        Map.entry(EventType.POLICY_UPDATED, Set.of("policyId", "version", "status")),
        Map.entry(EventType.POLICY_ACTIVATED, Set.of("policyId", "version", "status")),
        Map.entry(EventType.RUNTIME_AUTHORIZATION_ALLOW, Set.of("agentId", "action", "reasonCode")),
        Map.entry(EventType.RUNTIME_AUTHORIZATION_DENY, Set.of("agentId", "action", "reasonCode")),
        Map.entry(EventType.TOOL_EXECUTION_SUCCEEDED, Set.of("agentId", "executionId", "action", "result")),
        Map.entry(EventType.TOOL_EXECUTION_FAILED, Set.of("agentId", "executionId", "action", "result")),
        Map.entry(EventType.AI_THREAT_DETECTED, Set.of("agentId", "analysisId", "category", "riskScore")),
        Map.entry(EventType.AGENT_TRUST_SCORE_UPDATED, Set.of("agentId", "score")));

    public SecurityEvent {
        if (eventId == null || organizationId == null || eventType == null || timestamp == null || correlationId == null)
            throw new IllegalArgumentException("Event envelope fields are required");
        if (schemaVersion < 1 || schemaVersion > 2) throw new IllegalArgumentException("Unsupported event schema version");
        metadata = Map.copyOf(metadata == null ? Map.of() : metadata);
        Set<String> expected = V1.get(eventType);
        if (schemaVersion == 2 && (eventType == EventType.RUNTIME_AUTHORIZATION_ALLOW || eventType == EventType.RUNTIME_AUTHORIZATION_DENY))
            expected = Set.of("agentId", "actorId", "actorType", "executionId", "action", "resourceId", "reasonCode");
        if (schemaVersion == 2 && (eventType == EventType.TOOL_EXECUTION_SUCCEEDED || eventType == EventType.TOOL_EXECUTION_FAILED))
            expected = Set.of("agentId", "actorId", "actorType", "executionId", "action", "resourceId", "result");
        if (!expected.equals(metadata.keySet())) throw new IllegalArgumentException("Event metadata does not match the required fields for " + eventType);
        if (metadata.entrySet().stream().anyMatch(e -> e.getValue() == null || e.getValue().length() > (e.getKey().equals("resourceId") ? 500 : 160)
                || e.getValue().contains("\n") || e.getValue().contains("\r")))
            throw new IllegalArgumentException("Invalid event metadata value");
        metadata.forEach(SecurityEvent::validateValue);
        if (metadata.containsKey("riskScore") && !integer(metadata.get("riskScore"), 0, 100)) throw new IllegalArgumentException("Invalid risk score");
        if (metadata.containsKey("score") && !integer(metadata.get("score"), 0, 100)) throw new IllegalArgumentException("Invalid trust score");
        if (metadata.containsKey("version") && !integer(metadata.get("version"), 1, Integer.MAX_VALUE)) throw new IllegalArgumentException("Invalid policy version");
    }

    public static SecurityEvent create(UUID org, EventType type, UUID correlation, Map<String, String> metadata) {
        return new SecurityEvent(UUID.randomUUID(), org, type, Instant.now(), correlation == null ? UUID.randomUUID() : correlation, 1, metadata);
    }
    public static SecurityEvent createV2(UUID org, EventType type, UUID correlation, Map<String, String> metadata) {
        return new SecurityEvent(UUID.randomUUID(), org, type, Instant.now(), correlation == null ? UUID.randomUUID() : correlation, 2, metadata);
    }
    private static boolean integer(String value, int min, int max) {
        try { int n = Integer.parseInt(value); return n >= min && n <= max; } catch (NumberFormatException ex) { return false; }
    }
    private static void validateValue(String key, String value) {
        if (Set.of("agentId", "actorId", "policyId", "executionId", "analysisId").contains(key)) {
            try { UUID.fromString(value); } catch (IllegalArgumentException ex) { throw new IllegalArgumentException("Invalid identifier metadata"); }
        } else if (key.equals("actorType")) {
            if (!Set.of("AGENT", "USER", "SERVICE").contains(value)) throw new IllegalArgumentException("Invalid actor type metadata");
        } else if (key.equals("resourceId")) {
            if (value.isBlank() || value.chars().anyMatch(Character::isISOControl)) throw new IllegalArgumentException("Invalid resource metadata");
        } else if (Set.of("status", "reasonCode", "result", "category").contains(key)) {
            if (!value.matches("[A-Z][A-Z0-9_:-]{0,79}")) throw new IllegalArgumentException("Invalid code metadata");
        } else if (key.equals("action") && !value.matches("[A-Za-z][A-Za-z0-9_.:-]{0,149}")) {
            throw new IllegalArgumentException("Invalid action metadata");
        }
    }
}
