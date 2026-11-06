package com.agentshield.agentmanagement.agent.service;

public class DuplicateAgentCodeException extends RuntimeException {
    public DuplicateAgentCodeException(String agentCode) {
        super("Agent code is already in use in this organization: " + agentCode);
    }
}
