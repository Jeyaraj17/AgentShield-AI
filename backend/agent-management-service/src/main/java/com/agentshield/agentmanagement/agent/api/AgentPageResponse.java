package com.agentshield.agentmanagement.agent.api;

import java.util.List;

import org.springframework.data.domain.Page;

public record AgentPageResponse(
        List<AgentResponse> content,
        int page,
        int size,
        long totalElements,
        int totalPages) {

    public static AgentPageResponse from(Page<AgentResponse> page) {
        return new AgentPageResponse(page.getContent(), page.getNumber(), page.getSize(),
                page.getTotalElements(), page.getTotalPages());
    }
}
