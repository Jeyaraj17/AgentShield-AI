package com.agentshield.agentmanagement.agent.api;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.agentshield.agentmanagement.agent.service.AgentService;

/** Narrow internal lookup used by the Runtime Security Gateway. */
@RestController
@RequestMapping("/internal/v1/agents")
public class InternalAgentDirectoryController {

    private final AgentService agentService;

    public InternalAgentDirectoryController(AgentService agentService) {
        this.agentService = agentService;
    }

    @GetMapping("/{agentId}")
    public AgentResponse get(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID agentId,
            @RequestHeader("X-Organization-ID") String organizationHeader) {
        try {
            UUID organizationId = UUID.fromString(organizationHeader);
            if (!"service".equals(jwt.getClaimAsString("identity_type"))
                    || !"service".equals(jwt.getClaimAsString("token_type"))
                    || !"RUNTIME_GATEWAY".equals(jwt.getClaimAsString("service_role"))) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN);
            }
            return agentService.get(organizationId, agentId);
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }
}
