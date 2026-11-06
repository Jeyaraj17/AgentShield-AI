package com.agentshield.agentmanagement.agent.api;

import java.util.UUID;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.agentshield.agentmanagement.agent.domain.AgentStatus;
import com.agentshield.agentmanagement.agent.service.AgentService;
import com.agentshield.agentmanagement.security.TenantContext;

@Validated
@RestController
@RequestMapping("/api/v1/agents")
public class AgentController {

    private final AgentService agentService;

    public AgentController(AgentService agentService) {
        this.agentService = agentService;
    }

    @PostMapping
    public ResponseEntity<AgentResponse> register(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody CreateAgentRequest request) {
        AgentResponse response = agentService.register(TenantContext.from(jwt).organizationId(), request);
        var location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
                .buildAndExpand(response.id()).toUri();
        return ResponseEntity.created(location).body(response);
    }

    @GetMapping
    public AgentPageResponse list(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        return agentService.list(TenantContext.from(jwt).organizationId(), page, size);
    }

    @GetMapping("/{agentId}")
    public AgentResponse get(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID agentId) {
        return agentService.get(TenantContext.from(jwt).organizationId(), agentId);
    }

    @PutMapping("/{agentId}")
    public AgentResponse update(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID agentId,
            @Valid @RequestBody UpdateAgentRequest request) {
        return agentService.update(TenantContext.from(jwt).organizationId(), agentId, request);
    }

    @PatchMapping("/{agentId}/status")
    public AgentResponse changeStatus(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID agentId,
            @Valid @RequestBody ChangeAgentStatusRequest request) {
        return agentService.changeStatus(TenantContext.from(jwt).organizationId(), agentId, request.status());
    }

    @DeleteMapping("/{agentId}")
    public ResponseEntity<Void> deactivate(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID agentId) {
        agentService.deactivate(TenantContext.from(jwt).organizationId(), agentId);
        return ResponseEntity.noContent().build();
    }
}
