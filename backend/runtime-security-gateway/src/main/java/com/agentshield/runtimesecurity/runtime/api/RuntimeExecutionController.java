package com.agentshield.runtimesecurity.runtime.api;

import java.util.UUID;
import java.time.Instant;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.agentshield.runtimesecurity.runtime.service.RuntimeExecutionService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/runtime")
@Validated
public class RuntimeExecutionController {
    private final RuntimeExecutionService service;
    public RuntimeExecutionController(RuntimeExecutionService service) { this.service=service; }
    @PostMapping("/execute")
    public ResponseEntity<RuntimeExecutionResponse> execute(@AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody RuntimeExecuteRequest request) {
        RuntimeExecutionService.ExecutionAttempt result=service.execute(
                UUID.fromString(jwt.getClaimAsString("organization_id")),
                UUID.fromString(jwt.getClaimAsString("agent_id")),jwt.getTokenValue(),request);
        return ResponseEntity.status(result.httpStatus()).body(result.response());
    }
    @GetMapping("/executions/{executionId}")
    public RuntimeExecutionResponse get(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID executionId) {
        return service.get(UUID.fromString(jwt.getClaimAsString("organization_id")),
                UUID.fromString(jwt.getClaimAsString("agent_id")),executionId);
    }

    @GetMapping("/history")
    public ExecutionHistoryPage history(@AuthenticationPrincipal Jwt jwt,
            @RequestParam(defaultValue="0") int page, @RequestParam(defaultValue="20") int size,
            @RequestParam(required=false) UUID agentId, @RequestParam(required=false) String outcome,
            @RequestParam(required=false) String decision, @RequestParam(required=false) Instant from,
            @RequestParam(required=false) Instant to) {
        if (page < 0 || size < 1 || size > 100 || (from != null && to != null && from.isAfter(to)))
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,"Invalid history filters");
        UUID organization=requiredUuid(jwt,"organization_id");
        ExecutionHistoryPage result=service.history(organization,agentId,outcome,decision,from,to,PageRequest.of(page,size,Sort.by(Sort.Direction.DESC,"createdAt")));
        return result;
    }

    @GetMapping("/history/{executionId}")
    public ExecutionHistoryItem historyDetail(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID executionId) {
        return service.historyDetail(requiredUuid(jwt,"organization_id"),executionId);
    }

    private static UUID requiredUuid(Jwt jwt,String claim) {
        try { return UUID.fromString(jwt.getClaimAsString(claim)); }
        catch(RuntimeException ex) { throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.FORBIDDEN,"Tenant context is invalid"); }
    }
}
