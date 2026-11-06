package com.agentshield.policyengine.policy.api;

import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import com.agentshield.policyengine.policy.domain.PolicyStatus;
import com.agentshield.policyengine.policy.service.PolicyEvaluationService;
import com.agentshield.policyengine.policy.service.PolicyService;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/policies")
@Validated
public class PolicyController {
    private final PolicyService service;
    private final PolicyEvaluationService evaluation;
    private final JwtDecoder agentAssertionJwtDecoder;
    public PolicyController(PolicyService service, PolicyEvaluationService evaluation,
            @org.springframework.beans.factory.annotation.Qualifier("agentAssertionJwtDecoder") JwtDecoder agentAssertionJwtDecoder) { this.service=service; this.evaluation=evaluation; this.agentAssertionJwtDecoder=agentAssertionJwtDecoder; }
    @PostMapping @ResponseStatus(HttpStatus.CREATED)
    public PolicyResponse create(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody PolicyDefinitionRequest request) { return service.create(org(jwt),request); }
    @GetMapping public List<PolicyResponse> list(@AuthenticationPrincipal Jwt jwt) { return service.list(org(jwt)); }
    @GetMapping("/{policyId}") public PolicyResponse get(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID policyId) { return service.get(org(jwt),policyId); }
    @PutMapping("/{policyId}") public PolicyResponse update(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID policyId,@Valid @RequestBody PolicyDefinitionRequest request) { return service.update(org(jwt),policyId,request); }
    @PatchMapping("/{policyId}/status") public PolicyResponse status(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID policyId,@Valid @RequestBody ChangePolicyStatusRequest request) { return service.changeStatus(org(jwt),policyId,request.status()); }
    @GetMapping("/{policyId}/versions") public List<PolicyVersionResponse> versions(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID policyId) { return service.versions(org(jwt),policyId); }
    @PostMapping("/evaluate") public EvaluationDecision evaluate(@AuthenticationPrincipal Jwt jwt,
            @RequestHeader("X-Agent-Assertion") String agentAssertion,@RequestHeader("X-Organization-ID") String tenantHeader,
            @Valid @RequestBody EvaluationRequest request) {
        try {
            Jwt agent=agentAssertionJwtDecoder.decode(agentAssertion);
            UUID organizationId=UUID.fromString(agent.getClaimAsString("organization_id"));
            if(!"agent".equals(agent.getClaimAsString("identity_type"))||!request.agentId().toString().equals(agent.getClaimAsString("agent_id"))
                    ||!request.agentId().toString().equals(agent.getSubject())
                    ||!organizationId.toString().equals(tenantHeader))
                throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.FORBIDDEN,"Agent identity mismatch");
            return evaluation.evaluate(organizationId,request);
        } catch(org.springframework.security.oauth2.jwt.JwtException|IllegalArgumentException exception) {
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED,"Agent assertion is invalid");
        }
    }
    private static UUID org(Jwt jwt) { return UUID.fromString(jwt.getClaimAsString("organization_id")); }
}
