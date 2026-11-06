package com.agentshield.identity.agentcredential.api;

import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import com.agentshield.identity.agentcredential.AgentCredentialService;

@RestController
@RequestMapping("/api/v1/organizations/{organizationId}/agents/{agentId}/credentials")
public class AgentCredentialController {
    private final AgentCredentialService service;
    public AgentCredentialController(AgentCredentialService service){this.service=service;}
    @PostMapping @ResponseStatus(HttpStatus.CREATED)
    public AgentCredentialResponse issue(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID agentId) {
        requireAdminTenant(jwt,organizationId);
        try { return service.issue(agentId,organizationId,jwt.getTokenValue()); }
        catch(IllegalArgumentException exception){throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Active agent was not found in organization");}
    }
    @DeleteMapping("/{credentialId}") @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID organizationId,@PathVariable UUID agentId,@PathVariable UUID credentialId) {
        requireAdminTenant(jwt,organizationId);
        try { service.revoke(credentialId,agentId,organizationId); }
        catch(IllegalArgumentException exception){throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Credential was not found");}
    }
    private static void requireAdminTenant(Jwt jwt,UUID organizationId) {
        if(jwt==null || !organizationId.toString().equals(jwt.getClaimAsString("organization_id"))
                || !java.util.List.of("OWNER","ADMIN").contains(jwt.getClaimAsString("organization_role")))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Organization administrator required");
    }
}
