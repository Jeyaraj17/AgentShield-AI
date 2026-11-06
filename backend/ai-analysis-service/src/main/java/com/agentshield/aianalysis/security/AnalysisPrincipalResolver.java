package com.agentshield.aianalysis.security;

import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
public class AnalysisPrincipalResolver {
    private final JwtDecoder assertionDecoder;
    private final String gatewayClient;
    public AnalysisPrincipalResolver(@org.springframework.beans.factory.annotation.Qualifier("agentAssertionJwtDecoder") JwtDecoder assertionDecoder,
            @Value("${agentshield.security.runtime-gateway.analysis-client-id}") String gatewayClient) { this.assertionDecoder=assertionDecoder; this.gatewayClient=gatewayClient; }

    public AnalysisPrincipal forGateway(Jwt gateway,String assertion,String organizationHeader,String agentHeader) {
        if(!"service".equals(gateway.getClaimAsString("identity_type"))||!gatewayClient.equals(gateway.getClaimAsString("client_id"))
                ||!gatewayClient.equals(gateway.getSubject())||!"RUNTIME_GATEWAY_ANALYSIS".equals(gateway.getClaimAsString("service_role")))
            throw new ResponseStatusException(FORBIDDEN,"Gateway identity required");
        try {
            Jwt agent=assertionDecoder.decode(assertion);
            UUID agentId=UUID.fromString(agent.getClaimAsString("agent_id"));
            UUID orgId=UUID.fromString(agent.getClaimAsString("organization_id"));
            UUID forwardedAgent=UUID.fromString(agentHeader),forwardedOrganization=UUID.fromString(organizationHeader);
            if(!"agent".equals(agent.getClaimAsString("identity_type"))||!"agent".equals(agent.getClaimAsString("token_type"))
                    ||!"AGENT".equals(agent.getClaimAsString("agent_role"))||!agentId.toString().equals(agent.getSubject())
                    ||!agentId.equals(forwardedAgent)||!orgId.equals(forwardedOrganization))
                throw new ResponseStatusException(FORBIDDEN,"Agent assertion mismatch");
            return new AnalysisPrincipal(orgId,agentId);
        } catch(ResponseStatusException e) { throw e; }
        catch(RuntimeException e) { throw new ResponseStatusException(UNAUTHORIZED,"Agent assertion is invalid"); }
    }

    public UUID organizationFromUser(Jwt jwt) {
        if(!"user".equals(jwt.getClaimAsString("identity_type"))||!"user".equals(jwt.getClaimAsString("token_type"))) throw new ResponseStatusException(FORBIDDEN,"User identity required");
        try {
            UUID user=UUID.fromString(jwt.getClaimAsString("user_id"));
            if(!user.toString().equals(jwt.getSubject())||!java.util.List.of("OWNER","ADMIN","MEMBER").contains(jwt.getClaimAsString("organization_role"))) throw new IllegalArgumentException();
            return UUID.fromString(jwt.getClaimAsString("organization_id"));
        }
        catch(RuntimeException e) { throw new ResponseStatusException(FORBIDDEN,"Tenant context is invalid"); }
    }
}
