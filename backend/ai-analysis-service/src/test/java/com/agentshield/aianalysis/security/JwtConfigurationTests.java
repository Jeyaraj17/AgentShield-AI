package com.agentshield.aianalysis.security;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

class JwtConfigurationTests {
    private final UUID org=UUID.randomUUID(),user=UUID.randomUUID(),agent=UUID.randomUUID();
    @Test void resourceApiAcceptsOnlyVerifiedUserOrDedicatedGatewayClaims() {
        var validGateway=token("runtime-gateway-analysis").audience(List.of("analysis-api")).claim("identity_type","service")
                .claim("token_type","service").claim("client_id","runtime-gateway-analysis").claim("service_role","RUNTIME_GATEWAY_ANALYSIS")
                .claim("scope",List.of("analysis.evaluate")).build();
        assertTrue(ok(JwtConfiguration.gatewayOrUser("agentshield-api","analysis-api","runtime-gateway-analysis").validate(validGateway)));
        var missingScope=Jwt.withTokenValue("t").header("alg","RS256").issuer("https://id.example").subject("runtime-gateway-analysis")
                .audience(List.of("analysis-api")).issuedAt(Instant.now().minusSeconds(1)).expiresAt(Instant.now().plusSeconds(30))
                .claim("identity_type","service").claim("token_type","service").claim("client_id","runtime-gateway-analysis")
                .claim("service_role","RUNTIME_GATEWAY_ANALYSIS").claim("scope",List.of("agents.read")).build();
        assertFalse(ok(JwtConfiguration.gatewayOrUser("agentshield-api","analysis-api","runtime-gateway-analysis").validate(missingScope)));
        var wrongAudience=Jwt.withTokenValue("t").header("alg","RS256").issuer("https://id.example").subject("runtime-gateway-analysis")
                .audience(List.of("policy-engine-api")).issuedAt(Instant.now().minusSeconds(1)).expiresAt(Instant.now().plusSeconds(30))
                .claim("identity_type","service").claim("token_type","service").claim("client_id","runtime-gateway-analysis")
                .claim("service_role","RUNTIME_GATEWAY_ANALYSIS").claim("scope",List.of("analysis.evaluate")).build();
        assertFalse(ok(JwtConfiguration.gatewayOrUser("agentshield-api","analysis-api","runtime-gateway-analysis").validate(wrongAudience)));
        var wrongRole=Jwt.withTokenValue("t").header("alg","RS256").issuer("https://id.example").subject("runtime-gateway")
                .audience(List.of("analysis-api")).issuedAt(Instant.now().minusSeconds(1)).expiresAt(Instant.now().plusSeconds(30))
                .claim("identity_type","service").claim("token_type","service").claim("client_id","runtime-gateway").claim("service_role","ADMIN")
                .claim("scope",List.of("analysis.evaluate")).build();
        assertFalse(ok(JwtConfiguration.gatewayOrUser("agentshield-api","analysis-api","runtime-gateway-analysis").validate(wrongRole)));
        var validUser=token(user.toString()).audience(List.of("agentshield-api")).claim("identity_type","user").claim("token_type","user").claim("user_id",user.toString())
                .claim("organization_id",org.toString()).claim("organization_role","ADMIN").build();
        assertTrue(ok(JwtConfiguration.gatewayOrUser("agentshield-api","analysis-api","runtime-gateway-analysis").validate(validUser)));
        var missingTenant=token(user.toString()).audience(List.of("agentshield-api")).claim("identity_type","user").claim("token_type","user").claim("user_id",user.toString())
                .claim("organization_role","ADMIN").build();
        assertFalse(ok(JwtConfiguration.gatewayOrUser("agentshield-api","analysis-api","runtime-gateway-analysis").validate(missingTenant)));
    }
    @Test void signedAgentAssertionMustHaveTypeAudienceAndOrganization() {
        var valid=token(agent.toString()).audience(List.of("runtime-agent-api")).claim("identity_type","agent").claim("token_type","agent")
                .claim("agent_role","AGENT").claim("agent_id",agent.toString()).claim("organization_id",org.toString()).build();
        assertTrue(ok(JwtConfiguration.agentClaims("runtime-agent-api").validate(valid)));
        var missingOrg=token(agent.toString()).audience(List.of("runtime-agent-api")).claim("identity_type","agent").claim("token_type","agent")
                .claim("agent_role","AGENT").claim("agent_id",agent.toString()).build();
        assertFalse(ok(JwtConfiguration.agentClaims("runtime-agent-api").validate(missingOrg)));
        assertFalse(ok(JwtConfiguration.agentClaims("other-audience").validate(valid)));
    }
    private Jwt.Builder token(String subject){return Jwt.withTokenValue("t").header("alg","RS256").issuer("https://id.example").subject(subject)
            .issuedAt(Instant.now().minusSeconds(1)).expiresAt(Instant.now().plusSeconds(30));}
    private boolean ok(OAuth2TokenValidatorResult result){return result.getErrors().isEmpty();}
}
