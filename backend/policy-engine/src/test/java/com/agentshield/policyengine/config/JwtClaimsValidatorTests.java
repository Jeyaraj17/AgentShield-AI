package com.agentshield.policyengine.config;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class JwtClaimsValidatorTests {
    @Test void requiresVerifiedTenantClaimsAndExpiry() {
        UUID user=UUID.randomUUID(), org=UUID.randomUUID(); Instant now=Instant.now();
        Jwt complete=Jwt.withTokenValue("x").header("alg","RS256").subject(user.toString()).audience(List.of("agentshield-api"))
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(20)).claim("user_id",user.toString())
                .claim("organization_id",org.toString()).claim("organization_role","MEMBER").claim("identity_type","user").build();
        assertTrue(JwtConfiguration.gatewayOrUserClaims("agentshield-api","policy-engine-api","runtime-gateway").validate(complete).getErrors().isEmpty());
        Jwt missing=Jwt.withTokenValue("x").header("alg","RS256").subject(user.toString()).audience(List.of("agentshield-api"))
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(20)).claim("organization_role","MEMBER").build();
        assertFalse(JwtConfiguration.gatewayOrUserClaims("agentshield-api","policy-engine-api","runtime-gateway").validate(missing).getErrors().isEmpty());
    }

    @Test void onlyConfiguredRuntimeGatewayServiceClaimIsAcceptedOutsideTenantUserClaims() {
        Instant now=Instant.now();
        Jwt gateway=Jwt.withTokenValue("gateway").header("alg","RS256").issuer("https://identity.example.test")
                .subject("runtime-gateway").audience(List.of("policy-engine-api")).issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(30))
                .claim("identity_type","service").claim("token_type","service").claim("client_id","runtime-gateway")
                .claim("service_role","RUNTIME_GATEWAY").claim("scope","policy.evaluate").build();
        assertTrue(JwtConfiguration.gatewayOrUserClaims("agentshield-api","policy-engine-api","runtime-gateway").validate(gateway).getErrors().isEmpty());
        Jwt wrongClient=Jwt.withTokenValue("wrong").header("alg","RS256").issuer("https://identity.example.test")
                .subject("other-client").audience(List.of("policy-engine-api")).issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(30))
                .claim("identity_type","service").claim("token_type","service").claim("client_id","other-client")
                .claim("service_role","RUNTIME_GATEWAY").build();
        assertFalse(JwtConfiguration.gatewayOrUserClaims("agentshield-api","policy-engine-api","runtime-gateway").validate(wrongClient).getErrors().isEmpty());
        Jwt agent=Jwt.withTokenValue("agent").header("alg","RS256").issuer("https://identity.example.test")
                .subject(UUID.randomUUID().toString()).audience(List.of("policy-engine-api")).issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(30))
                .claim("identity_type","agent").claim("agent_id",UUID.randomUUID().toString()).claim("organization_id",UUID.randomUUID().toString()).build();
        assertFalse(JwtConfiguration.gatewayOrUserClaims("agentshield-api","policy-engine-api","runtime-gateway").validate(agent).getErrors().isEmpty());
    }

    @Test void gatewayMustHaveEvaluationScopeAndExactServiceRole() {
        Instant now=Instant.now();
        Jwt missingScope=Jwt.withTokenValue("missing-scope").header("alg","RS256").issuer("https://identity.example.test")
                .subject("runtime-gateway").audience(List.of("policy-engine-api")).issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(30))
                .claim("identity_type","service").claim("token_type","service").claim("client_id","runtime-gateway")
                .claim("service_role","RUNTIME_GATEWAY").build();
        assertFalse(JwtConfiguration.gatewayOrUserClaims("agentshield-api","policy-engine-api","runtime-gateway").validate(missingScope).getErrors().isEmpty());
        Jwt wrongRole=Jwt.withTokenValue("wrong-role").header("alg","RS256").issuer("https://identity.example.test")
                .subject("runtime-gateway").audience(List.of("policy-engine-api")).issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(30))
                .claim("identity_type","service").claim("token_type","service").claim("client_id","runtime-gateway")
                .claim("service_role","OTHER_SERVICE").claim("scope","policy.evaluate").build();
        assertFalse(JwtConfiguration.gatewayOrUserClaims("agentshield-api","policy-engine-api","runtime-gateway").validate(wrongRole).getErrors().isEmpty());
    }

    @Test void gatewayServiceTokenMustUseConfiguredPolicyAudience() {
        Instant now=Instant.now();
        Jwt gateway=Jwt.withTokenValue("gateway").header("alg","RS256").issuer("https://identity.example.test")
                .subject("runtime-gateway").audience(List.of("custom-policy-audience"))
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(30))
                .claim("identity_type","service").claim("token_type","service").claim("client_id","runtime-gateway")
                .claim("service_role","RUNTIME_GATEWAY").claim("scope","policy.evaluate").build();
        assertTrue(JwtConfiguration.gatewayOrUserClaims("agentshield-api","custom-policy-audience","runtime-gateway").validate(gateway).getErrors().isEmpty());
        assertFalse(JwtConfiguration.gatewayOrUserClaims("agentshield-api","policy-engine-api","runtime-gateway").validate(gateway).getErrors().isEmpty());
    }
}
