package com.agentshield.apigateway.config;

import java.net.URI;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class JwtConfiguration {
    @Bean
    ReactiveJwtDecoder jwtDecoder(@Value("${agentshield.security.jwt.jwk-set-uri}") String jwksUri,
                          @Value("${agentshield.security.jwt.issuer}") String issuer,
                          @Value("${agentshield.security.jwt.audience}") String audience,
                          @Value("${agentshield.security.jwt.agent-audience}") String agentAudience,
                          Environment environment) {
        requireValue(jwksUri, "IDENTITY_JWKS_URI");
        requireValue(issuer, "IDENTITY_ISSUER");
        requireValue(audience, "API_GATEWAY_AUDIENCE");
        requireValue(agentAudience, "API_GATEWAY_AGENT_AUDIENCE");
        validateSecureUrl(jwksUri, environment, "IDENTITY_JWKS_URI");
        validateSecureUrl(issuer, environment, "IDENTITY_ISSUER");
        org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder decoder = org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder.withJwkSetUri(jwksUri)
                .jwsAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer), tenantClaimsValidator(audience, agentAudience)));
        return decoder;
    }

    static OAuth2TokenValidator<Jwt> tenantClaimsValidator(String userAudience, String agentAudience) {
        return jwt -> {
            try {
                String subject=jwt.getSubject();
                String organizationId=jwt.getClaimAsString("organization_id");
                if (subject==null || organizationId==null || jwt.getExpiresAt()==null || jwt.getAudience()==null) return invalid();
                UUID.fromString(organizationId);
                String identityType=jwt.getClaimAsString("identity_type");
                if ("user".equals(identityType)) {
                    String userId=jwt.getClaimAsString("user_id");
                    String role=jwt.getClaimAsString("organization_role");
                    if (!subject.equals(userId) || !jwt.getAudience().contains(userAudience)
                            || !List.of("OWNER","ADMIN","MEMBER").contains(role)) return invalid();
                    UUID.fromString(userId);
                } else if ("agent".equals(identityType)) {
                    String agentId=jwt.getClaimAsString("agent_id");
                    if (!subject.equals(agentId) || !"AGENT".equals(jwt.getClaimAsString("agent_role"))
                            || !"agent".equals(jwt.getClaimAsString("token_type"))
                            || !jwt.getAudience().contains(agentAudience)) return invalid();
                    UUID.fromString(agentId);
                } else return invalid();
                return OAuth2TokenValidatorResult.success();
            } catch (RuntimeException exception) { return invalid(); }
        };
    }

    static void validateSecureUrl(String value, Environment environment, String setting) {
        URI uri;
        try { uri=URI.create(value); } catch (IllegalArgumentException exception) { throw new IllegalStateException(setting+" must be an absolute URL"); }
        String[] profiles=environment.getActiveProfiles();
        boolean local=profiles.length>0 && java.util.Arrays.stream(profiles).allMatch(p -> p.equals("local") || p.equals("test"));
        boolean loopback="localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost())
                || "::1".equals(uri.getHost()) || "[::1]".equals(uri.getHost());
        boolean scheme="https".equalsIgnoreCase(uri.getScheme()) || local && loopback && "http".equalsIgnoreCase(uri.getScheme());
        if (!scheme || uri.getHost()==null || uri.getUserInfo()!=null || uri.getQuery()!=null || uri.getFragment()!=null)
            throw new IllegalStateException(setting+" must use HTTPS outside local/test");
    }
    private static void requireValue(String value,String setting) {
        if (value==null || value.isBlank()) throw new IllegalStateException("Required security setting is missing: "+setting);
    }
    private static OAuth2TokenValidatorResult invalid() {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Access token validation failed",null));
    }
}
