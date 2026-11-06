package com.agentshield.agentmanagement.config;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class JwtConfiguration {

    @Bean
    JwtDecoder jwtDecoder(
            @Value("${agentshield.security.jwt.issuer}") String issuer,
            @Value("${agentshield.security.jwt.jwk-set-uri}") String jwkSetUri,
            @Value("${agentshield.security.jwt.audience}") String audience,
            @Value("${agentshield.security.runtime-gateway.client-id}") String gatewayClientId,
            Environment environment) {
        requireConfigured("IDENTITY_ISSUER", issuer);
        requireConfigured("IDENTITY_JWKS_URI", jwkSetUri);
        requireConfigured("AGENT_MANAGEMENT_AUDIENCE", audience);
        validateUrl(issuer, environment, "IDENTITY_ISSUER");
        validateUrl(jwkSetUri, environment, "IDENTITY_JWKS_URI");

        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer),
            audienceValidator(audience),
                requiredTenantClaims(gatewayClientId)));
        return decoder;
    }

    static OAuth2TokenValidator<Jwt> requiredTenantClaims(String gatewayClientId) {
        return jwt -> {
            try {
                if ("service".equals(jwt.getClaimAsString("identity_type"))) {
                    if (gatewayClientId.equals(jwt.getClaimAsString("client_id"))
                            && "service".equals(jwt.getClaimAsString("token_type"))
                            && "RUNTIME_GATEWAY".equals(jwt.getClaimAsString("service_role"))
                            && jwt.getSubject().equals(jwt.getClaimAsString("client_id"))
                            && jwt.getExpiresAt()!=null && hasScope(jwt, "agents.read")) return OAuth2TokenValidatorResult.success();
                    return invalidToken();
                }
                if ("agent".equals(jwt.getClaimAsString("identity_type"))) return invalidToken();
                String subject = jwt.getSubject();
                String userId = jwt.getClaimAsString("user_id");
                String organizationId = jwt.getClaimAsString("organization_id");
                String organizationRole = jwt.getClaimAsString("organization_role");
                if (subject == null || !subject.equals(userId) || organizationId == null || organizationRole == null
                        || jwt.getExpiresAt() == null) {
                    return invalidToken();
                }
                UUID.fromString(userId);
                UUID.fromString(organizationId);
                com.agentshield.agentmanagement.security.OrganizationRole.valueOf(organizationRole);
                return OAuth2TokenValidatorResult.success();
            } catch (RuntimeException exception) {
                return invalidToken();
            }
        };
    }

    private static boolean hasScope(Jwt jwt, String requiredScope) {
        Object scope = jwt.getClaims().get("scope");
        if (scope instanceof String value) {
            return java.util.Arrays.asList(value.split("\\s+")).contains(requiredScope);
        }
        if (scope instanceof java.util.Collection<?> values) {
            return values.contains(requiredScope);
        }
        return false;
    }

    private static OAuth2TokenValidator<Jwt> audienceValidator(String configured) {
        List<String> allowed=java.util.Arrays.stream(configured.split(",")).map(String::trim).filter(v->!v.isBlank()).toList();
        return jwt -> jwt.getAudience()!=null && jwt.getAudience().stream().anyMatch(allowed::contains)
                ? OAuth2TokenValidatorResult.success() : invalidToken();
    }

    private static OAuth2TokenValidatorResult invalidToken() {
        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", "Access token tenant claims are invalid", null));
    }

    private static void validateUrl(String value, Environment environment, String setting) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException(setting + " must be a valid absolute URL", exception);
        }
        String[] profiles = environment.getActiveProfiles();
        boolean development = profiles.length > 0
                && java.util.Arrays.stream(profiles).allMatch(p -> p.equals("local") || p.equals("test"));
        boolean loopback = "localhost".equalsIgnoreCase(uri.getHost())
                || "127.0.0.1".equals(uri.getHost()) || "::1".equals(uri.getHost())
                || "[::1]".equals(uri.getHost());
        boolean schemeAllowed = "https".equalsIgnoreCase(uri.getScheme())
                || development && loopback && "http".equalsIgnoreCase(uri.getScheme());
        if (!schemeAllowed || uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null
                || uri.getQuery() != null) {
            throw new IllegalStateException(setting + " must use HTTPS outside local/test");
        }
    }

    private static void requireConfigured(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Required authentication setting is missing: " + name);
        }
    }
}
