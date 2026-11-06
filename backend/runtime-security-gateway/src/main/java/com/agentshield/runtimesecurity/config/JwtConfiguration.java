package com.agentshield.runtimesecurity.config;

import java.net.URI;
import java.time.Duration;
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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class JwtConfiguration {
    @Bean JwtDecoder jwtDecoder(@Value("${agentshield.security.jwt.jwk-set-uri}") String jwks,
            @Value("${agentshield.security.jwt.issuer}") String issuer,
            @Value("${agentshield.security.jwt.audience}") String audience,
            @Value("${agentshield.security.jwt.user-audience:agentshield-api}") String userAudience, Environment environment) {
        required(jwks,"IDENTITY_JWKS_URI"); required(issuer,"IDENTITY_ISSUER"); required(audience,"RUNTIME_SECURITY_GATEWAY_AUDIENCE");
        validateHttps(jwks,environment,"IDENTITY_JWKS_URI"); validateHttps(issuer,environment,"IDENTITY_ISSUER");
        NimbusJwtDecoder decoder=NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(validators(issuer,audience,userAudience));
        return decoder;
    }
    static org.springframework.security.oauth2.core.OAuth2TokenValidator<Jwt> validators(String issuer,String audience,String userAudience) {
        JwtTimestampValidator timestamps=new JwtTimestampValidator(Duration.ZERO);
        return new DelegatingOAuth2TokenValidator<>(new JwtIssuerValidator(issuer),timestamps,claimsValidator(audience,userAudience));
    }
    static OAuth2TokenValidator<Jwt> claimsValidator(String audience) {
        return claimsValidator(audience,"agentshield-api");
    }
    static OAuth2TokenValidator<Jwt> claimsValidator(String audience,String userAudience) {
        return jwt -> {
            try {
                if("user".equals(jwt.getClaimAsString("identity_type"))) {
                    String user=jwt.getClaimAsString("user_id"),org=jwt.getClaimAsString("organization_id"),role=jwt.getClaimAsString("organization_role");
                    if("user".equals(jwt.getClaimAsString("token_type"))&&user!=null&&user.equals(jwt.getSubject())&&org!=null
                            &&role!=null&&java.util.List.of("OWNER","ADMIN","MEMBER").contains(role)&&jwt.getAudience()!=null
                            &&jwt.getAudience().contains(userAudience)&&jwt.getExpiresAt()!=null) { UUID.fromString(user);UUID.fromString(org);return OAuth2TokenValidatorResult.success(); }
                    return invalid();
                }
                String subject=jwt.getSubject(), org=jwt.getClaimAsString("organization_id"), agent=jwt.getClaimAsString("agent_id");
                if(!"agent".equals(jwt.getClaimAsString("identity_type"))||!"agent".equals(jwt.getClaimAsString("token_type"))
                        ||!"AGENT".equals(jwt.getClaimAsString("agent_role"))||subject==null||!subject.equals(agent)
                        ||org==null||agent==null||jwt.getExpiresAt()==null||jwt.getAudience()==null||!jwt.getAudience().contains(audience)) return invalid();
                UUID.fromString(agent); UUID.fromString(org);
                return OAuth2TokenValidatorResult.success();
            } catch(RuntimeException exception) { return invalid(); }
        };
    }
    public static void validateHttps(String value,Environment environment,String setting) {
        URI uri;
        try { uri=URI.create(value); } catch(IllegalArgumentException ex) { throw new IllegalStateException(setting+" must be an absolute URL"); }
        String[] profiles=environment.getActiveProfiles();
        boolean local=profiles.length>0 && java.util.Arrays.stream(profiles).allMatch(p -> p.equals("local") || p.equals("test"));
        boolean loopback="localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "::1".equals(uri.getHost()) || "[::1]".equals(uri.getHost());
        boolean scheme="https".equalsIgnoreCase(uri.getScheme()) || local && loopback && "http".equalsIgnoreCase(uri.getScheme());
        if(!scheme || uri.getHost()==null || uri.getUserInfo()!=null || uri.getFragment()!=null || uri.getQuery()!=null)
            throw new IllegalStateException(setting+" must use HTTPS outside local/test");
    }
    private static void required(String value,String name) { if(value==null || value.isBlank()) throw new IllegalStateException("Required security setting is missing: "+name); }
    private static OAuth2TokenValidatorResult invalid() { return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Access token validation failed",null)); }
}
