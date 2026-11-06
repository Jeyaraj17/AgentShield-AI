package com.agentshield.policyengine.config;

import java.net.URI;
import java.util.Arrays;
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
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class JwtConfiguration {
    @Bean JwtDecoder jwtDecoder(@Value("${agentshield.security.jwt.jwk-set-uri}") String jwks,
            @Value("${agentshield.security.jwt.issuer}") String issuer,
            @Value("${agentshield.security.jwt.audience}") String userAudiences,
            @Value("${agentshield.security.jwt.gateway-audience}") String gatewayAudience,
            @Value("${agentshield.security.runtime-gateway-client-id:}") String gatewayClient,Environment environment) {
        require(jwks,"IDENTITY_JWKS_URI"); require(issuer,"IDENTITY_ISSUER"); require(userAudiences,"POLICY_ENGINE_ALLOWED_AUDIENCES");
        require(gatewayAudience,"POLICY_ENGINE_AUDIENCE"); require(gatewayClient,"RUNTIME_GATEWAY_CLIENT_ID");
        validateUrl(jwks,environment,"IDENTITY_JWKS_URI"); validateUrl(issuer,environment,"IDENTITY_ISSUER");
        NimbusJwtDecoder decoder=NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                gatewayOrUserClaims(userAudiences,gatewayAudience,gatewayClient)));
        return decoder;
    }
    @Bean(name="agentAssertionJwtDecoder") JwtDecoder agentAssertionJwtDecoder(@Value("${agentshield.security.jwt.jwk-set-uri}") String jwks,
            @Value("${agentshield.security.jwt.issuer}") String issuer,@Value("${agentshield.security.jwt.agent-audience}") String audience,Environment environment) {
        require(jwks,"IDENTITY_JWKS_URI"); require(issuer,"IDENTITY_ISSUER"); require(audience,"AGENT_TOKEN_AUDIENCE"); validateUrl(jwks,environment,"IDENTITY_JWKS_URI");
        NimbusJwtDecoder decoder=NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),agentClaims(audience)));
        return decoder;
    }
    static OAuth2TokenValidator<Jwt> gatewayOrUserClaims(String userAudiences,String gatewayAudience,String gatewayClient) {
        return jwt -> {
            if("service".equals(jwt.getClaimAsString("identity_type"))) {
                boolean valid=gatewayClient.equals(jwt.getClaimAsString("client_id"))&&gatewayClient.equals(jwt.getSubject())
                        &&"service".equals(jwt.getClaimAsString("token_type"))&&"RUNTIME_GATEWAY".equals(jwt.getClaimAsString("service_role"))
                        &&hasAudience(jwt,gatewayAudience)&&jwt.getExpiresAt()!=null&&hasScope(jwt,"policy.evaluate");
                return valid?OAuth2TokenValidatorResult.success():invalid();
            }
            Object user=jwt.getClaims().get("user_id"),org=jwt.getClaims().get("organization_id"),role=jwt.getClaims().get("organization_role");
            boolean valid="user".equals(jwt.getClaimAsString("identity_type"))&&hasAudience(jwt,userAudiences)
                    &&user instanceof String u&&u.equals(jwt.getSubject())&&jwt.getExpiresAt()!=null&&uuid(user)&&uuid(org)
                    &&role instanceof String r&&List.of("OWNER","ADMIN","MEMBER").contains(r);
            return valid?OAuth2TokenValidatorResult.success():invalid();
        };
    }
    private static boolean hasScope(Jwt jwt,String requiredScope) {
        Object scope=jwt.getClaims().get("scope");
        if(scope instanceof String value)return Arrays.asList(value.split("\\s+")).contains(requiredScope);
        if(scope instanceof java.util.Collection<?> values)return values.contains(requiredScope);
        return false;
    }
    private static OAuth2TokenValidator<Jwt> agentClaims(String audience) {
        return jwt -> "agent".equals(jwt.getClaimAsString("identity_type"))&&"agent".equals(jwt.getClaimAsString("token_type"))
                &&"AGENT".equals(jwt.getClaimAsString("agent_role"))&&uuid(jwt.getClaimAsString("agent_id"))
                &&jwt.getSubject()!=null&&jwt.getSubject().equals(jwt.getClaimAsString("agent_id"))
                &&uuid(jwt.getClaimAsString("organization_id"))&&jwt.getAudience().contains(audience)&&jwt.getExpiresAt()!=null
                ?OAuth2TokenValidatorResult.success():invalid();
    }
    private static boolean hasAudience(Jwt jwt,String configured){return jwt.getAudience()!=null&&jwt.getAudience().stream().anyMatch(Arrays.asList(configured.split(","))::contains);}
    private static boolean uuid(Object value){try{UUID.fromString((String)value);return true;}catch(RuntimeException ex){return false;}}
    private static OAuth2TokenValidatorResult invalid(){return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Token identity or audience is invalid",null));}
    private static void require(String value,String name){if(value==null||value.isBlank())throw new IllegalStateException(name+" must be configured");}
    private static void validateUrl(String value,Environment env,String name){URI u;try{u=URI.create(value);}catch(IllegalArgumentException e){throw new IllegalStateException(name+" must be an absolute URL");}
        String[] p=env.getActiveProfiles();boolean local=p.length>0&&Arrays.stream(p).allMatch(x->x.equals("local")||x.equals("test"));
        boolean loop="localhost".equalsIgnoreCase(u.getHost())||"127.0.0.1".equals(u.getHost())||"::1".equals(u.getHost())||"[::1]".equals(u.getHost());
        if(u.getHost()==null||u.getUserInfo()!=null||u.getQuery()!=null||u.getFragment()!=null||!("https".equalsIgnoreCase(u.getScheme())||local&&loop&&"http".equalsIgnoreCase(u.getScheme())))throw new IllegalStateException(name+" must use HTTPS outside local/test");}
}
