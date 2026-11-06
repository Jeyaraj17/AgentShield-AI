package com.agentshield.aianalysis.security;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

@Configuration
public class JwtConfiguration {
    @Bean JwtDecoder jwtDecoder(@Value("${agentshield.security.jwt.jwk-set-uri}") String jwks,
            @Value("${agentshield.security.jwt.issuer}") String issuer,
            @Value("${agentshield.security.jwt.user-audiences}") String userAudiences,
            @Value("${agentshield.security.jwt.gateway-audience}") String gatewayAudience,
            @Value("${agentshield.security.runtime-gateway.analysis-client-id}") String gatewayClient, Environment env) {
        require(jwks,"IDENTITY_JWKS_URI"); require(issuer,"IDENTITY_ISSUER"); require(userAudiences,"AI_ANALYSIS_ALLOWED_AUDIENCES");
        require(gatewayAudience,"AI_ANALYSIS_GATEWAY_AUDIENCE"); require(gatewayClient,"RUNTIME_GATEWAY_ANALYSIS_CLIENT_ID");
        validateUrl(jwks,env,"IDENTITY_JWKS_URI"); validateUrl(issuer,env,"IDENTITY_ISSUER");
        NimbusJwtDecoder decoder=NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),
                gatewayOrUser(userAudiences,gatewayAudience,gatewayClient)));
        return decoder;
    }

    @Bean(name="agentAssertionJwtDecoder") JwtDecoder agentAssertionJwtDecoder(
            @Value("${agentshield.security.jwt.jwk-set-uri}") String jwks,
            @Value("${agentshield.security.jwt.issuer}") String issuer,
            @Value("${agentshield.security.jwt.agent-audience}") String audience, Environment env) {
        require(jwks,"IDENTITY_JWKS_URI"); require(issuer,"IDENTITY_ISSUER"); require(audience,"AGENT_TOKEN_AUDIENCE");
        validateUrl(jwks,env,"IDENTITY_JWKS_URI"); validateUrl(issuer,env,"IDENTITY_ISSUER");
        NimbusJwtDecoder decoder=NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),agentClaims(audience)));
        return decoder;
    }

    @Bean Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        return jwt -> {
            String identity=jwt.getClaimAsString("identity_type");
            if("service".equals(identity)) return new JwtAuthenticationToken(jwt,
                    List.of(new SimpleGrantedAuthority("ROLE_RUNTIME_GATEWAY_ANALYSIS")),jwt.getSubject());
            String role=jwt.getClaimAsString("organization_role");
            return new JwtAuthenticationToken(jwt,List.of(new SimpleGrantedAuthority("ROLE_"+role)),jwt.getSubject());
        };
    }

    static OAuth2TokenValidator<Jwt> gatewayOrUser(String userAudiences,String gatewayAudience,String gatewayClient) {
        return jwt -> {
            if("service".equals(jwt.getClaimAsString("identity_type"))) {
                boolean valid=gatewayClient.equals(jwt.getSubject())&&gatewayClient.equals(jwt.getClaimAsString("client_id"))
                        &&"service".equals(jwt.getClaimAsString("token_type"))
                        &&"RUNTIME_GATEWAY_ANALYSIS".equals(jwt.getClaimAsString("service_role"))
                        &&hasAudience(jwt,gatewayAudience)&&hasOnlyScope(jwt,"analysis.evaluate")&&jwt.getExpiresAt()!=null;
                return valid?OAuth2TokenValidatorResult.success():invalid();
            }
            String user=jwt.getClaimAsString("user_id"),org=jwt.getClaimAsString("organization_id"),role=jwt.getClaimAsString("organization_role");
            boolean valid="user".equals(jwt.getClaimAsString("identity_type"))&&"user".equals(jwt.getClaimAsString("token_type"))&&user!=null&&user.equals(jwt.getSubject())
                    &&uuid(user)&&uuid(org)&&role!=null&&List.of("OWNER","ADMIN","MEMBER").contains(role)
                    &&hasAudience(jwt,userAudiences)&&jwt.getExpiresAt()!=null;
            return valid?OAuth2TokenValidatorResult.success():invalid();
        };
    }

    static OAuth2TokenValidator<Jwt> agentClaims(String audience) {
        return jwt -> {
            String agent=jwt.getClaimAsString("agent_id"),org=jwt.getClaimAsString("organization_id");
            boolean valid="agent".equals(jwt.getClaimAsString("identity_type"))&&"agent".equals(jwt.getClaimAsString("token_type"))
                    &&"AGENT".equals(jwt.getClaimAsString("agent_role"))&&uuid(agent)&&agent.equals(jwt.getSubject())
                    &&uuid(org)&&jwt.getExpiresAt()!=null&&jwt.getAudience()!=null&&jwt.getAudience().contains(audience);
            return valid?OAuth2TokenValidatorResult.success():invalid();
        };
    }

    static void validateUrl(String value,Environment env,String setting) {
        URI uri; try { uri=URI.create(value); } catch(RuntimeException ex) { throw new IllegalStateException(setting+" must be an absolute URL"); }
        String[] profiles=env.getActiveProfiles(); boolean local=profiles.length>0&&Arrays.stream(profiles).allMatch(p->p.equals("local")||p.equals("test"));
        boolean loop="localhost".equalsIgnoreCase(uri.getHost())||"127.0.0.1".equals(uri.getHost())||"::1".equals(uri.getHost())||"[::1]".equals(uri.getHost());
        boolean allowed="https".equalsIgnoreCase(uri.getScheme())||(local&&loop&&"http".equalsIgnoreCase(uri.getScheme()));
        if(!allowed||uri.getHost()==null||uri.getUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null)
            throw new IllegalStateException(setting+" must use HTTPS outside local/test");
    }
    private static boolean hasAudience(Jwt jwt,String configured) { return jwt.getAudience()!=null&&jwt.getAudience().stream().anyMatch(Arrays.asList(configured.split(","))::contains); }
    private static boolean hasOnlyScope(Jwt jwt,String expected) {
        Object raw=jwt.getClaims().get("scope");
        if(raw instanceof String value) return Arrays.stream(value.split("\\s+")).filter(s->!s.isBlank()).toList().equals(List.of(expected));
        if(raw instanceof List<?> values) return values.size()==1&&expected.equals(values.getFirst());
        return false;
    }
    private static boolean uuid(String value) { try { UUID.fromString(value); return true; } catch(RuntimeException ex) { return false; } }
    private static void require(String value,String name) { if(value==null||value.isBlank()) throw new IllegalStateException("Required security setting is missing: "+name); }
    private static OAuth2TokenValidatorResult invalid() { return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Token identity or audience is invalid",null)); }
}
