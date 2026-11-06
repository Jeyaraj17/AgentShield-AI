package com.agentshield.audit.config;

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
    @Bean JwtDecoder jwtDecoder(@Value("${agentshield.security.jwt.issuer}") String issuer,
            @Value("${agentshield.security.jwt.jwk-set-uri}") String jwks,
            @Value("${agentshield.security.jwt.audience}") String audiences,Environment environment) {
        required("IDENTITY_ISSUER",issuer);required("IDENTITY_JWKS_URI",jwks);required("AUDIT_SERVICE_AUDIENCE",audiences);
        httpsOrLocal(issuer,environment,"IDENTITY_ISSUER");httpsOrLocal(jwks,environment,"IDENTITY_JWKS_URI");
        NimbusJwtDecoder decoder=NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).build();
        List<String> accepted=Arrays.stream(audiences.split(",")).map(String::trim).filter(s->!s.isBlank()).toList();
        OAuth2TokenValidator<Jwt> tenant=jwt->{
            try {
                String user=jwt.getClaimAsString("user_id"),org=jwt.getClaimAsString("organization_id"),role=jwt.getClaimAsString("organization_role");
                boolean valid="user".equals(jwt.getClaimAsString("identity_type"))&&user!=null&&user.equals(jwt.getSubject())
                        &&org!=null&&List.of("OWNER","ADMIN","MEMBER").contains(role)&&jwt.getExpiresAt()!=null
                        &&jwt.getAudience()!=null&&jwt.getAudience().stream().anyMatch(accepted::contains);
                UUID.fromString(user);UUID.fromString(org);
                return valid?OAuth2TokenValidatorResult.success():invalid();
            } catch(RuntimeException ex){return invalid();}
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),tenant));
        return decoder;
    }
    private static OAuth2TokenValidatorResult invalid(){return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Access token identity or audience is invalid",null));}
    private static void required(String name,String value){if(value==null||value.isBlank())throw new IllegalStateException(name+" must be configured");}
    private static void httpsOrLocal(String value,Environment env,String name){
        URI uri;try{uri=URI.create(value);}catch(IllegalArgumentException ex){throw new IllegalStateException(name+" must be an absolute URL");}
        String[] profiles=env.getActiveProfiles();boolean local=profiles.length>0&&Arrays.stream(profiles).allMatch(p->p.equals("local")||p.equals("test"));
        boolean loop="localhost".equalsIgnoreCase(uri.getHost())||"127.0.0.1".equals(uri.getHost())||"::1".equals(uri.getHost())||"[::1]".equals(uri.getHost());
        if(uri.getHost()==null||uri.getUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null||!("https".equalsIgnoreCase(uri.getScheme())||local&&loop&&"http".equalsIgnoreCase(uri.getScheme())))
            throw new IllegalStateException(name+" must use HTTPS outside local/test");
    }
}
