package com.agentshield.notification.config;

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
    @Bean JwtDecoder notificationJwtDecoder(@Value("${agentshield.security.jwt.issuer}") String issuer,
            @Value("${agentshield.security.jwt.jwk-set-uri}") String jwks,
            @Value("${agentshield.security.jwt.audiences}") String audience, Environment environment) {
        required("IDENTITY_ISSUER",issuer); required("IDENTITY_JWKS_URI",jwks); required("NOTIFICATION_SERVICE_AUDIENCE",audience);
        secureUrl(issuer,environment,"IDENTITY_ISSUER"); secureUrl(jwks,environment,"IDENTITY_JWKS_URI");
        List<String> accepted=Arrays.stream(audience.split(",")).map(String::trim).filter(s->!s.isBlank()).toList();
        NimbusJwtDecoder decoder=NimbusJwtDecoder.withJwkSetUri(jwks).jwsAlgorithm(SignatureAlgorithm.RS256).build();
        OAuth2TokenValidator<Jwt> claims=jwt->{
            try {
                String user=jwt.getClaimAsString("user_id"),org=jwt.getClaimAsString("organization_id"),role=jwt.getClaimAsString("organization_role");
                boolean valid="user".equals(jwt.getClaimAsString("identity_type")) && "user".equals(jwt.getClaimAsString("token_type"))
                        && user!=null && user.equals(jwt.getSubject()) && org!=null && List.of("OWNER","ADMIN","MEMBER").contains(role)
                        && jwt.getExpiresAt()!=null && jwt.getAudience()!=null && jwt.getAudience().stream().anyMatch(accepted::contains);
                UUID.fromString(user); UUID.fromString(org);
                return valid ? OAuth2TokenValidatorResult.success() : invalid();
            } catch(RuntimeException ex) { return invalid(); }
        };
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(issuer),claims));
        return decoder;
    }
    private static OAuth2TokenValidatorResult invalid(){return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token","Access token identity or audience is invalid",null));}
    private static void required(String name,String value){if(value==null||value.isBlank())throw new IllegalStateException(name+" must be configured");}
    private static void secureUrl(String value,Environment env,String name){
        URI uri;try{uri=URI.create(value);}catch(IllegalArgumentException ex){throw new IllegalStateException(name+" must be absolute");}
        String[] profiles=env.getActiveProfiles();boolean local=profiles.length>0&&Arrays.stream(profiles).allMatch(p->p.equals("local")||p.equals("test"));
        String host=uri.getHost();boolean loop="localhost".equalsIgnoreCase(host)||"127.0.0.1".equals(host)||"::1".equals(host)||"[::1]".equals(host);
        if(host==null||uri.getUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null||!("https".equalsIgnoreCase(uri.getScheme())||local&&loop&&"http".equalsIgnoreCase(uri.getScheme())))
            throw new IllegalStateException(name+" must use HTTPS outside local/test");
    }
}
