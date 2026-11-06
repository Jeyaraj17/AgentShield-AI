package com.agentshield.runtimesecurity.config;

import static org.junit.jupiter.api.Assertions.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;

class JwtValidationTests {
    private static final String ISSUER="https://identity.example.test",AUDIENCE="runtime-api";
    private static KeyPair keyPair;
    private static JwtEncoder encoder;
    @BeforeAll static void keys() throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); keyPair=generator.generateKeyPair();
        RSAKey rsa=new RSAKey.Builder((RSAPublicKey)keyPair.getPublic()).privateKey((java.security.interfaces.RSAPrivateKey)keyPair.getPrivate()).keyID("runtime-test-key").build();
        JWKSource<SecurityContext> source=new ImmutableJWKSet<>(new JWKSet(rsa)); encoder=new NimbusJwtEncoder(source);
    }
    @Test void checksSignatureAlgorithmIssuerAudienceExpiryAndTenantClaims() throws Exception {
        NimbusJwtDecoder decoder=decoder((RSAPublicKey)keyPair.getPublic());
        assertNotNull(decoder.decode(token(ISSUER,List.of(AUDIENCE),Instant.now().plusSeconds(120),true)));
        String valid=token(ISSUER,List.of(AUDIENCE),Instant.now().plusSeconds(120),true);
        KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        assertThrows(RuntimeException.class,() -> decoder(generator.generateKeyPair().getPublic()).decode(valid));
        assertThrows(RuntimeException.class,() -> decoder.decode(hmacToken()));
        assertThrows(RuntimeException.class,() -> decoder.decode(token("https://wrong.example",List.of(AUDIENCE),Instant.now().plusSeconds(120),true)));
        assertThrows(RuntimeException.class,() -> decoder.decode(token(ISSUER,List.of("wrong-audience"),Instant.now().plusSeconds(120),true)));
        assertThrows(RuntimeException.class,() -> decoder.decode(token(ISSUER,List.of(AUDIENCE),Instant.now().minusSeconds(60),true)));
        assertThrows(RuntimeException.class,() -> decoder.decode(token(ISSUER,List.of(AUDIENCE),Instant.now().minusSeconds(5),true)));
        assertThrows(RuntimeException.class,() -> decoder.decode(token(ISSUER,List.of(AUDIENCE),Instant.now().plusSeconds(120),false)));
    }
    @Test void acceptsValidDashboardUserAudienceAndRejectsWrongOrIncompleteUserIdentity() {
        var userDecoder=decoder((RSAPublicKey)keyPair.getPublic());
        var now=Instant.now(); UUID user=UUID.randomUUID();
        var valid=org.springframework.security.oauth2.jwt.JwtClaimsSet.builder().issuer(ISSUER).subject(user.toString()).audience(List.of("agentshield-api"))
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(120)).claim("identity_type","user").claim("token_type","user")
                .claim("user_id",user.toString()).claim("organization_id",UUID.randomUUID().toString()).claim("organization_role","OWNER").build();
        String signed=encoder.encode(JwtEncoderParameters.from(org.springframework.security.oauth2.jwt.JwsHeader.with(SignatureAlgorithm.RS256).keyId("runtime-test-key").build(),valid)).getTokenValue();
        assertNotNull(userDecoder.decode(signed));
        var wrong=org.springframework.security.oauth2.jwt.JwtClaimsSet.from(valid).audience(List.of("wrong-audience")).build();
        String wrongToken=encoder.encode(JwtEncoderParameters.from(org.springframework.security.oauth2.jwt.JwsHeader.with(SignatureAlgorithm.RS256).keyId("runtime-test-key").build(),wrong)).getTokenValue();
        assertThrows(RuntimeException.class,()->userDecoder.decode(wrongToken));
        var incomplete=org.springframework.security.oauth2.jwt.JwtClaimsSet.builder().issuer(ISSUER).subject(user.toString()).audience(List.of("agentshield-api"))
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(120)).claim("identity_type","user").claim("token_type","user")
                .claim("user_id",user.toString()).claim("organization_role","OWNER").build();
        String incompleteToken=encoder.encode(JwtEncoderParameters.from(org.springframework.security.oauth2.jwt.JwsHeader.with(SignatureAlgorithm.RS256).keyId("runtime-test-key").build(),incomplete)).getTokenValue();
        assertThrows(RuntimeException.class,()->userDecoder.decode(incompleteToken));
    }
    private static NimbusJwtDecoder decoder(java.security.PublicKey publicKey) {
        NimbusJwtDecoder decoder=NimbusJwtDecoder.withPublicKey((RSAPublicKey)publicKey).build();
        decoder.setJwtValidator(JwtConfiguration.validators(ISSUER,AUDIENCE,"agentshield-api"));
        return decoder;
    }
    private static String token(String issuer,List<String> audience,Instant expires,boolean includeOrganization) {
        Instant now=Instant.now(); UUID agent=UUID.randomUUID();
        JwtClaimsSet.Builder claims=JwtClaimsSet.builder().issuer(issuer).subject(agent.toString()).audience(audience)
                .issuedAt(now.minusSeconds(1)).expiresAt(expires).claim("agent_id",agent.toString()).claim("identity_type","agent")
                .claim("token_type","agent").claim("agent_role","AGENT");
        if(includeOrganization) claims.claim("organization_id",UUID.randomUUID().toString());
        return encoder.encode(JwtEncoderParameters.from(org.springframework.security.oauth2.jwt.JwsHeader.with(SignatureAlgorithm.RS256).keyId("runtime-test-key").build(),claims.build())).getTokenValue();
    }
    private static String hmacToken() {
        Instant now=Instant.now(); UUID agent=UUID.randomUUID();
        JwtClaimsSet claims=JwtClaimsSet.builder().issuer(ISSUER).subject(agent.toString()).audience(List.of(AUDIENCE))
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(120)).claim("agent_id",agent.toString())
                .claim("organization_id",UUID.randomUUID().toString()).claim("identity_type","agent").claim("token_type","agent").claim("agent_role","AGENT").build();
        var hmac=new OctetSequenceKey.Builder(new byte[32]).keyID("runtime-hmac").algorithm(JWSAlgorithm.HS256).build();
        JwtEncoder hmacEncoder=new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(hmac)));
        return hmacEncoder.encode(JwtEncoderParameters.from(org.springframework.security.oauth2.jwt.JwsHeader.with(MacAlgorithm.HS256).keyId("runtime-hmac").build(),claims)).getTokenValue();
    }
}
