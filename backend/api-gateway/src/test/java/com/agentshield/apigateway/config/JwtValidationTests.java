package com.agentshield.apigateway.config;

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
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;

class JwtValidationTests {
    private static final String ISSUER="https://identity.example.test";
    private static final String AUDIENCE="agentshield-api";
    private static KeyPair keyPair;
    private static JwtEncoder encoder;

    @BeforeAll static void createKey() throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); keyPair=generator.generateKeyPair();
        RSAKey rsa=new RSAKey.Builder((RSAPublicKey)keyPair.getPublic()).privateKey((java.security.interfaces.RSAPrivateKey)keyPair.getPrivate()).keyID("key-1").build();
        JWKSource<SecurityContext> source=new ImmutableJWKSet<>(new JWKSet(rsa)); encoder=new NimbusJwtEncoder(source);
    }

    @Test void validatesValidRsaTokenAndRejectsTamperingIssuerAudienceExpiryAndMissingTenant() throws Exception {
        var decoder=decoder();
        String valid=token(ISSUER,List.of(AUDIENCE),Instant.now().plusSeconds(300),true);
        assertNotNull(decoder.decode(valid).block());
        KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        RSAPublicKey wrongKey=(RSAPublicKey)generator.generateKeyPair().getPublic();
        assertThrows(RuntimeException.class,() -> decoder(wrongKey).decode(valid).block());
        assertThrows(RuntimeException.class,() -> decoder().decode(hmacToken()).block());
        assertThrows(RuntimeException.class,() -> decoder.decode(token("https://wrong-issuer",List.of(AUDIENCE),Instant.now().plusSeconds(300),true)).block());
        assertThrows(RuntimeException.class,() -> decoder.decode(token(ISSUER,List.of("other-audience"),Instant.now().plusSeconds(300),true)).block());
        assertThrows(RuntimeException.class,() -> decoder.decode(token(ISSUER,List.of(AUDIENCE),Instant.now().minusSeconds(60),true)).block());
        assertThrows(RuntimeException.class,() -> decoder.decode(token(ISSUER,List.of(AUDIENCE),Instant.now().plusSeconds(300),false)).block());
    }

    private static NimbusReactiveJwtDecoder decoder() { return decoder((RSAPublicKey)keyPair.getPublic()); }
    private static NimbusReactiveJwtDecoder decoder(RSAPublicKey publicKey) {
        NimbusReactiveJwtDecoder decoder=NimbusReactiveJwtDecoder.withPublicKey(publicKey).signatureAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefaultWithIssuer(ISSUER),JwtConfiguration.tenantClaimsValidator(AUDIENCE,"agentshield-runtime-api")));
        return decoder;
    }
    private static String token(String issuer,List<String> audience,Instant expiry,boolean tenantClaims) {
        Instant now=Instant.now(); UUID user=UUID.randomUUID();
        JwtClaimsSet.Builder claims=JwtClaimsSet.builder().issuer(issuer).subject(user.toString()).audience(audience)
                .issuedAt(now.minusSeconds(1)).expiresAt(expiry).claim("user_id",user.toString()).claim("organization_role","MEMBER");
        if(tenantClaims) claims.claim("organization_id",UUID.randomUUID().toString());
        claims.claim("identity_type","user").claim("token_type","user");
        return encoder.encode(JwtEncoderParameters.from(org.springframework.security.oauth2.jwt.JwsHeader.with(SignatureAlgorithm.RS256).keyId("key-1").build(),claims.build())).getTokenValue();
    }

    @Test void acceptsOnlyWellFormedAgentTokensForTheRuntimeAudience() {
        var decoder=decoder();
        UUID agent=UUID.randomUUID();
        assertNotNull(decoder.decode(agentToken(agent.toString(),agent.toString(),"agentshield-runtime-api","AGENT","agent",Instant.now().plusSeconds(300))).block());
        assertThrows(RuntimeException.class,() -> decoder.decode(agentToken(agent.toString(),agent.toString(),AUDIENCE,"AGENT","agent",Instant.now().plusSeconds(300))).block());
        assertThrows(RuntimeException.class,() -> decoder.decode(agentToken(agent.toString(),agent.toString(),"agentshield-runtime-api",null,"agent",Instant.now().plusSeconds(300))).block());
        assertThrows(RuntimeException.class,() -> decoder.decode(agentToken(agent.toString(),UUID.randomUUID().toString(),"agentshield-runtime-api","AGENT","agent",Instant.now().plusSeconds(300))).block());
        assertThrows(RuntimeException.class,() -> decoder.decode(agentToken(agent.toString(),agent.toString(),"agentshield-runtime-api","RUNTIME_GATEWAY","service",Instant.now().plusSeconds(300))).block());
        assertThrows(RuntimeException.class,() -> decoder.decode(agentToken(agent.toString(),agent.toString(),"agentshield-runtime-api","AGENT","agent",Instant.now().minusSeconds(1))).block());
    }

    private static String agentToken(String subject,String agentId,String audience,String agentRole,String identityType,Instant expiry) {
        JwtClaimsSet.Builder claims=JwtClaimsSet.builder().issuer(ISSUER).subject(subject).audience(List.of(audience))
                .issuedAt(Instant.now().minusSeconds(1)).expiresAt(expiry).claim("agent_id",agentId)
                .claim("organization_id",UUID.randomUUID().toString()).claim("identity_type",identityType)
                .claim("token_type",identityType.equals("agent")?"agent":"service");
        if(agentRole!=null) claims.claim("agent_role",agentRole);
        return encoder.encode(JwtEncoderParameters.from(org.springframework.security.oauth2.jwt.JwsHeader.with(SignatureAlgorithm.RS256).keyId("key-1").build(),claims.build())).getTokenValue();
    }
    private static String hmacToken() {
        Instant now=Instant.now(); UUID user=UUID.randomUUID();
        JwtClaimsSet claims=JwtClaimsSet.builder().issuer(ISSUER).subject(user.toString()).audience(List.of(AUDIENCE))
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(300)).claim("user_id",user.toString())
                .claim("organization_id",UUID.randomUUID().toString()).claim("organization_role","MEMBER").build();
        OctetSequenceKey hmac=new OctetSequenceKey.Builder(new byte[32]).keyID("hmac").algorithm(JWSAlgorithm.HS256).build();
        JwtEncoder hmacEncoder=new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(hmac)));
        return hmacEncoder.encode(JwtEncoderParameters.from(org.springframework.security.oauth2.jwt.JwsHeader.with(MacAlgorithm.HS256).keyId("hmac").build(),claims)).getTokenValue();
    }
}
