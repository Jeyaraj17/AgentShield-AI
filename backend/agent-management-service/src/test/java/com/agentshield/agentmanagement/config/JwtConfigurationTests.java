package com.agentshield.agentmanagement.config;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtConfigurationTests {

    private static final String ISSUER = "https://identity.test";
    private static final String AUDIENCE = "agentshield-api";
    private static final String KEY_ID = "identity-test-key";

    private KeyPair keyPair;
    private HttpServer jwksServer;
    private JwtDecoder jwtDecoder;
    private UUID userId;
    private UUID organizationId;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        RSAKey publicJwk = new RSAKey.Builder((java.security.interfaces.RSAPublicKey) keyPair.getPublic())
                .keyID(KEY_ID).algorithm(JWSAlgorithm.RS256).build();
        jwksServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] body = new JWKSet(publicJwk).toString().getBytes(StandardCharsets.UTF_8);
        jwksServer.createContext("/jwks", exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) {
                output.write(body);
            }
        });
        jwksServer.start();
        String jwksUri = "http://127.0.0.1:" + jwksServer.getAddress().getPort() + "/jwks";
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles("test");
        jwtDecoder = new JwtConfiguration().jwtDecoder(ISSUER, jwksUri,
                AUDIENCE+",agentshield-agent-management-api","agentshield-runtime-gateway",environment);
        userId = UUID.randomUUID();
        organizationId = UUID.randomUUID();
    }

    @AfterEach
    void stopJwksServer() {
        jwksServer.stop(0);
    }

    @Test
    void validatesRsaSignatureIssuerAudienceExpiryAndTenantClaims() throws Exception {
        String valid = sign(KEY_ID, JWSAlgorithm.RS256, keyPair, ISSUER, AUDIENCE, Instant.now().plusSeconds(60), true);
        assertEquals(userId.toString(), jwtDecoder.decode(valid).getSubject());

        String invalidSignature = sign(KEY_ID, JWSAlgorithm.RS256, generateOtherKey(), ISSUER, AUDIENCE,
                Instant.now().plusSeconds(60), true);
        assertThrows(JwtException.class, () -> jwtDecoder.decode(invalidSignature));
        String wrongAlgorithm = sign(KEY_ID, JWSAlgorithm.HS256, keyPair, ISSUER, AUDIENCE,
                Instant.now().plusSeconds(60), true);
        assertThrows(JwtException.class, () -> jwtDecoder.decode(wrongAlgorithm));
        String wrongIssuer = sign(KEY_ID, JWSAlgorithm.RS256, keyPair, "http://wrong-issuer.test", AUDIENCE,
                Instant.now().plusSeconds(60), true);
        assertThrows(JwtException.class, () -> jwtDecoder.decode(wrongIssuer));
        String wrongAudience = sign(KEY_ID, JWSAlgorithm.RS256, keyPair, ISSUER, "wrong-audience",
                Instant.now().plusSeconds(60), true);
        assertThrows(JwtException.class, () -> jwtDecoder.decode(wrongAudience));
        String expired = sign(KEY_ID, JWSAlgorithm.RS256, keyPair, ISSUER, AUDIENCE,
                Instant.now().minusSeconds(5), true);
        assertThrows(JwtException.class, () -> jwtDecoder.decode(expired));
        String missingExpiry = sign(KEY_ID, JWSAlgorithm.RS256, keyPair, ISSUER, AUDIENCE, null, true);
        assertThrows(JwtException.class, () -> jwtDecoder.decode(missingExpiry));
        String missingOrganization = sign(KEY_ID, JWSAlgorithm.RS256, keyPair, ISSUER, AUDIENCE,
                Instant.now().plusSeconds(60), false);
        assertThrows(JwtException.class, () -> jwtDecoder.decode(missingOrganization));
    }

    @Test
    void runtimeGatewayRequiresExactIdentityRoleAndAgentReadScope() {
        Instant now = Instant.now();
        Jwt valid = Jwt.withTokenValue("gateway").header("alg", "RS256").issuer(ISSUER)
                .audience(List.of("agentshield-agent-management-api")).subject("agentshield-runtime-gateway")
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(60))
                .claim("client_id", "agentshield-runtime-gateway").claim("identity_type", "service")
                .claim("token_type", "service").claim("service_role", "RUNTIME_GATEWAY")
                .claim("scope", "agents.read").build();
        assertEquals(true, JwtConfiguration.requiredTenantClaims("agentshield-runtime-gateway")
                .validate(valid).getErrors().isEmpty());

        Jwt missingScope = Jwt.withTokenValue("missing-scope").header("alg", "RS256").issuer(ISSUER)
                .audience(List.of("agentshield-agent-management-api")).subject("agentshield-runtime-gateway")
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(60))
                .claim("client_id", "agentshield-runtime-gateway").claim("identity_type", "service")
                .claim("token_type", "service").claim("service_role", "RUNTIME_GATEWAY").build();
        assertEquals(false, JwtConfiguration.requiredTenantClaims("agentshield-runtime-gateway")
                .validate(missingScope).getErrors().isEmpty());

        Jwt wrongRole = Jwt.withTokenValue("wrong-role").header("alg", "RS256").issuer(ISSUER)
                .audience(List.of("agentshield-agent-management-api")).subject("agentshield-runtime-gateway")
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(60))
                .claim("client_id", "agentshield-runtime-gateway").claim("identity_type", "service")
                .claim("token_type", "service").claim("service_role", "OTHER_SERVICE")
                .claim("scope", "agents.read").build();
        assertEquals(false, JwtConfiguration.requiredTenantClaims("agentshield-runtime-gateway")
                .validate(wrongRole).getErrors().isEmpty());
    }

    private String sign(String kid, JWSAlgorithm algorithm, KeyPair pair, String issuer, String audience,
            Instant expiresAt, boolean includeOrganization) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer).audience(audience).subject(userId.toString())
                .issueTime(Date.from(Instant.now().minusSeconds(1)))
                .claim("user_id", userId.toString())
                .claim("organization_role", "OWNER");
        if (expiresAt != null) {
            claims.expirationTime(Date.from(expiresAt));
        }
        if (includeOrganization) {
            claims.claim("organization_id", organizationId.toString());
        }
        SignedJWT token = new SignedJWT(new JWSHeader.Builder(algorithm).keyID(kid).build(), claims.build());
        if (JWSAlgorithm.RS256.equals(algorithm)) {
            token.sign(new RSASSASigner((java.security.interfaces.RSAPrivateKey) pair.getPrivate()));
        } else {
            token.sign(new MACSigner("negative-test-hmac-key-length-must-be-32-bytes"));
        }
        return token.serialize();
    }

    private KeyPair generateOtherKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
