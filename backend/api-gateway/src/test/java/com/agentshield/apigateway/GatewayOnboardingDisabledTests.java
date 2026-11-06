package com.agentshield.apigateway;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class GatewayOnboardingDisabledTests {
    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("agentshield.security.organization-onboarding.enabled", () -> false);
    }

    @Autowired WebTestClient client;
    @MockitoBean ReactiveJwtDecoder decoder;

    @Test
    void publicOnboardingIsDeniedEvenForAnAuthenticatedOwnerWhenTheFeatureFlagIsOff() {
        Instant now = Instant.now();
        when(decoder.decode("signed-owner")).thenReturn(Mono.just(org.springframework.security.oauth2.jwt.Jwt
                .withTokenValue("signed-owner").header("alg", "RS256")
                .issuer("http://localhost:19000").subject(UUID.randomUUID().toString())
                .audience(List.of("agentshield-api")).issuedAt(now).expiresAt(now.plusSeconds(60))
                .claim("identity_type", "user").claim("user_id", UUID.randomUUID().toString())
                .claim("organization_id", UUID.randomUUID().toString()).claim("organization_role", "OWNER")
                .build()));
        client.post().uri("/api/v1/onboarding/organizations")
                .headers(headers -> headers.setBearerAuth("signed-owner"))
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isForbidden();
    }
}
