package com.agentshield.identity.config;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:defaultprofile;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "agentshield.security.issuer=https://identity.example.test",
        "agentshield.security.audience=agentshield-api",
        "agentshield.security.spa.redirect-uri=https://app.example.test/auth/callback",
        "agentshield.security.cors.allowed-origins=https://app.example.test",
        "agentshield.security.jwt.generate-ephemeral-key=false"
})
class DefaultProfileUserAccessTests {

    @DynamicPropertySource
    static void signingKeys(DynamicPropertyRegistry registry) {
        TestKeyMaterial.register(registry);
    }

    @Value("${local.server.port}")
    private int port;

    @Test
    void userEndpointsAreDeniedWhenNoActiveProfileIsSet() throws Exception {
        HttpRequest createRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/users"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"email\":\"blocked-default@example.com\",\"firstName\":\"Blocked\","
                                + "\"lastName\":\"User\",\"password\":\"StrongPassword1!\"}"))
                .build();
        HttpRequest lookupRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/users/" + UUID.randomUUID()))
                .GET()
                .build();

        HttpResponse<String> createResponse = HttpClient.newHttpClient()
                .send(createRequest, HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> lookupResponse = HttpClient.newHttpClient()
                .send(lookupRequest, HttpResponse.BodyHandlers.ofString());

        assertEquals(403, createResponse.statusCode());
        assertEquals(403, lookupResponse.statusCode());
    }

    @Test
    void membershipEndpointsAreDeniedWhenNoActiveProfileIsSet() throws Exception {
        UUID userId = UUID.randomUUID();
        HttpRequest createRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/organizations/"
                        + UUID.randomUUID() + "/memberships"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"userId\":\"" + userId + "\",\"role\":\"MEMBER\"}"))
                .build();
        HttpRequest listRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/users/" + userId + "/memberships"))
                .GET()
                .build();

        HttpResponse<String> createResponse = HttpClient.newHttpClient()
                .send(createRequest, HttpResponse.BodyHandlers.ofString());
        HttpResponse<String> listResponse = HttpClient.newHttpClient()
                .send(listRequest, HttpResponse.BodyHandlers.ofString());

        assertEquals(403, createResponse.statusCode());
        assertEquals(403, listResponse.statusCode());
    }
}
