package com.agentshield.identity.config;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:trustedproxy;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "agentshield.security.issuer=https://identity.example.test",
        "agentshield.security.audience=agentshield-api",
        "agentshield.security.spa.redirect-uri=https://app.example.test/auth/callback",
        "agentshield.security.cors.allowed-origins=https://app.example.test",
        "agentshield.security.trusted-proxy-addresses=127.0.0.1"
})
@ActiveProfiles("production")
class TrustedForwardedProxyTests {

    @Value("${local.server.port}")
    private int port;

    @DynamicPropertySource
    static void signingKeys(DynamicPropertyRegistry registry) {
        TestKeyMaterial.register(registry);
    }

    @Test
    void configuredProxyForwardedHttpsIsAccepted() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/login"))
                .header("X-Forwarded-Proto", "https")
                .header("X-Forwarded-Host", "identity.example.test")
                .GET()
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(302, response.statusCode());
        assertEquals("https://app.example.test/sign-in?identityLogin=1",
                response.headers().firstValue("location").orElseThrow());
        String csrfCookie = response.headers().allValues("set-cookie").stream()
                .filter(cookie -> cookie.startsWith("XSRF-TOKEN="))
                .findFirst().orElse("");
        org.junit.jupiter.api.Assertions.assertTrue(csrfCookie.contains("Secure"));
        org.junit.jupiter.api.Assertions.assertTrue(csrfCookie.contains("SameSite=Lax"));
        org.junit.jupiter.api.Assertions.assertTrue(!csrfCookie.contains("HttpOnly"));
    }
}
