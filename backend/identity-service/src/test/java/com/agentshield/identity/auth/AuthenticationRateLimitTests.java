package com.agentshield.identity.auth;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "agentshield.security.rate-limit.max-requests=2",
        "agentshield.security.rate-limit.window-seconds=60",
        "agentshield.security.onboarding-rate-limit.max-requests=2",
        "agentshield.security.onboarding-rate-limit.window-seconds=60"
})
@ActiveProfiles("test")
class AuthenticationRateLimitTests {

    @Value("${local.server.port}")
    private int port;

    @Test
    void loginAndPublicOnboardingHaveIndependentConfigurableSourceLimits() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> first = login(client);
        HttpResponse<String> second = login(client);
        HttpResponse<String> third = login(client);

        assertEquals(403, first.statusCode());
        assertEquals(403, second.statusCode());
        assertEquals(429, third.statusCode());
        org.junit.jupiter.api.Assertions.assertTrue(third.headers().firstValue("Retry-After").isPresent());

        HttpResponse<String> onboardingFirst = onboard(client);
        HttpResponse<String> onboardingSecond = onboard(client);
        HttpResponse<String> onboardingThird = onboard(client);
        assertEquals(400, onboardingFirst.statusCode());
        assertEquals(400, onboardingSecond.statusCode());
        assertEquals(429, onboardingThird.statusCode());
    }

    private HttpResponse<String> login(HttpClient client) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("username=missing@example.com&password=not-a-password"))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> onboard(HttpClient client) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/onboarding/organizations"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build(), HttpResponse.BodyHandlers.ofString());
    }
}
