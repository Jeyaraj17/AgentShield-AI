package com.agentshield.identity.config;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import com.agentshield.identity.user.domain.User;
import com.agentshield.identity.user.persistence.UserRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:localsecurity;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password="
})
@ActiveProfiles("local")
class LocalOrganizationAccessTests {

    @org.springframework.beans.factory.annotation.Autowired
    private UserRepository userRepository;

    @Value("${local.server.port}")
    private int port;

    @Test
    void organizationCreationIsAvailableInLocalProfile() throws Exception {
        String requestBody = "{\"name\":\"Local Organization\",\"organizationCode\":\"local-"
                + UUID.randomUUID() + "\"}";
        HttpResponse<String> response = postOrganization(requestBody);

        assertEquals(201, response.statusCode());
    }

    @Test
    void userCreateAndLookupAreAvailableInLocalProfile() throws Exception {
        String requestBody = "{\"email\":\"local-user@example.com\",\"firstName\":\"Local\","
                + "\"lastName\":\"User\",\"password\":\"StrongPassword1!\"}";
        HttpResponse<String> createResponse = postUser(requestBody);
        User storedUser = userRepository.findByEmailNormalized("local-user@example.com").orElseThrow();
        HttpResponse<String> lookupResponse = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://localhost:" + port + "/api/v1/users/" + storedUser.getId()))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(201, createResponse.statusCode());
        assertEquals(200, lookupResponse.statusCode());
    }

    private HttpResponse<String> postOrganization(String requestBody) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/organizations"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postUser(String requestBody) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/users"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }
}
