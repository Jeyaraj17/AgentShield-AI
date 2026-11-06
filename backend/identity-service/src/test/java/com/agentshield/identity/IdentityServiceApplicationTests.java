package com.agentshield.identity;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import com.agentshield.identity.user.domain.User;
import com.agentshield.identity.user.persistence.UserRepository;
import com.agentshield.identity.organization.domain.Organization;
import com.agentshield.identity.organization.persistence.OrganizationRepository;
import com.agentshield.identity.membership.domain.MembershipStatus;
import com.agentshield.identity.membership.domain.OrganizationMembership;
import com.agentshield.identity.membership.domain.OrganizationRole;
import com.agentshield.identity.membership.persistence.OrganizationMembershipRepository;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class IdentityServiceApplicationTests {

    private static final String VALID_PASSWORD = "StrongPassword1!";

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private OrganizationRepository organizationRepository;

    @Autowired
    private OrganizationMembershipRepository membershipRepository;

    @Test
    void healthEndpointIsAvailableWithoutAuthentication() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/actuator/health"))
                .GET()
                .build();

        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"status\":\"UP\""));
    }

    @Test
    void createsOrganization() throws Exception {
        String code = "org-" + java.util.UUID.randomUUID();
        HttpResponse<String> response = postOrganization(
                "{\"name\":\"Acme Corporation\",\"organizationCode\":\"" + code
                        + "\",\"description\":\"Example organization\"}");

        assertEquals(201, response.statusCode());
        assertTrue(response.body().contains(code));
        assertTrue(response.body().contains("\"status\":\"ACTIVE\""));
        assertTrue(response.body().contains("\"id\":"));
        assertTrue(response.headers().firstValue("location").isPresent());
    }

    @Test
    void rejectsBlankOrganizationNameAndCode() throws Exception {
        HttpResponse<String> response = postOrganization(
                "{\"name\":\" \",\"organizationCode\":\"\",\"description\":null}");

        assertEquals(400, response.statusCode());
        assertTrue(response.body().contains("name"));
        assertTrue(response.body().contains("organizationCode"));
    }

    @Test
    void rejectsDuplicateOrganizationCode() throws Exception {
        String code = "org-" + java.util.UUID.randomUUID();
        String requestBody = "{\"name\":\"Acme Corporation\",\"organizationCode\":\"" + code + "\"}";

        HttpResponse<String> firstResponse = postOrganization(requestBody);
        HttpResponse<String> duplicateResponse = postOrganization(requestBody);

        assertEquals(201, firstResponse.statusCode());
        assertEquals(409, duplicateResponse.statusCode());
        assertTrue(duplicateResponse.body().contains("Duplicate organization code"));
    }

    @Test
    void createsUserWithNormalizedEmailAndBcryptHashWithoutExposingPassword() throws Exception {
        String requestBody = "{\"email\":\"  New.User@Example.COM  \",\"firstName\":\"New\"," 
                + "\"lastName\":\"User\",\"password\":\"" + VALID_PASSWORD + "\"}";

        HttpResponse<String> response = postUser(requestBody);
        User storedUser = userRepository.findByEmailNormalized("new.user@example.com").orElseThrow();

        assertEquals(201, response.statusCode());
        assertTrue(response.body().contains("\"email\":\"new.user@example.com\""));
        assertTrue(response.body().contains("\"status\":\"ACTIVE\""));
        assertTrue(response.body().contains("\"id\":"));
        assertTrue(response.headers().firstValue("location").isPresent());
        assertNotEquals(VALID_PASSWORD, storedUser.getPasswordHash());
        assertTrue(storedUser.getPasswordHash().startsWith("$2"));
        assertTrue(passwordEncoder.matches(VALID_PASSWORD, storedUser.getPasswordHash()));
        assertFalse(response.body().contains(VALID_PASSWORD));
        assertFalse(response.body().contains("passwordHash"));
        assertFalse(response.body().contains(storedUser.getPasswordHash()));
    }

    @Test
    void rejectsInvalidEmailAndBlankRequiredFields() throws Exception {
        HttpResponse<String> response = postUser(
                "{\"email\":\"not-an-email\",\"firstName\":\" \","
                        + "\"lastName\":\"\",\"password\":\"" + VALID_PASSWORD + "\"}");

        assertEquals(400, response.statusCode());
        assertTrue(response.body().contains("email"));
        assertTrue(response.body().contains("firstName"));
        assertTrue(response.body().contains("lastName"));
    }

    @Test
    void rejectsPasswordsOutsidePolicy() throws Exception {
        HttpResponse<String> tooShort = postUser(userRequest("short@example.com", "Short1!"));
        HttpResponse<String> tooLongForBcrypt = postUser(userRequest("long@example.com", "a".repeat(73)));

        assertEquals(400, tooShort.statusCode());
        assertEquals(400, tooLongForBcrypt.statusCode());
    }

    @Test
    void duplicateNormalizedEmailReturnsConflict() throws Exception {
        HttpResponse<String> firstResponse = postUser(userRequest("person@example.com", VALID_PASSWORD));
        HttpResponse<String> duplicateResponse = postUser(userRequest("  PERSON@EXAMPLE.COM  ", VALID_PASSWORD));

        assertEquals(201, firstResponse.statusCode());
        assertEquals(409, duplicateResponse.statusCode());
    }

    @Test
    void looksUpUserAndReturnsNotFoundForUnknownId() throws Exception {
        postUser(userRequest("lookup@example.com", VALID_PASSWORD));
        User storedUser = userRepository.findByEmailNormalized("lookup@example.com").orElseThrow();

        HttpResponse<String> foundResponse = getUser(storedUser.getId());
        HttpResponse<String> missingResponse = getUser(UUID.randomUUID());

        assertEquals(200, foundResponse.statusCode());
        assertTrue(foundResponse.body().contains("lookup@example.com"));
        assertFalse(foundResponse.body().contains("passwordHash"));
        assertEquals(404, missingResponse.statusCode());
    }

    @Test
    void createsMembershipWithRoleAndActiveStatus() throws Exception {
        Organization organization = createOrganization();
        User user = createUser();

        HttpResponse<String> response = postMembership(organization.getId(), user.getId(), OrganizationRole.ADMIN);
        OrganizationMembership membership = membershipRepository
                .findByUser_IdAndOrganization_Id(user.getId(), organization.getId()).orElseThrow();

        assertEquals(201, response.statusCode());
        assertTrue(response.body().contains("\"role\":\"ADMIN\""));
        assertTrue(response.body().contains("\"status\":\"ACTIVE\""));
        assertTrue(response.body().contains(user.getId().toString()));
        assertTrue(response.body().contains(organization.getId().toString()));
        assertFalse(response.body().contains("password"));
        assertEquals(OrganizationRole.ADMIN, membership.getRole());
        assertEquals(MembershipStatus.ACTIVE, membership.getStatus());
        assertTrue(membership.getJoinedAt() != null);
    }

    @Test
    void oneUserCanJoinMultipleOrganizationsAndListMemberships() throws Exception {
        User user = createUser();
        Organization firstOrganization = createOrganization();
        Organization secondOrganization = createOrganization();

        HttpResponse<String> firstCreate = postMembership(
                firstOrganization.getId(), user.getId(), OrganizationRole.OWNER);
        HttpResponse<String> secondCreate = postMembership(
                secondOrganization.getId(), user.getId(), OrganizationRole.MEMBER);
        HttpResponse<String> listResponse = getMemberships(user.getId());

        assertEquals(201, firstCreate.statusCode());
        assertEquals(201, secondCreate.statusCode());
        assertEquals(200, listResponse.statusCode());
        assertEquals(2, membershipRepository.findAllByUser_Id(user.getId()).size());
        assertTrue(listResponse.body().contains(firstOrganization.getId().toString()));
        assertTrue(listResponse.body().contains(secondOrganization.getId().toString()));
        assertFalse(listResponse.body().contains("passwordHash"));
    }

    @Test
    void multipleUsersCanJoinTheSameOrganization() throws Exception {
        Organization organization = createOrganization();
        User firstUser = createUser();
        User secondUser = createUser();

        HttpResponse<String> firstCreate = postMembership(
                organization.getId(), firstUser.getId(), OrganizationRole.MEMBER);
        HttpResponse<String> secondCreate = postMembership(
                organization.getId(), secondUser.getId(), OrganizationRole.ADMIN);

        assertEquals(201, firstCreate.statusCode());
        assertEquals(201, secondCreate.statusCode());
        assertEquals(2, membershipRepository.findAllByOrganization_Id(organization.getId()).size());
    }

    @Test
    void duplicateMembershipReturnsConflict() throws Exception {
        Organization organization = createOrganization();
        User user = createUser();

        HttpResponse<String> firstCreate = postMembership(
                organization.getId(), user.getId(), OrganizationRole.MEMBER);
        HttpResponse<String> duplicateCreate = postMembership(
                organization.getId(), user.getId(), OrganizationRole.ADMIN);

        assertEquals(201, firstCreate.statusCode());
        assertEquals(409, duplicateCreate.statusCode());
    }

    @Test
    void missingUserAndOrganizationReturnNotFound() throws Exception {
        Organization organization = createOrganization();
        User user = createUser();

        HttpResponse<String> missingUserResponse = postMembership(
                organization.getId(), UUID.randomUUID(), OrganizationRole.MEMBER);
        HttpResponse<String> missingOrganizationResponse = postMembership(
                UUID.randomUUID(), user.getId(), OrganizationRole.MEMBER);

        assertEquals(404, missingUserResponse.statusCode());
        assertEquals(404, missingOrganizationResponse.statusCode());
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

    private HttpResponse<String> getUser(UUID userId) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/users/" + userId))
                .GET()
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    private String userRequest(String email, String password) {
        return "{\"email\":\"" + email + "\",\"firstName\":\"Test\",\"lastName\":\"User\","
                + "\"password\":\"" + password + "\"}";
    }

    private Organization createOrganization() {
        String unique = UUID.randomUUID().toString();
        return organizationRepository.saveAndFlush(
                new Organization("Membership Organization", "member-org-" + unique, null));
    }

    private User createUser() {
        String unique = UUID.randomUUID().toString();
        return userRepository.saveAndFlush(
                new User("member-" + unique + "@example.com", "Membership", "User", "test-only-hash"));
    }

    private HttpResponse<String> postMembership(UUID organizationId, UUID userId, OrganizationRole role)
            throws Exception {
        String requestBody = "{\"userId\":\"" + userId + "\",\"role\":\"" + role.name() + "\"}";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/organizations/"
                        + organizationId + "/memberships"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> getMemberships(UUID userId) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/users/" + userId + "/memberships"))
                .GET()
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }
}
