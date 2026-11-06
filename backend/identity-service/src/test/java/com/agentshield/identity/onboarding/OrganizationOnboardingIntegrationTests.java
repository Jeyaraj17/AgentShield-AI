package com.agentshield.identity.onboarding;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import com.agentshield.identity.membership.domain.MembershipStatus;
import com.agentshield.identity.membership.domain.OrganizationRole;
import com.agentshield.identity.membership.persistence.OrganizationMembershipRepository;
import com.agentshield.identity.organization.persistence.OrganizationRepository;
import com.agentshield.identity.user.persistence.UserRepository;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "agentshield.security.onboarding-rate-limit.max-requests=100")
@ActiveProfiles("test")
class OrganizationOnboardingIntegrationTests {
    private static final Pattern ORGANIZATION_ID = Pattern.compile("\\\"organizationId\\\":\\\"([^\\\"]+)\\\"");
    private static final String PASSWORD = "NewOwnerPassphrase123!";

    @Value("${local.server.port}") int port;
    @Autowired OrganizationRepository organizations;
    @Autowired UserRepository users;
    @Autowired OrganizationMembershipRepository memberships;
    @Autowired PasswordEncoder passwordEncoder;

    @Test
    void createsOrganizationUserAndInitialOwnerTogether() throws Exception {
        String suffix = UUID.randomUUID().toString();
        HttpResponse<String> response = onboard(suffix, "owner-" + suffix + "@example.test");

        assertEquals(201, response.statusCode(), response.body());
        UUID organizationId = organizationId(response.body());
        var organization = organizations.findById(organizationId).orElseThrow();
        var user = users.findByEmailNormalized("owner-" + suffix + "@example.test").orElseThrow();
        var membership = memberships.findByUser_IdAndOrganization_Id(user.getId(), organizationId).orElseThrow();
        assertEquals("Organization " + suffix, organization.getName());
        assertEquals(OrganizationRole.OWNER, membership.getRole());
        assertEquals(MembershipStatus.ACTIVE, membership.getStatus());
        assertNotEquals(PASSWORD, user.getPasswordHash());
        assertTrue(passwordEncoder.matches(PASSWORD, user.getPasswordHash()));
        assertFalse(response.body().contains(PASSWORD));
        assertFalse(response.body().contains(user.getPasswordHash()));
    }

    @Test
    void duplicateEmailReturnsGenericConflictAndRollsBackNewOrganization() throws Exception {
        String suffix = UUID.randomUUID().toString();
        String email = "duplicate-" + suffix + "@example.test";
        HttpResponse<String> first = onboard(suffix, email);
        assertEquals(201, first.statusCode(), first.body());
        long organizationsBefore = organizations.count();
        long membershipsBefore = memberships.count();

        HttpResponse<String> duplicate = onboard(suffix + "-second", email.toUpperCase());

        assertEquals(409, duplicate.statusCode());
        assertFalse(duplicate.body().contains(email));
        assertEquals(organizationsBefore, organizations.count());
        assertEquals(membershipsBefore, memberships.count());
    }

    @Test
    void invalidFieldsAreRejectedBeforeAnyRecordsAreCreated() throws Exception {
        long organizationsBefore = organizations.count();
        HttpResponse<String> response = post("{\"organizationName\":\" \",\"firstName\":\" \","
                + "\"lastName\":\"Owner\",\"email\":\"not-an-email\",\"password\":\"short\"}");
        assertEquals(400, response.statusCode());
        assertEquals(organizationsBefore, organizations.count());
    }

    private HttpResponse<String> onboard(String suffix, String email) throws Exception {
        return post("{\"organizationName\":\"Organization " + suffix + "\",\"firstName\":\"Initial\","
                + "\"lastName\":\"Owner\",\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}");
    }

    private HttpResponse<String> post(String body) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port + "/api/v1/onboarding/organizations"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static UUID organizationId(String body) {
        Matcher matcher = ORGANIZATION_ID.matcher(body);
        assertTrue(matcher.find(), "Response must contain organizationId only after onboarding succeeds");
        return UUID.fromString(matcher.group(1));
    }
}
