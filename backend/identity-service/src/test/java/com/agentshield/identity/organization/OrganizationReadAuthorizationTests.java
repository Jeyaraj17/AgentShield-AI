package com.agentshield.identity.organization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import java.net.http.HttpResponse.BodyHandlers;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import com.agentshield.identity.config.TestKeyMaterial;
import com.agentshield.identity.membership.domain.OrganizationMembership;
import com.agentshield.identity.membership.domain.OrganizationRole;
import com.agentshield.identity.membership.persistence.OrganizationMembershipRepository;
import com.agentshield.identity.organization.domain.Organization;
import com.agentshield.identity.organization.persistence.OrganizationRepository;
import com.agentshield.identity.user.domain.User;
import com.agentshield.identity.user.persistence.UserRepository;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:h2:mem:organizationreads;DB_CLOSE_DELAY=-1",
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
@ActiveProfiles("test")
class OrganizationReadAuthorizationTests {
    @DynamicPropertySource
    static void signingKeys(DynamicPropertyRegistry registry) { TestKeyMaterial.register(registry); }

    @Value("${local.server.port}") private int port;
    @Autowired private OrganizationRepository organizations;
    @Autowired private OrganizationMembershipRepository memberships;
    @Autowired private UserRepository users;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private ObjectMapper mapper;
    @MockitoBean private JwtDecoder decoder;
    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void ownerAndAdminCanReadCurrentOrganizationAndDirectory() throws Exception {
        Organization organization = organization("privileged-read");
        User owner = user("owner"); User admin = user("admin"); User member = user("member");
        membership(owner, organization, OrganizationRole.OWNER);
        membership(admin, organization, OrganizationRole.ADMIN);
        membership(member, organization, OrganizationRole.MEMBER);
        stub("owner-token", owner, organization, "OWNER");
        stub("admin-token", admin, organization, "ADMIN");

        for (String token : List.of("owner-token", "admin-token")) {
            HttpResponse<String> organizationResponse = get("/api/v1/organizations/current", token);
            assertEquals(200, organizationResponse.statusCode(), organizationResponse.body());
            JsonNode organizationJson = mapper.readTree(organizationResponse.body());
            assertEquals(organization.getId().toString(), organizationJson.path("id").asText());
            assertEquals(organization.getName(), organizationJson.path("name").asText());
            assertFalse(organizationResponse.body().contains("passwordHash"));

            HttpResponse<String> directory = get("/api/v1/organizations/current/members", token);
            assertEquals(200, directory.statusCode(), directory.body());
            JsonNode entries = mapper.readTree(directory.body());
            assertEquals(3, entries.size());
            assertTrue(directory.body().contains(owner.getEmailNormalized()));
            assertTrue(directory.body().contains(admin.getEmailNormalized()));
            assertFalse(directory.body().contains("passwordHash"));
            assertFalse(directory.body().contains("password_hash"));
        }
    }

    @Test
    void memberCanReadOrganizationAndOnlyOwnProfileAndMembership() throws Exception {
        Organization organization = organization("member-read");
        User member = user("self"); User another = user("another");
        membership(member, organization, OrganizationRole.MEMBER);
        membership(another, organization, OrganizationRole.ADMIN);
        stub("member-token", member, organization, "MEMBER");

        assertEquals(200, get("/api/v1/organizations/current", "member-token").statusCode());
        HttpResponse<String> profile = get("/api/v1/users/me", "member-token");
        assertEquals(200, profile.statusCode(), profile.body());
        assertTrue(profile.body().contains(member.getEmailNormalized()));
        assertFalse(profile.body().contains("passwordHash"));
        HttpResponse<String> selfMembership = get("/api/v1/users/me/membership", "member-token");
        assertEquals(200, selfMembership.statusCode(), selfMembership.body());
        assertEquals(member.getId().toString(), mapper.readTree(selfMembership.body()).path("userId").asText());
        assertEquals("MEMBER", mapper.readTree(selfMembership.body()).path("role").asText());
        assertEquals(403, get("/api/v1/organizations/current/members", "member-token").statusCode());
    }

    @Test
    void tenantAndRoleHeadersCannotChangeClaimScopedDirectory() throws Exception {
        Organization tenantA = organization("tenant-a"); Organization tenantB = organization("tenant-b");
        User adminA = user("admin-a"); User privateB = user("private-b");
        membership(adminA, tenantA, OrganizationRole.ADMIN); membership(privateB, tenantB, OrganizationRole.OWNER);
        stub("admin-a-token", adminA, tenantA, "ADMIN");

        HttpRequest request = HttpRequest.newBuilder(uri("/api/v1/organizations/current/members?organizationId=" + tenantB.getId()))
                .header("Authorization", "Bearer admin-a-token")
                .header("X-Organization-Id", tenantB.getId().toString())
                .header("X-Authenticated-Organization-Id", tenantB.getId().toString())
                .header("X-Organization-Role", "OWNER").header("X-Role", "OWNER")
                .GET().build();
        HttpResponse<String> directory = client.send(request, BodyHandlers.ofString());
        assertEquals(200, directory.statusCode(), directory.body());
        JsonNode entries = mapper.readTree(directory.body());
        assertEquals(1, entries.size());
        assertEquals(adminA.getId().toString(), entries.get(0).path("userId").asText());
        assertFalse(directory.body().contains(privateB.getEmailNormalized()));

        HttpRequest memberSpoof = HttpRequest.newBuilder(uri("/api/v1/organizations/current/members"))
                .header("Authorization", "Bearer admin-a-token").header("X-Role", "MEMBER")
                .GET().build();
        assertEquals(200, client.send(memberSpoof, BodyHandlers.ofString()).statusCode());
    }

    @Test
    void unauthenticatedInvalidAndNonUserTokensAreRejected() throws Exception {
        Organization organization = organization("authz"); User user = user("authz");
        membership(user, organization, OrganizationRole.OWNER);
        stub("owner-authz", user, organization, "OWNER");
        when(decoder.decode("invalid-token")).thenThrow(new BadJwtException("invalid"));
        Jwt agent = Jwt.withTokenValue("agent-token").header("alg", "RS256")
                .issuer("https://identity.example.test").audience(List.of("agentshield-api"))
                .subject(UUID.randomUUID().toString()).issuedAt(Instant.now().minusSeconds(1))
                .expiresAt(Instant.now().plusSeconds(120)).claim("identity_type", "agent")
                .claim("organization_role", "OWNER").claim("organization_id", organization.getId().toString()).build();
        when(decoder.decode("agent-token")).thenReturn(agent);

        assertEquals(403, get("/api/v1/organizations/current", null).statusCode());
        assertEquals(401, get("/api/v1/organizations/current", "invalid-token").statusCode());
        assertEquals(403, get("/api/v1/organizations/current", "agent-token").statusCode());
        assertEquals(403, get("/api/v1/organizations/current/members", "agent-token").statusCode());
    }

    private Organization organization(String suffix) {
        return organizations.saveAndFlush(new Organization("Organization " + suffix,
                "org-" + UUID.randomUUID(), null));
    }
    private User user(String suffix) {
        return users.saveAndFlush(new User(suffix + "-" + UUID.randomUUID() + "@example.test", suffix,
                "Member", passwordEncoder.encode("StrongPassword1!")));
    }
    private void membership(User user, Organization organization, OrganizationRole role) {
        memberships.saveAndFlush(new OrganizationMembership(user, organization, role));
    }
    private void stub(String token, User user, Organization organization, String role) {
        Instant now = Instant.now();
        Jwt jwt = Jwt.withTokenValue(token).header("alg", "RS256").issuer("https://identity.example.test")
                .audience(List.of("agentshield-api")).subject(user.getId().toString())
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(300))
                .claim("identity_type", "user").claim("user_id", user.getId().toString())
                .claim("organization_id", organization.getId().toString()).claim("organization_role", role).build();
        when(decoder.decode(token)).thenReturn(jwt);
    }
    private HttpResponse<String> get(String path, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri(path)).GET();
        if (token != null) request.header("Authorization", "Bearer " + token);
        return client.send(request.build(), BodyHandlers.ofString());
    }
    private URI uri(String path) { return URI.create("http://localhost:" + port + path); }
}
