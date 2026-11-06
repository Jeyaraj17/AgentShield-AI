package com.agentshield.agentmanagement.agent;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.agentshield.agentmanagement.agent.domain.Agent;
import com.agentshield.agentmanagement.agent.domain.AgentStatus;
import com.agentshield.agentmanagement.agent.persistence.AgentRepository;

import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.anyString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AgentManagementApiTests {

    private static final String BASE = "/api/v1/agents";
    private static final UUID USER_ID = UUID.randomUUID();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AgentRepository agentRepository;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @BeforeEach
    void cleanAgents() {
        agentRepository.deleteAll();
    }

    @Test
    void createsAgentForTenantFromVerifiedTokenAndValidatesRequest() throws Exception {
        UUID organizationId = UUID.randomUUID();
        stubToken("owner", USER_ID, organizationId, "OWNER");

        mockMvc.perform(post(BASE).header("Authorization", "Bearer owner")
                        .contentType(MediaType.APPLICATION_JSON).content(request("Agent One", "Agent-01")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.organizationId").value(organizationId.toString()))
                .andExpect(jsonPath("$.agentCode").value("AGENT-01"))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.capabilities[0]").value("search"));

        mockMvc.perform(post(BASE).header("Authorization", "Bearer owner")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request(" ", "invalid")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void duplicateCodesConflictWithinOrganizationButMayRepeatAcrossOrganizations() throws Exception {
        UUID firstOrganization = UUID.randomUUID();
        UUID secondOrganization = UUID.randomUUID();
        stubToken("first-owner", USER_ID, firstOrganization, "OWNER");
        stubToken("second-owner", USER_ID, secondOrganization, "OWNER");

        mockMvc.perform(post(BASE).header("Authorization", "Bearer first-owner")
                        .contentType(MediaType.APPLICATION_JSON).content(request("Agent One", "agent-unique")))
                .andExpect(status().isCreated());
        mockMvc.perform(post(BASE).header("Authorization", "Bearer first-owner")
                        .contentType(MediaType.APPLICATION_JSON).content(request("Agent Two", "AGENT-UNIQUE")))
                .andExpect(status().isConflict());
        mockMvc.perform(post(BASE).header("Authorization", "Bearer second-owner")
                        .contentType(MediaType.APPLICATION_JSON).content(request("Agent Other Tenant", "agent-unique")))
                .andExpect(status().isCreated());
    }

    @Test
    void listingIsPaginatedAndScopedToAuthenticatedOrganization() throws Exception {
        UUID organizationId = UUID.randomUUID();
        UUID otherOrganizationId = UUID.randomUUID();
        stubToken("member", USER_ID, organizationId, "MEMBER");
        agentRepository.saveAllAndFlush(List.of(
                agent(organizationId, "One", "ONE"),
                agent(organizationId, "Two", "TWO"),
                agent(organizationId, "Three", "THREE"),
                agent(otherOrganizationId, "Foreign", "FOREIGN")));

        mockMvc.perform(get(BASE).header("Authorization", "Bearer member").param("page", "0").param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(2))
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(2))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(2));
    }

    @Test
    void managerCanUpdateChangeStatusAndSoftDeactivate() throws Exception {
        UUID organizationId = UUID.randomUUID();
        stubToken("admin", USER_ID, organizationId, "ADMIN");
        Agent stored = agentRepository.saveAndFlush(agent(organizationId, "Before", "BEFORE"));

        mockMvc.perform(put(BASE + "/" + stored.getId()).header("Authorization", "Bearer admin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request("After", "AFTER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("After"))
                .andExpect(jsonPath("$.agentCode").value("AFTER"));
        mockMvc.perform(patch(BASE + "/" + stored.getId() + "/status")
                        .header("Authorization", "Bearer admin")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"SUSPENDED\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SUSPENDED"));
        mockMvc.perform(delete(BASE + "/" + stored.getId()).header("Authorization", "Bearer admin"))
                .andExpect(status().isNoContent());

        Agent retained = agentRepository.findById(stored.getId()).orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals(AgentStatus.INACTIVE, retained.getStatus());
    }

    @Test
    void ownerAndAdminMayManageButMemberIsReadOnly() throws Exception {
        UUID organizationId = UUID.randomUUID();
        Agent stored = agentRepository.saveAndFlush(agent(organizationId, "Read Only", "READ"));
        stubToken("owner", USER_ID, organizationId, "OWNER");
        stubToken("admin", UUID.randomUUID(), organizationId, "ADMIN");
        stubToken("member", UUID.randomUUID(), organizationId, "MEMBER");

        mockMvc.perform(get(BASE + "/" + stored.getId()).header("Authorization", "Bearer member"))
                .andExpect(status().isOk());
        mockMvc.perform(post(BASE).header("Authorization", "Bearer member")
                        .contentType(MediaType.APPLICATION_JSON).content(request("Denied", "DENIED")))
                .andExpect(status().isForbidden());
        mockMvc.perform(put(BASE + "/" + stored.getId()).header("Authorization", "Bearer member")
                        .contentType(MediaType.APPLICATION_JSON).content(request("Denied", "DENIED")))
                .andExpect(status().isForbidden());
        mockMvc.perform(patch(BASE + "/" + stored.getId() + "/status")
                        .header("Authorization", "Bearer member").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"SUSPENDED\"}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(delete(BASE + "/" + stored.getId()).header("Authorization", "Bearer member"))
                .andExpect(status().isForbidden());

        mockMvc.perform(post(BASE).header("Authorization", "Bearer owner")
                        .contentType(MediaType.APPLICATION_JSON).content(request("Owner Managed", "OWNER-AGENT")))
                .andExpect(status().isCreated());
        mockMvc.perform(post(BASE).header("Authorization", "Bearer admin")
                        .contentType(MediaType.APPLICATION_JSON).content(request("Admin Managed", "ADMIN-AGENT")))
                .andExpect(status().isCreated());
    }

    @Test
    void guessedCrossOrganizationIdsCannotBeReadUpdatedOrDeleted() throws Exception {
        UUID authenticatedOrganization = UUID.randomUUID();
        UUID foreignOrganization = UUID.randomUUID();
        stubToken("owner", USER_ID, authenticatedOrganization, "OWNER");
        Agent foreign = agentRepository.saveAndFlush(agent(foreignOrganization, "Private", "PRIVATE"));

        mockMvc.perform(get(BASE).header("Authorization", "Bearer owner"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(0));
        mockMvc.perform(get(BASE + "/" + foreign.getId()).header("Authorization", "Bearer owner"))
                .andExpect(status().isNotFound());
        mockMvc.perform(put(BASE + "/" + foreign.getId()).header("Authorization", "Bearer owner")
                        .contentType(MediaType.APPLICATION_JSON).content(request("Attempted", "ATTEMPTED")))
                .andExpect(status().isNotFound());
        mockMvc.perform(delete(BASE + "/" + foreign.getId()).header("Authorization", "Bearer owner"))
                .andExpect(status().isNotFound());
        org.junit.jupiter.api.Assertions.assertEquals(AgentStatus.ACTIVE,
                agentRepository.findById(foreign.getId()).orElseThrow().getStatus());
    }

    @Test
    void unauthenticatedInvalidJwtAndMissingTenantClaimsAreDenied() throws Exception {
        mockMvc.perform(get(BASE)).andExpect(status().isUnauthorized());
        mockMvc.perform(post(BASE).contentType(MediaType.APPLICATION_JSON).content(request("No Auth", "NOAUTH")))
                .andExpect(status().isUnauthorized());

        when(jwtDecoder.decode("bad-token")).thenThrow(new InvalidBearerTokenException("invalid token"));
        mockMvc.perform(get(BASE).header("Authorization", "Bearer bad-token"))
                .andExpect(status().isUnauthorized());

        when(jwtDecoder.decode("missing-tenant")).thenReturn(jwt("missing-tenant", USER_ID, null, "MEMBER"));
        mockMvc.perform(get(BASE).header("Authorization", "Bearer missing-tenant"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unapprovedCorsOriginIsRejected() throws Exception {
        mockMvc.perform(options(BASE)
                        .header("Origin", "https://unapproved.example.test")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isForbidden());
    }

    private void stubToken(String token, UUID userId, UUID organizationId, String role) {
        when(jwtDecoder.decode(token)).thenReturn(jwt(token, userId, organizationId, role));
    }

    private Jwt jwt(String token, UUID userId, UUID organizationId, String role) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .issuer("http://identity.test")
                .audience(List.of("agentshield-api"))
                .subject(userId.toString())
                .issuedAt(now.minusSeconds(1))
                .expiresAt(now.plusSeconds(300))
                .claim("user_id", userId.toString())
                .claim("organization_role", role);
        if (organizationId != null) {
            builder.claim("organization_id", organizationId.toString());
        }
        return builder.build();
    }

    private Agent agent(UUID organizationId, String name, String code) {
        return new Agent(organizationId, name, code, null, "ASSISTANT", List.of("search"));
    }

    private String request(String name, String code) {
        return "{\"name\":\"" + name + "\",\"agentCode\":\"" + code
                + "\",\"agentType\":\"assistant\",\"capabilities\":[\"search\"]}";
    }
}
