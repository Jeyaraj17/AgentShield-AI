package com.agentshield.agentmanagement.agent;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.agentshield.agentmanagement.agent.api.CreateAgentRequest;
import com.agentshield.agentmanagement.agent.persistence.AgentRepository;
import com.agentshield.agentmanagement.agent.service.AgentService;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class InternalAgentDirectorySecurityTests {
    @Autowired MockMvc mvc;
    @Autowired AgentService agentService;
    @Autowired AgentRepository agents;
    @MockitoBean(name = "jwtDecoder") JwtDecoder decoder;

    @BeforeEach void clearAgents() { agents.deleteAll(); }

    @Test
    void scopedRuntimeGatewayCanCallInternalLookupAndTenantIsPassedToQuery() throws Exception {
        UUID org = UUID.randomUUID();
        UUID otherOrg = UUID.randomUUID();
        var created = agentService.register(org, new CreateAgentRequest("Agent", "agent-1", null, "ASSISTANT", List.of()));
        UUID agent = created.id();
        Instant now = Instant.now();
        when(decoder.decode("gateway")).thenReturn(Jwt.withTokenValue("gateway").header("alg", "RS256")
                .issuer("http://identity.test").audience(List.of("agentshield-agent-management-api"))
                .subject("agentshield-runtime-gateway").issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(60))
                .claim("client_id", "agentshield-runtime-gateway").claim("identity_type", "service")
                .claim("token_type", "service").claim("service_role", "RUNTIME_GATEWAY")
                .claim("scope", "agents.read").build());
        mvc.perform(get("/internal/v1/agents/{id}", agent).header("Authorization", "Bearer gateway")
                        .header("X-Organization-ID", org))
                .andExpect(status().isOk());
        mvc.perform(get("/internal/v1/agents/{id}", agent).header("Authorization", "Bearer gateway")
                        .header("X-Organization-ID", otherOrg))
                .andExpect(status().isNotFound());
    }

    @Test
    void userAndAgentTokensCannotCallInternalLookup() throws Exception {
        UUID user = UUID.randomUUID();
        UUID org = UUID.randomUUID();
        Instant now = Instant.now();
        when(decoder.decode("user")).thenReturn(Jwt.withTokenValue("user").header("alg", "RS256")
                .issuer("http://identity.test").audience(List.of("agentshield-api")).subject(user.toString())
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(60)).claim("user_id", user.toString())
                .claim("organization_id", org.toString()).claim("organization_role", "OWNER")
                .claim("identity_type", "user").build());
        when(decoder.decode("agent")).thenReturn(Jwt.withTokenValue("agent").header("alg", "RS256")
                .issuer("http://identity.test").audience(List.of("agentshield-runtime-api")).subject(UUID.randomUUID().toString())
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(60)).claim("identity_type", "agent")
                .claim("token_type", "agent").claim("agent_role", "AGENT").build());

        mvc.perform(get("/internal/v1/agents/{id}", UUID.randomUUID()).header("Authorization", "Bearer user")
                        .header("X-Organization-ID", org))
                .andExpect(status().isForbidden());
        mvc.perform(get("/internal/v1/agents/{id}", UUID.randomUUID()).header("Authorization", "Bearer agent")
                        .header("X-Organization-ID", org))
                .andExpect(status().isUnauthorized());
    }
}
