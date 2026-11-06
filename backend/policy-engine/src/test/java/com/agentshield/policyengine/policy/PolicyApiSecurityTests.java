package com.agentshield.policyengine.policy;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import jakarta.servlet.DispatcherType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import com.agentshield.policyengine.policy.api.PolicyDefinitionRequest;
import com.agentshield.policyengine.policy.api.PolicyRuleRequest;
import com.agentshield.policyengine.policy.domain.AgentScope;
import com.agentshield.policyengine.policy.domain.RuleEffect;
import com.agentshield.policyengine.policy.persistence.PolicyRuleRepository;
import com.agentshield.policyengine.policy.persistence.SecurityPolicyRepository;
import com.agentshield.policyengine.policy.service.PolicyService;

@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class PolicyApiSecurityTests {
    @Autowired MockMvc mvc;
    @Autowired PolicyService service;
    @Autowired SecurityPolicyRepository policies;
    @Autowired PolicyRuleRepository rules;
    @MockitoBean(name="jwtDecoder") JwtDecoder decoder;
    @MockitoBean(name="agentAssertionJwtDecoder") JwtDecoder assertionDecoder;
    private static final String BASE="/api/v1/policies";

    @BeforeEach void clear() { rules.deleteAll(); policies.deleteAll(); }

    @Test void memberCanReadOnlyAndPolicyReadsAreTenantScoped() throws Exception {
        UUID first=UUID.randomUUID(), second=UUID.randomUUID();
        var created=service.create(first,definition());
        stub("member",UUID.randomUUID(),first,"MEMBER",false);
        stub("admin-other",UUID.randomUUID(),second,"ADMIN",false);
        mvc.perform(get(BASE).header("Authorization","Bearer member")).andExpect(status().isOk()).andExpect(jsonPath("$[0].policyId").value(created.policyId().toString()));
        mvc.perform(get(BASE+"/"+created.policyId()).header("Authorization","Bearer member")).andExpect(status().isOk());
        mvc.perform(get(BASE+"/"+created.policyId()).header("Authorization","Bearer admin-other")).andExpect(status().isNotFound());
        mvc.perform(post(BASE).header("Authorization","Bearer member").contentType(MediaType.APPLICATION_JSON).content(body())).andExpect(status().isForbidden());
        stub("owner",UUID.randomUUID(),first,"OWNER",false);
        stub("admin",UUID.randomUUID(),first,"ADMIN",false);
        mvc.perform(post(BASE).header("Authorization","Bearer owner").contentType(MediaType.APPLICATION_JSON).content(body())).andExpect(status().isCreated());
        mvc.perform(post(BASE).header("Authorization","Bearer admin").contentType(MediaType.APPLICATION_JSON).content(body())).andExpect(status().isCreated());
    }

    @Test void unauthenticatedAndNonGatewayEvaluationAreDenied() throws Exception {
        mvc.perform(get(BASE)).andExpect(status().isUnauthorized());
        UUID org=UUID.randomUUID(); stub("owner",UUID.randomUUID(),org,"OWNER",false);
        mvc.perform(post(BASE+"/evaluate").header("Authorization","Bearer owner").contentType(MediaType.APPLICATION_JSON)
                .content("{\"agentId\":\""+UUID.randomUUID()+"\",\"action\":\"tool.call\"}"))
                .andExpect(status().isForbidden());
        Instant now=Instant.now(); UUID agent=UUID.randomUUID();
        when(decoder.decode("agent-only")).thenReturn(Jwt.withTokenValue("agent-only").header("alg","RS256")
                .issuer("http://localhost:9000").audience(List.of("agentshield-runtime-api")).subject(agent.toString())
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(60)).claim("identity_type","agent")
                .claim("token_type","agent").claim("agent_id",agent.toString()).claim("organization_id",org.toString())
                .claim("agent_role","AGENT").build());
        mvc.perform(post(BASE+"/evaluate").header("Authorization","Bearer agent-only").contentType(MediaType.APPLICATION_JSON)
                .content("{\"agentId\":\""+agent+"\",\"action\":\"tool.call\"}"))
                .andExpect(status().isForbidden());
    }

    @Test void malformedAgentAssertionKeepsUnauthorizedStatusAfterGatewayAuthorization() throws Exception {
        UUID org=UUID.randomUUID(), agent=UUID.randomUUID();
        stub("gateway",UUID.randomUUID(),org,"MEMBER",true);
        when(assertionDecoder.decode("malformed-assertion"))
                .thenThrow(new org.springframework.security.oauth2.jwt.BadJwtException("invalid assertion"));

        mvc.perform(post(BASE+"/evaluate").header("Authorization","Bearer gateway").contentType(MediaType.APPLICATION_JSON)
                .header("X-Agent-Assertion","malformed-assertion").header("X-Organization-ID",org.toString())
                .content("{\"agentId\":\""+agent+"\",\"action\":\"tool.call\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test void missingAgentAssertionKeepsBadRequestStatusAfterGatewayAuthorization() throws Exception {
        UUID org=UUID.randomUUID(), agent=UUID.randomUUID();
        stub("gateway",UUID.randomUUID(),org,"MEMBER",true);

        mvc.perform(post(BASE+"/evaluate").header("Authorization","Bearer gateway").contentType(MediaType.APPLICATION_JSON)
                .header("X-Organization-ID",org.toString())
                .content("{\"agentId\":\""+agent+"\",\"action\":\"tool.call\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test void onlyServletErrorDispatchBypassesTheDefaultDenyMatcher() throws Exception {
        UUID org=UUID.randomUUID();
        stub("owner",UUID.randomUUID(),org,"OWNER",false);

        mvc.perform(get("/error").header("Authorization","Bearer owner"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/error").header("Authorization","Bearer owner")
                .with(request -> { request.setDispatcherType(DispatcherType.ERROR); return request; }))
                .andExpect(result -> assertNotEquals(403,result.getResponse().getStatus()));
    }

    @Test void gatewayEvaluationReturnsFailClosedDecision() throws Exception {
        UUID org=UUID.randomUUID(), agent=UUID.randomUUID(); stub("gateway",UUID.randomUUID(),org,"MEMBER",true);
        stubAgent("agent-assertion",agent,org);
        mvc.perform(post(BASE+"/evaluate").header("Authorization","Bearer gateway").contentType(MediaType.APPLICATION_JSON)
                .header("X-Agent-Assertion","agent-assertion")
                .header("X-Organization-ID",UUID.randomUUID().toString())
                .content("{\"agentId\":\""+agent+"\",\"action\":\"tool.call\"}"))
                .andExpect(status().isForbidden());
        mvc.perform(post(BASE+"/evaluate").header("Authorization","Bearer gateway").contentType(MediaType.APPLICATION_JSON)
                .header("X-Agent-Assertion","agent-assertion").header("X-Organization-ID",org.toString())
                .content("{\"agentId\":\""+agent+"\",\"action\":\"tool.call\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.reasonCode").value("NO_APPLICABLE_ALLOW"));
    }

    @Test void activePolicyAllowsThenMatchingDenyTakesPrecedence() throws Exception {
        UUID org=UUID.randomUUID(), agent=UUID.randomUUID();
        stub("gateway",UUID.randomUUID(),org,"MEMBER",true); stubAgent("agent-assertion",agent,org);
        var allow=service.create(org,new PolicyDefinitionRequest("Allow",null,10,List.of(new PolicyRuleRequest("allow",AgentScope.ALL_AGENTS,null,"tool.call",RuleEffect.ALLOW,null))));
        service.changeStatus(org,allow.policyId(),com.agentshield.policyengine.policy.domain.PolicyStatus.ACTIVE);
        mvc.perform(post(BASE+"/evaluate").header("Authorization","Bearer gateway").contentType(MediaType.APPLICATION_JSON)
                .header("X-Agent-Assertion","agent-assertion")
                .header("X-Organization-ID",org.toString())
                .content("{\"agentId\":\""+agent+"\",\"action\":\"tool.call\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.decision").value("ALLOW"))
                .andExpect(jsonPath("$.matchedRules[0].policyVersion").value(2));
        var deny=service.create(org,new PolicyDefinitionRequest("Deny",null,1,List.of(new PolicyRuleRequest("deny",AgentScope.SPECIFIC_AGENT,agent,"tool.call",RuleEffect.DENY,null))));
        service.changeStatus(org,deny.policyId(),com.agentshield.policyengine.policy.domain.PolicyStatus.ACTIVE);
        mvc.perform(post(BASE+"/evaluate").header("Authorization","Bearer gateway").contentType(MediaType.APPLICATION_JSON)
                .header("X-Agent-Assertion","agent-assertion")
                .header("X-Organization-ID",org.toString())
                .content("{\"agentId\":\""+agent+"\",\"action\":\"tool.call\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.reasonCode").value("MATCHED_DENY"));
        service.changeStatus(org,allow.policyId(),com.agentshield.policyengine.policy.domain.PolicyStatus.DISABLED);
        service.changeStatus(org,deny.policyId(),com.agentshield.policyengine.policy.domain.PolicyStatus.DISABLED);
        mvc.perform(post(BASE+"/evaluate").header("Authorization","Bearer gateway").contentType(MediaType.APPLICATION_JSON)
                .header("X-Agent-Assertion","agent-assertion")
                .header("X-Organization-ID",org.toString())
                .content("{\"agentId\":\""+agent+"\",\"action\":\"tool.call\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.reasonCode").value("NO_APPLICABLE_ALLOW"));
    }

    @Test void malformedTokenIsRejectedAtDecoderBoundary() throws Exception {
        when(decoder.decode("invalid")).thenThrow(new org.springframework.security.oauth2.jwt.BadJwtException("invalid"));
        mvc.perform(get(BASE).header("Authorization","Bearer invalid")).andExpect(status().isUnauthorized());
    }

    private void stub(String token,UUID user,UUID org,String role,boolean gateway) {
        Instant now=Instant.now(); var builder=Jwt.withTokenValue(token).header("alg","RS256").issuer("http://localhost:9000")
                .audience(List.of("agentshield-api")).subject(user.toString()).issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(60))
                .claim("user_id",user.toString()).claim("organization_id",org.toString()).claim("organization_role",role);
        if(gateway) builder.claim("client_id","runtime-gateway").claim("service_role","RUNTIME_GATEWAY").claim("scope","policy.evaluate");
        if(gateway) builder.claim("identity_type","service").claim("token_type","service").subject("runtime-gateway");
        else builder.claim("identity_type","user");
        when(decoder.decode(token)).thenReturn(builder.build());
    }
    private void stubAgent(String token,UUID agent,UUID org) {
        Instant now=Instant.now(); when(assertionDecoder.decode(token)).thenReturn(Jwt.withTokenValue(token).header("alg","RS256")
                .issuer("http://localhost:9000").audience(List.of("agentshield-runtime-api")).subject(agent.toString())
                .issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(60)).claim("identity_type","agent").claim("token_type","agent")
                .claim("agent_role","AGENT").claim("agent_id",agent.toString()).claim("organization_id",org.toString()).build());
    }
    private PolicyDefinitionRequest definition() { return new PolicyDefinitionRequest("Policy",null,1,List.of(new PolicyRuleRequest("Rule",AgentScope.ALL_AGENTS,null,"tool.call",RuleEffect.ALLOW,null))); }
    private String body() { return "{\"name\":\"Policy\",\"priority\":0,\"rules\":[{\"name\":\"Rule\",\"agentScope\":\"ALL_AGENTS\",\"action\":\"tool.call\",\"effect\":\"ALLOW\"}]}"; }
}
