package com.agentshield.audit;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import com.agentshield.audit.persistence.AuditEventEntity;
import com.agentshield.audit.persistence.AuditEventRepository;
import com.agentshield.events.contract.EventType;

@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class AuditApiSecurityTests {
    @Autowired MockMvc mvc; @Autowired AuditEventRepository repository;
    @MockitoBean(name="jwtDecoder") JwtDecoder decoder;
    private final UUID org=UUID.randomUUID(),otherOrg=UUID.randomUUID(),user=UUID.randomUUID(),agent=UUID.randomUUID();
    @BeforeEach void resetData(){repository.deleteAll();reset(decoder);}

    @Test void tenantScopedSearchSupportsFiltersAndPagination() throws Exception {
        seed(org,EventType.RUNTIME_AUTHORIZATION_ALLOW,"ALLOW",null);
        seed(org,EventType.RUNTIME_AUTHORIZATION_DENY,"DENY",null);
        seed(org,EventType.RUNTIME_AUTHORIZATION_DENY,"DENY",null);
        seed(otherOrg,EventType.RUNTIME_AUTHORIZATION_DENY,"DENY",null);
        authenticate("owner",org,"OWNER");
        mvc.perform(get("/api/v1/audit/events").header("Authorization","Bearer owner").param("outcome","DENY").param("page","0").param("size","1"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(2)).andExpect(jsonPath("$.content.length()").value(1)).andExpect(jsonPath("$.content[0].decision").value("DENY"));
        var own=repository.findAll().stream().filter(e->e.getOrganizationId().equals(org)).findFirst().orElseThrow();
        mvc.perform(get("/api/v1/audit/events/"+own.getEventId()).header("Authorization","Bearer owner"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.organizationId").value(org.toString()));
        mvc.perform(get("/api/v1/audit/events").header("Authorization","Bearer owner").param("from","2030-01-01T00:00:00Z").param("to","2020-01-01T00:00:00Z"))
                .andExpect(status().isBadRequest());
    }

    @Test void memberCanReadOperationalEventsButNotPolicyOrTrustConfiguration(){
        var operational=seed(org,EventType.TOOL_EXECUTION_SUCCEEDED,null,"SUCCEEDED");
        seed(org,EventType.POLICY_CREATED,null,null);
        seed(org,EventType.AGENT_TRUST_SCORE_UPDATED,null,null);
        authenticate("member",org,"MEMBER");
        try {
            mvc.perform(get("/api/v1/audit/events").header("Authorization","Bearer member"))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(1));
            mvc.perform(get("/api/v1/audit/events/"+operational.getEventId()).header("Authorization","Bearer member"))
                    .andExpect(status().isOk());
            var restricted=repository.findAll().stream().filter(e->e.getEventType()==EventType.POLICY_CREATED).findFirst().orElseThrow();
            mvc.perform(get("/api/v1/audit/events/"+restricted.getEventId()).header("Authorization","Bearer member"))
                    .andExpect(status().isNotFound());
            mvc.perform(get("/api/v1/audit/summary").header("Authorization","Bearer member"))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.totalEvents").value(1));
        } catch(Exception ex){throw new AssertionError(ex);}
    }

    @Test void requiresAuthenticatedOrganizationUserAndHidesOtherTenantEvent() throws Exception {
        var row=seed(otherOrg,EventType.RUNTIME_AUTHORIZATION_DENY,"DENY",null);
        mvc.perform(get("/api/v1/audit/events")).andExpect(status().isUnauthorized());
        authenticate("different-tenant",org,"ADMIN");
        mvc.perform(get("/api/v1/audit/events/"+row.getEventId()).header("Authorization","Bearer different-tenant"))
                .andExpect(status().isNotFound());
        when(decoder.decode("invalid")).thenThrow(new org.springframework.security.oauth2.jwt.BadJwtException("invalid"));
        mvc.perform(get("/api/v1/audit/events").header("Authorization","Bearer invalid")).andExpect(status().isUnauthorized());
    }

    private AuditEventEntity seed(UUID tenant,EventType type,String decision,String outcome){
        return repository.saveAndFlush(new AuditEventEntity(UUID.randomUUID(),tenant,type,"audit-test","SERVICE",agent,
                type.name(),agent.toString(),decision,null,outcome,UUID.randomUUID(),Instant.now(),Instant.now()));
    }
    private void authenticate(String token,UUID tenant,String role){
        Instant now=Instant.now();when(decoder.decode(token)).thenReturn(Jwt.withTokenValue(token).header("alg","RS256").issuer("http://localhost:9000")
                .audience(List.of("agentshield-api")).subject(user.toString()).issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(60))
                .claim("identity_type","user").claim("user_id",user.toString()).claim("organization_id",tenant.toString()).claim("organization_role",role).build());
    }
}
