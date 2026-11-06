package com.agentshield.notification;

import static org.mockito.Mockito.when;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.contract.SecurityEvent;
import com.agentshield.events.inbox.InboxEventProcessor;
import com.agentshield.notification.persistence.NotificationRepository;
import tools.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class NotificationApiSecurityTests {
    @Autowired MockMvc mvc;
    @Autowired InboxEventProcessor inbox;
    @Autowired NotificationRepository repository;
    @Autowired ObjectMapper mapper;
    @MockitoBean JwtDecoder decoder;

    @Test void onlyOwnerAndAdminTokensCanReadAndTenantOrRoleHeadersCannotElevateMember(){
        UUID org=UUID.randomUUID();when(decoder.decode("owner")).thenReturn(jwt("owner",org,"OWNER"));
        when(decoder.decode("member")).thenReturn(jwt("member",org,"MEMBER"));
        try {
            mvc.perform(get("/api/v1/notifications").header(HttpHeaders.AUTHORIZATION,"Bearer owner"))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.content").isArray());
            mvc.perform(get("/api/v1/notifications").header(HttpHeaders.AUTHORIZATION,"Bearer member")
                    .header("X-Organization-Id",UUID.randomUUID().toString()).header("X-Role","OWNER"))
                    .andExpect(status().isForbidden());
        } catch(Exception ex){throw new AssertionError(ex);}
    }

    @Test void invalidAndMissingBearerTokensAreRejected(){
        when(decoder.decode("bad")).thenThrow(new BadJwtException("invalid"));
        try {
            mvc.perform(get("/api/v1/notifications")).andExpect(status().isUnauthorized());
            mvc.perform(get("/api/v1/notifications").header(HttpHeaders.AUTHORIZATION,"Bearer bad")).andExpect(status().isUnauthorized());
        } catch(Exception ex){throw new AssertionError(ex);}
    }

    @Test void eventInboxMakesNotificationCreationIdempotentAndDoesNotCopyRawContent(){
        UUID organization=UUID.randomUUID();var event=SecurityEvent.create(organization,EventType.AI_THREAT_DETECTED,UUID.randomUUID(),Map.of(
                "agentId",UUID.randomUUID().toString(),"analysisId",UUID.randomUUID().toString(),"category","PROMPT_INJECTION","riskScore","91"));
        String payload=mapper.writeValueAsString(event);long before=repository.count();
        org.junit.jupiter.api.Assertions.assertTrue(inbox.process(payload));org.junit.jupiter.api.Assertions.assertFalse(inbox.process(payload));
        org.junit.jupiter.api.Assertions.assertEquals(before+1,repository.count());
        var saved=repository.findAll().stream().filter(n->n.getEventId().equals(event.eventId())).findFirst().orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals("CRITICAL",saved.getSeverity());
        org.junit.jupiter.api.Assertions.assertFalse(saved.getDescription().contains("prompt"));
    }

    private static Jwt jwt(String subject,UUID org,String role){
        Instant now=Instant.now();String userId=UUID.randomUUID().toString();return Jwt.withTokenValue(subject).header("alg","RS256").issuer("http://localhost:9000")
                .audience(List.of("agentshield-api","notification-service-api")).subject(userId).issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(300))
                .claim("identity_type","user").claim("token_type","user").claim("user_id",userId)
                .claim("organization_id",org.toString()).claim("organization_role",role).build();
    }
}
