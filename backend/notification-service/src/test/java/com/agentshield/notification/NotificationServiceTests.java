package com.agentshield.notification;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.contract.SecurityEvent;
import com.agentshield.notification.event.NotificationEventHandler;
import com.agentshield.notification.persistence.NotificationEntity;
import com.agentshield.notification.persistence.NotificationRepository;
import com.agentshield.notification.security.NotificationPrincipal;
import com.agentshield.notification.service.NotificationService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.server.ResponseStatusException;

class NotificationServiceTests {
    @Test void eventHandlerCreatesSafeNotificationAndKeepsTenantExecutionAndCorrelation() {
        NotificationRepository repository=mock(NotificationRepository.class);NotificationEventHandler handler=new NotificationEventHandler(repository);
        UUID org=UUID.randomUUID(),agent=UUID.randomUUID(),execution=UUID.randomUUID(),correlation=UUID.randomUUID();
        SecurityEvent event=SecurityEvent.createV2(org,EventType.RUNTIME_AUTHORIZATION_DENY,correlation,java.util.Map.of(
                "agentId",agent.toString(),"actorId",agent.toString(),"actorType","AGENT","executionId",execution.toString(),
                "action","database.query","resourceId","customer-records","reasonCode","POLICY_DENY"));
        handler.handle(event);
        var captor=ArgumentCaptor.forClass(NotificationEntity.class);verify(repository).save(captor.capture());
        NotificationEntity notification=captor.getValue();assertEquals(org,notification.getOrganizationId());assertEquals(agent,notification.getAgentId());
        assertEquals(execution,notification.getExecutionId());assertEquals(correlation,notification.getCorrelationId());
        assertEquals("HIGH",notification.getSeverity());assertFalse(notification.getDescription().contains("customer-records"));
    }

    @Test void searchAlwaysUsesClaimTenantAndRejectsBadFilters() {
        NotificationRepository repository=mock(NotificationRepository.class);NotificationService service=new NotificationService(repository);
        UUID user=UUID.randomUUID(),org=UUID.randomUUID();var principal=new NotificationPrincipal(user,org,"OWNER");
        when(repository.search(eq(org),eq("AI_THREAT"),isNull(),eq(true),isNull(),isNull(),any())).thenReturn(new PageImpl<>(java.util.List.of()));
        service.search(principal,"AI_THREAT",null,true,null,null,0,20);
        verify(repository).search(eq(org),eq("AI_THREAT"),isNull(),eq(true),isNull(),isNull(),any());
        assertThrows(ResponseStatusException.class,()->service.search(principal,"UNKNOWN",null,null,null,null,0,20));
    }

    @Test void guessedNotificationIdCannotCrossTenantBoundaryAndReadAllIsScoped() {
        NotificationRepository repository=mock(NotificationRepository.class);NotificationService service=new NotificationService(repository);
        var principal=new NotificationPrincipal(UUID.randomUUID(),UUID.randomUUID(),"ADMIN");UUID id=UUID.randomUUID();
        when(repository.findByNotificationIdAndOrganizationId(id,principal.organizationId())).thenReturn(Optional.empty());
        assertEquals(404,assertThrows(ResponseStatusException.class,()->service.get(principal,id)).getStatusCode().value());
        when(repository.markAllRead(eq(principal.organizationId()),any(Instant.class))).thenReturn(3);
        assertEquals(3,service.markAllRead(principal));verify(repository).markAllRead(eq(principal.organizationId()),any(Instant.class));
    }
}
