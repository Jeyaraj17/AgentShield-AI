package com.agentshield.notification.api;

import java.time.Instant;
import java.util.UUID;
import com.agentshield.notification.persistence.NotificationEntity;

public record NotificationResponse(UUID notificationId,String category,String severity,String title,String description,
        String sourceEventType,UUID agentId,UUID executionId,String sourceIdentifier,UUID correlationId,
        Instant eventTimestamp,Instant createdAt,Instant readAt) {
    public static NotificationResponse from(NotificationEntity n){return new NotificationResponse(n.getNotificationId(),n.getCategory(),n.getSeverity(),n.getTitle(),n.getDescription(),
            n.getSourceEventType(),n.getAgentId(),n.getExecutionId(),n.getSourceIdentifier(),n.getCorrelationId(),n.getEventTimestamp(),n.getCreatedAt(),n.getReadAt());}
}
