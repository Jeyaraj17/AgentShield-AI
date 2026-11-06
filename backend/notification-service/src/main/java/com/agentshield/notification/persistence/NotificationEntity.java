package com.agentshield.notification.persistence;

import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Id;

@Entity
@Table(name="notifications",indexes={
        @Index(name="idx_notification_org_created",columnList="organization_id,created_at"),
        @Index(name="idx_notification_org_read_created",columnList="organization_id,read_at,created_at"),
        @Index(name="idx_notification_org_category_created",columnList="organization_id,category,created_at"),
        @Index(name="idx_notification_org_agent_created",columnList="organization_id,agent_id,created_at")})
public class NotificationEntity {
    @Id @JdbcTypeCode(SqlTypes.CHAR) @Column(name="notification_id",columnDefinition="char(36)",nullable=false,updatable=false)
    private UUID notificationId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="event_id",columnDefinition="char(36)",nullable=false,unique=true,updatable=false)
    private UUID eventId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="organization_id",columnDefinition="char(36)",nullable=false,updatable=false)
    private UUID organizationId;
    @Column(name="category",nullable=false,length=40,updatable=false) private String category;
    @Column(name="severity",nullable=false,length=16,updatable=false) private String severity;
    @Column(name="title",nullable=false,length=160,updatable=false) private String title;
    @Column(name="description",nullable=false,length=500,updatable=false) private String description;
    @Column(name="source_event_type",nullable=false,length=48,updatable=false) private String sourceEventType;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="agent_id",columnDefinition="char(36)",updatable=false) private UUID agentId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="execution_id",columnDefinition="char(36)",updatable=false) private UUID executionId;
    @Column(name="source_identifier",length=180,updatable=false) private String sourceIdentifier;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="correlation_id",columnDefinition="char(36)",nullable=false,updatable=false) private UUID correlationId;
    @Column(name="event_timestamp",nullable=false,updatable=false) private Instant eventTimestamp;
    @Column(name="created_at",nullable=false,updatable=false) private Instant createdAt;
    @Column(name="read_at") private Instant readAt;
    protected NotificationEntity() { }
    public NotificationEntity(UUID eventId,UUID organizationId,String category,String severity,String title,String description,
            String sourceEventType,UUID agentId,UUID executionId,String sourceIdentifier,UUID correlationId,Instant eventTimestamp) {
        this.notificationId=UUID.randomUUID();this.eventId=eventId;this.organizationId=organizationId;this.category=category;this.severity=severity;
        this.title=title;this.description=description;this.sourceEventType=sourceEventType;this.agentId=agentId;this.executionId=executionId;
        this.sourceIdentifier=sourceIdentifier;this.correlationId=correlationId;this.eventTimestamp=eventTimestamp;
    }
    @PrePersist void onCreate(){if(createdAt==null)createdAt=Instant.now();}
    public void markRead(){if(readAt==null)readAt=Instant.now();}
    public UUID getNotificationId(){return notificationId;} public UUID getEventId(){return eventId;} public UUID getOrganizationId(){return organizationId;}
    public String getCategory(){return category;} public String getSeverity(){return severity;} public String getTitle(){return title;} public String getDescription(){return description;}
    public String getSourceEventType(){return sourceEventType;} public UUID getAgentId(){return agentId;} public UUID getExecutionId(){return executionId;}
    public String getSourceIdentifier(){return sourceIdentifier;} public UUID getCorrelationId(){return correlationId;} public Instant getEventTimestamp(){return eventTimestamp;}
    public Instant getCreatedAt(){return createdAt;} public Instant getReadAt(){return readAt;}
}
