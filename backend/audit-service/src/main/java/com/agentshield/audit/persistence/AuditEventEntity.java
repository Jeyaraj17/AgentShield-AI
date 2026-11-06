package com.agentshield.audit.persistence;

import java.time.Instant;
import java.util.UUID;
import com.agentshield.events.contract.EventType;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

@Entity
@Table(name="audit_events", indexes={
        @Index(name="idx_audit_org_time",columnList="organization_id,event_timestamp"),
        @Index(name="idx_audit_org_type_time",columnList="organization_id,event_type,event_timestamp"),
        @Index(name="idx_audit_org_agent_time",columnList="organization_id,agent_id,event_timestamp"),
        @Index(name="idx_audit_org_execution",columnList="organization_id,execution_id"),
        @Index(name="idx_audit_org_outcome_time",columnList="organization_id,execution_outcome,event_timestamp")})
public class AuditEventEntity {
    @Id @JdbcTypeCode(SqlTypes.CHAR) @Column(name="event_id",columnDefinition="char(36)",nullable=false,updatable=false)
    private UUID eventId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="organization_id",columnDefinition="char(36)",nullable=false,updatable=false)
    private UUID organizationId;
    @Enumerated(EnumType.STRING) @Column(name="event_type",nullable=false,length=48,updatable=false)
    private EventType eventType;
    @Column(name="actor_identity",nullable=false,length=100,updatable=false)
    private String actorIdentity;
    @Column(name="actor_type",nullable=false,length=16,updatable=false)
    private String actorType;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="agent_id",columnDefinition="char(36)",updatable=false)
    private UUID agentId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="execution_id",columnDefinition="char(36)",updatable=false)
    private UUID executionId;
    @Column(name="action_name",length=160,updatable=false)
    private String action;
    @Column(name="resource_identifier",length=500,updatable=false)
    private String resource;
    @Column(name="decision",length=16,updatable=false)
    private String decision;
    @Column(name="reason",length=100,updatable=false)
    private String reason;
    @Column(name="execution_outcome",length=20,updatable=false)
    private String executionOutcome;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="correlation_id",columnDefinition="char(36)",nullable=false,updatable=false)
    private UUID correlationId;
    @Column(name="event_timestamp",nullable=false,updatable=false)
    private Instant eventTimestamp;
    @Column(name="received_timestamp",nullable=false,updatable=false)
    private Instant receivedTimestamp;

    protected AuditEventEntity() { }
    public AuditEventEntity(UUID eventId,UUID organizationId,EventType eventType,String actorIdentity,String actorType,UUID agentId,
            String action,String resource,String decision,String reason,String executionOutcome,UUID correlationId,Instant eventTimestamp,Instant receivedTimestamp) {
        this(eventId,organizationId,eventType,actorIdentity,actorType,agentId,null,action,resource,decision,reason,executionOutcome,correlationId,eventTimestamp,receivedTimestamp);
    }
    public AuditEventEntity(UUID eventId,UUID organizationId,EventType eventType,String actorIdentity,String actorType,UUID agentId,UUID executionId,
            String action,String resource,String decision,String reason,String executionOutcome,UUID correlationId,Instant eventTimestamp,Instant receivedTimestamp) {
        this.eventId=eventId;this.organizationId=organizationId;this.eventType=eventType;this.actorIdentity=actorIdentity;this.actorType=actorType;
        this.executionId=executionId;
        this.agentId=agentId;this.action=action;this.resource=resource;this.decision=decision;this.reason=reason;this.executionOutcome=executionOutcome;
        this.correlationId=correlationId;this.eventTimestamp=eventTimestamp;this.receivedTimestamp=receivedTimestamp;
    }
    public UUID getEventId(){return eventId;} public UUID getOrganizationId(){return organizationId;} public EventType getEventType(){return eventType;}
    public String getActorIdentity(){return actorIdentity;} public String getActorType(){return actorType;} public UUID getAgentId(){return agentId;} public UUID getExecutionId(){return executionId;}
    public String getAction(){return action;} public String getResource(){return resource;} public String getDecision(){return decision;}
    public String getReason(){return reason;} public String getExecutionOutcome(){return executionOutcome;} public UUID getCorrelationId(){return correlationId;}
    public Instant getEventTimestamp(){return eventTimestamp;} public Instant getReceivedTimestamp(){return receivedTimestamp;}
}
