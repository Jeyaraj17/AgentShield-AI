package com.agentshield.runtimesecurity.runtime.domain;

import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@Entity
@Table(name="runtime_executions",indexes={
        @Index(name="idx_runtime_execution_org_created",columnList="organization_id,created_at"),
        @Index(name="idx_runtime_execution_agent_created",columnList="agent_id,created_at")})
public class RuntimeExecution {
    @Id @JdbcTypeCode(SqlTypes.CHAR) @Column(columnDefinition="char(36)",nullable=false)
    private UUID id;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="organization_id",columnDefinition="char(36)",nullable=false,updatable=false)
    private UUID organizationId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="agent_id",columnDefinition="char(36)",nullable=false,updatable=false)
    private UUID agentId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="user_id",columnDefinition="char(36)",nullable=true,updatable=false)
    private UUID userId;
    @Column(name="action_identifier",length=150,nullable=false,updatable=false)
    private String action;
    @Column(name="resource_identifier",length=500,nullable=false,updatable=false)
    private String resourceId;
    @Enumerated(EnumType.STRING) @Column(name="authorization_decision",length=8,nullable=false)
    private AuthorizationDecision authorizationDecision;
    @Column(name="reason_code",length=80,nullable=false)
    private String reasonCode;
    @Enumerated(EnumType.STRING) @Column(name="execution_result",length=20,nullable=false)
    private ExecutionResult executionResult;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="correlation_id",columnDefinition="char(36)",nullable=false,updatable=false)
    private UUID correlationId;
    @Column(name="created_at",nullable=false,updatable=false)
    private Instant createdAt;
    @Column(name="completed_at")
    private Instant completedAt;
    protected RuntimeExecution() {}
    public RuntimeExecution(UUID organizationId,UUID agentId,UUID userId,String action,String resourceId,
            AuthorizationDecision decision,String reasonCode,ExecutionResult executionResult,UUID correlationId) {
        this.id=UUID.randomUUID(); this.organizationId=organizationId; this.agentId=agentId; this.userId=userId;
        this.action=action; this.resourceId=resourceId; this.authorizationDecision=decision;
        this.reasonCode=reasonCode; this.executionResult=executionResult; this.correlationId=correlationId;
    }
    @PrePersist void prePersist() { if(createdAt==null) createdAt=Instant.now(); }
    public void complete(ExecutionResult result) { this.executionResult=result; this.completedAt=Instant.now(); }
    public UUID getId(){return id;} public UUID getOrganizationId(){return organizationId;} public UUID getAgentId(){return agentId;}
    public UUID getUserId(){return userId;} public String getAction(){return action;} public String getResourceId(){return resourceId;}
    public AuthorizationDecision getAuthorizationDecision(){return authorizationDecision;} public String getReasonCode(){return reasonCode;}
    public ExecutionResult getExecutionResult(){return executionResult;} public UUID getCorrelationId(){return correlationId;}
    public Instant getCreatedAt(){return createdAt;} public Instant getCompletedAt(){return completedAt;}
}
