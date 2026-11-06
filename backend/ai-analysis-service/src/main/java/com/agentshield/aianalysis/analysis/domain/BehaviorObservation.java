package com.agentshield.aianalysis.analysis.domain;

import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Index;

@Entity
@Table(name="behavior_observations",indexes=@Index(name="idx_behavior_tenant_agent_created",columnList="organization_id,agent_id,created_at"))
public class BehaviorObservation {
    @Id @GeneratedValue(strategy=GenerationType.UUID) @JdbcTypeCode(SqlTypes.CHAR) @Column(columnDefinition="char(36)") private UUID id;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="organization_id",nullable=false,updatable=false,columnDefinition="char(36)") private UUID organizationId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="agent_id",nullable=false,updatable=false,columnDefinition="char(36)") private UUID agentId;
    @Column(name="tool_call_count",nullable=false) private int toolCallCount;
    @Column(name="error_count",nullable=false) private int errorCount;
    @Column(name="policy_violation_count",nullable=false) private int policyViolationCount;
    @Column(name="unusual_activity_count",nullable=false) private int unusualActivityCount;
    @Column(name="action_distribution_json",nullable=false,columnDefinition="text") private String actionDistributionJson;
    @Column(name="drift_score",nullable=false) private int driftScore;
    @Column(name="drift_detected",nullable=false) private boolean driftDetected;
    @Column(name="created_at",nullable=false,updatable=false) private Instant createdAt;
    protected BehaviorObservation() { }
    public BehaviorObservation(UUID org,UUID agent,int calls,int errors,int violations,int unusual,String actions,int score,boolean detected) {
        organizationId=org;agentId=agent;toolCallCount=calls;errorCount=errors;policyViolationCount=violations;
        unusualActivityCount=unusual;actionDistributionJson=actions;driftScore=score;driftDetected=detected;
    }
    @PrePersist void onCreate(){createdAt=Instant.now();}
    public UUID getId(){return id;} public UUID getOrganizationId(){return organizationId;} public UUID getAgentId(){return agentId;}
    public int getToolCallCount(){return toolCallCount;} public int getErrorCount(){return errorCount;} public int getPolicyViolationCount(){return policyViolationCount;}
    public int getUnusualActivityCount(){return unusualActivityCount;} public String getActionDistributionJson(){return actionDistributionJson;}
    public int getDriftScore(){return driftScore;} public boolean isDriftDetected(){return driftDetected;} public Instant getCreatedAt(){return createdAt;}
}
