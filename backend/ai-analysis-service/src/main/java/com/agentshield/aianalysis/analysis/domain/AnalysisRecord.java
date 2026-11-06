package com.agentshield.aianalysis.analysis.domain;

import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Index;

@Entity
@Table(name="analysis_records",indexes={
        @Index(name="idx_analysis_tenant_agent_type_created",columnList="organization_id,agent_id,analysis_type,created_at"),
        @Index(name="idx_analysis_tenant_created",columnList="organization_id,created_at")})
public class AnalysisRecord {
    @Id @GeneratedValue(strategy=GenerationType.UUID) @JdbcTypeCode(SqlTypes.CHAR) @Column(columnDefinition="char(36)") private UUID id;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="organization_id",nullable=false,updatable=false,columnDefinition="char(36)") private UUID organizationId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="agent_id",nullable=false,updatable=false,columnDefinition="char(36)") private UUID agentId;
    @Enumerated(EnumType.STRING) @Column(name="analysis_type",nullable=false,length=40) private AnalysisType type;
    @Column(name="risk_score") private Integer riskScore;
    @Column(name="result_json",nullable=false,columnDefinition="text") private String resultJson;
    @Column(name="created_at",nullable=false,updatable=false) private Instant createdAt;
    protected AnalysisRecord() { }
    public AnalysisRecord(UUID organizationId,UUID agentId,AnalysisType type,Integer riskScore,String resultJson) {
        this.organizationId=organizationId;this.agentId=agentId;this.type=type;this.riskScore=riskScore;this.resultJson=resultJson;
    }
    @PrePersist void onCreate(){createdAt=Instant.now();}
    public UUID getId(){return id;} public UUID getOrganizationId(){return organizationId;} public UUID getAgentId(){return agentId;}
    public AnalysisType getType(){return type;} public Integer getRiskScore(){return riskScore;} public String getResultJson(){return resultJson;} public Instant getCreatedAt(){return createdAt;}
}
