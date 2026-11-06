package com.agentshield.identity.agentcredential.domain;

import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name="agent_credentials", uniqueConstraints=@UniqueConstraint(name="uk_agent_credentials_client_id", columnNames="client_id"))
public class AgentCredential {
    @Id @JdbcTypeCode(SqlTypes.CHAR) @Column(columnDefinition="char(36)", nullable=false)
    private UUID id;
    @Column(name="client_id", nullable=false, length=100, updatable=false) private String clientId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="agent_id", columnDefinition="char(36)", nullable=false, updatable=false) private UUID agentId;
    @JdbcTypeCode(SqlTypes.CHAR) @Column(name="organization_id", columnDefinition="char(36)", nullable=false, updatable=false) private UUID organizationId;
    @Enumerated(EnumType.STRING) @Column(nullable=false, length=16) private AgentCredentialStatus status;
    @Column(name="created_at", nullable=false, updatable=false) private Instant createdAt;
    @Column(name="revoked_at") private Instant revokedAt;
    protected AgentCredential() { }
    public AgentCredential(String clientId, UUID agentId, UUID organizationId) {
        this.id=UUID.randomUUID(); this.clientId=clientId; this.agentId=agentId; this.organizationId=organizationId; this.status=AgentCredentialStatus.ACTIVE;
    }
    @PrePersist void beforeInsert() { if(createdAt==null) createdAt=Instant.now(); }
    public void revoke() { if(status==AgentCredentialStatus.ACTIVE) { status=AgentCredentialStatus.REVOKED; revokedAt=Instant.now(); } }
    public UUID getId(){return id;} public String getClientId(){return clientId;} public UUID getAgentId(){return agentId;}
    public UUID getOrganizationId(){return organizationId;} public AgentCredentialStatus getStatus(){return status;}
    public Instant getCreatedAt(){return createdAt;} public Instant getRevokedAt(){return revokedAt;}
}
