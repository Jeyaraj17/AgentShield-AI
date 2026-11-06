package com.agentshield.agentmanagement.agent.domain;

import java.time.Instant;
import java.util.List;
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
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Index;

@Entity
@Table(name = "agents", uniqueConstraints = {
        @UniqueConstraint(name = "uk_agents_organization_code", columnNames = {"organization_id", "agent_code"})
}, indexes = {
        @Index(name = "idx_agents_organization_id", columnList = "organization_id"),
        @Index(name = "idx_agents_organization_status", columnList = "organization_id,status")
})
public class Agent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(columnDefinition = "char(36)")
    private UUID id;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "organization_id", nullable = false, updatable = false)
    private UUID organizationId;

    @Column(name = "agent_name", nullable = false, length = 150)
    private String name;

    @Column(name = "agent_code", nullable = false, length = 50)
    private String agentCode;

    @Column(length = 1000)
    private String description;

    @Column(name = "agent_type", nullable = false, length = 50)
    private String agentType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private AgentStatus status;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(nullable = false, columnDefinition = "json")
    private List<String> capabilities;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected Agent() {
        // Required by JPA.
    }

    public Agent(UUID organizationId, String name, String agentCode, String description,
            String agentType, List<String> capabilities) {
        this.organizationId = organizationId;
        this.name = name;
        this.agentCode = agentCode;
        this.description = description;
        this.agentType = agentType;
        this.capabilities = List.copyOf(capabilities);
        this.status = AgentStatus.ACTIVE;
    }

    public void updateDetails(String name, String agentCode, String description,
            String agentType, List<String> capabilities) {
        this.name = name;
        this.agentCode = agentCode;
        this.description = description;
        this.agentType = agentType;
        this.capabilities = List.copyOf(capabilities);
    }

    public void changeStatus(AgentStatus status) {
        this.status = status;
    }

    @PrePersist
    void setCreationTimestamps() {
        Instant now = Instant.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void setUpdateTimestamp() {
        updatedAt = Instant.now();
    }

    public UUID getId() { return id; }
    public UUID getOrganizationId() { return organizationId; }
    public String getName() { return name; }
    public String getAgentCode() { return agentCode; }
    public String getDescription() { return description; }
    public String getAgentType() { return agentType; }
    public AgentStatus getStatus() { return status; }
    public List<String> getCapabilities() { return capabilities; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
