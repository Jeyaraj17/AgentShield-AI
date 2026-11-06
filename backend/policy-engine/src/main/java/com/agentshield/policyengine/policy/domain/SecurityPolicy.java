package com.agentshield.policyengine.policy.domain;

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
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "security_policies", uniqueConstraints = {
        @UniqueConstraint(name = "uk_policy_org_key_version",
                columnNames = {"organization_id", "policy_id", "version_number"})
}, indexes = {
        @Index(name = "idx_policies_org_latest", columnList = "organization_id,is_latest"),
        @Index(name = "idx_policies_org_policy", columnList = "organization_id,policy_id,version_number")
})
public class SecurityPolicy {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(columnDefinition = "char(36)")
    private UUID id;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "policy_id", nullable = false, columnDefinition = "char(36)")
    private UUID policyId;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "organization_id", nullable = false, updatable = false, columnDefinition = "char(36)")
    private UUID organizationId;

    @Column(name = "policy_name", nullable = false, length = 150)
    private String name;

    @Column(length = 1000)
    private String description;

    @Column(name = "version_number", nullable = false)
    private int version;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private PolicyStatus status;

    @Column(nullable = false)
    private int priority;

    @Column(name = "is_latest", nullable = false)
    private boolean latestVersion;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected SecurityPolicy() {
        // Required by JPA.
    }

    public SecurityPolicy(UUID id, UUID policyId, UUID organizationId, String name, String description,
            int version, PolicyStatus status, int priority, boolean latestVersion) {
        this.id = id;
        this.policyId = policyId;
        this.organizationId = organizationId;
        this.name = name;
        this.description = description;
        this.version = version;
        this.status = status;
        this.priority = priority;
        this.latestVersion = latestVersion;
    }

    public void markHistorical() {
        this.latestVersion = false;
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
    public UUID getPolicyId() { return policyId; }
    public UUID getOrganizationId() { return organizationId; }
    public String getName() { return name; }
    public String getDescription() { return description; }
    public int getVersion() { return version; }
    public PolicyStatus getStatus() { return status; }
    public int getPriority() { return priority; }
    public boolean isLatestVersion() { return latestVersion; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
