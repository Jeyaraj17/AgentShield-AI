package com.agentshield.policyengine.policy.domain;

import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@Entity
@Table(name = "policy_rules", indexes = {
        @Index(name = "idx_policy_rules_version", columnList = "policy_version_id"),
        @Index(name = "idx_policy_rules_target_agent", columnList = "target_agent_id")
})
public class PolicyRule {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(columnDefinition = "char(36)")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "policy_version_id", nullable = false)
    private SecurityPolicy policyVersion;

    @Column(name = "rule_name", nullable = false, length = 150)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "agent_scope", nullable = false, length = 20)
    private AgentScope agentScope;

    @JdbcTypeCode(SqlTypes.CHAR)
    @Column(name = "target_agent_id", columnDefinition = "char(36)")
    private UUID targetAgentId;

    @Column(name = "action_identifier", nullable = false, length = 150)
    private String action;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 8)
    private RuleEffect effect;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "json")
    private RuleConditions conditions;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected PolicyRule() {
        // Required by JPA.
    }

    public PolicyRule(SecurityPolicy policyVersion, String name, AgentScope agentScope, UUID targetAgentId,
            String action, RuleEffect effect, RuleConditions conditions) {
        this.policyVersion = policyVersion;
        this.name = name;
        this.agentScope = agentScope;
        this.targetAgentId = targetAgentId;
        this.action = action;
        this.effect = effect;
        this.conditions = conditions;
    }

    @PrePersist
    void setCreationTimestamp() {
        createdAt = Instant.now();
    }

    public UUID getId() { return id; }
    public SecurityPolicy getPolicyVersion() { return policyVersion; }
    public String getName() { return name; }
    public AgentScope getAgentScope() { return agentScope; }
    public UUID getTargetAgentId() { return targetAgentId; }
    public String getAction() { return action; }
    public RuleEffect getEffect() { return effect; }
    public RuleConditions getConditions() { return conditions; }
    public Instant getCreatedAt() { return createdAt; }
}
