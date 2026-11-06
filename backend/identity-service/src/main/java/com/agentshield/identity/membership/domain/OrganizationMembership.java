package com.agentshield.identity.membership.domain;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import com.agentshield.identity.organization.domain.Organization;
import com.agentshield.identity.user.domain.User;

@Entity
@Table(name = "organization_memberships",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_membership_user_organization",
                columnNames = {"user_id", "organization_id"}),
        indexes = @Index(name = "idx_membership_organization_id", columnList = "organization_id"))
public class OrganizationMembership {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_membership_user"))
    private User user;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "organization_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_membership_organization"))
    private Organization organization;

    @Enumerated(EnumType.STRING)
    @Column(name = "organization_role", nullable = false, length = 16)
    private OrganizationRole role;

    @Enumerated(EnumType.STRING)
    @Column(name = "membership_status", nullable = false, length = 16)
    private MembershipStatus status;

    @Column(name = "joined_at", nullable = false, updatable = false)
    private Instant joinedAt;

    protected OrganizationMembership() {
        // Required by JPA.
    }

    public OrganizationMembership(User user, Organization organization, OrganizationRole role) {
        this.user = user;
        this.organization = organization;
        this.role = role;
        this.status = MembershipStatus.ACTIVE;
    }

    @PrePersist
    void setMembershipDefaults() {
        if (status == null) {
            status = MembershipStatus.ACTIVE;
        }
        if (joinedAt == null) {
            joinedAt = Instant.now();
        }
    }

    public UUID getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public Organization getOrganization() {
        return organization;
    }

    public OrganizationRole getRole() {
        return role;
    }

    public MembershipStatus getStatus() {
        return status;
    }

    public Instant getJoinedAt() {
        return joinedAt;
    }
}
