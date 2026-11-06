package com.agentshield.identity.membership.api;

import java.time.Instant;
import java.util.UUID;

import com.agentshield.identity.membership.domain.MembershipStatus;
import com.agentshield.identity.membership.domain.OrganizationMembership;
import com.agentshield.identity.membership.domain.OrganizationRole;

public record OrganizationMembershipResponse(
        UUID id,
        UUID userId,
        UUID organizationId,
        OrganizationRole role,
        MembershipStatus status,
        Instant joinedAt) {

    public static OrganizationMembershipResponse from(OrganizationMembership membership) {
        return new OrganizationMembershipResponse(
                membership.getId(),
                membership.getUser().getId(),
                membership.getOrganization().getId(),
                membership.getRole(),
                membership.getStatus(),
                membership.getJoinedAt());
    }
}
