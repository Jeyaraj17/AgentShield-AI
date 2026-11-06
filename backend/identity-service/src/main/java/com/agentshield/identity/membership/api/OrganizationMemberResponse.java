package com.agentshield.identity.membership.api;

import java.time.Instant;
import java.util.UUID;
import com.agentshield.identity.membership.domain.MembershipStatus;
import com.agentshield.identity.membership.domain.OrganizationMembership;
import com.agentshield.identity.membership.domain.OrganizationRole;
import com.agentshield.identity.user.domain.UserStatus;

public record OrganizationMemberResponse(UUID userId, String email, String firstName, String lastName,
        UserStatus accountStatus, OrganizationRole role, MembershipStatus membershipStatus, Instant joinedAt) {
    public static OrganizationMemberResponse from(OrganizationMembership membership) {
        var user = membership.getUser();
        return new OrganizationMemberResponse(user.getId(), user.getEmailNormalized(), user.getFirstName(),
                user.getLastName(), user.getStatus(), membership.getRole(), membership.getStatus(),
                membership.getJoinedAt());
    }
}
