package com.agentshield.identity.membership.api;

import java.util.UUID;

import jakarta.validation.constraints.NotNull;
import com.agentshield.identity.membership.domain.OrganizationRole;

public record CreateOrganizationMembershipRequest(
        @NotNull(message = "User ID is required") UUID userId,
        @NotNull(message = "Organization role is required") OrganizationRole role) {
}
