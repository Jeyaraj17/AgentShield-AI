package com.agentshield.identity.membership.service;

import java.util.UUID;

public class DuplicateOrganizationMembershipException extends RuntimeException {

    public DuplicateOrganizationMembershipException(UUID userId, UUID organizationId) {
        super("User is already a member of organization");
    }
}
