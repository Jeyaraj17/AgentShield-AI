package com.agentshield.identity.membership.service;

import java.util.UUID;

public class OrganizationNotFoundException extends RuntimeException {

    public OrganizationNotFoundException(UUID organizationId) {
        super("Organization not found: " + organizationId);
    }
}
