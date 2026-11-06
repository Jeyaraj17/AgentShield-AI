package com.agentshield.identity.organization.api;

import java.util.UUID;
import com.agentshield.identity.organization.domain.Organization;
import com.agentshield.identity.organization.domain.OrganizationStatus;

public record CurrentOrganizationResponse(UUID id, String name, String organizationCode, OrganizationStatus status) {
    public static CurrentOrganizationResponse from(Organization organization) {
        return new CurrentOrganizationResponse(organization.getId(), organization.getName(),
                organization.getOrganizationCode(), organization.getStatus());
    }
}
