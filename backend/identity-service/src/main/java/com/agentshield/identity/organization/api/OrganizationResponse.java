package com.agentshield.identity.organization.api;

import java.time.Instant;
import java.util.UUID;

import com.agentshield.identity.organization.domain.Organization;
import com.agentshield.identity.organization.domain.OrganizationStatus;

public record OrganizationResponse(
        UUID id,
        String name,
        String organizationCode,
        String description,
        OrganizationStatus status,
        Instant createdAt,
        Instant updatedAt) {

    public static OrganizationResponse from(Organization organization) {
        return new OrganizationResponse(
                organization.getId(),
                organization.getName(),
                organization.getOrganizationCode(),
                organization.getDescription(),
                organization.getStatus(),
                organization.getCreatedAt(),
                organization.getUpdatedAt());
    }
}
