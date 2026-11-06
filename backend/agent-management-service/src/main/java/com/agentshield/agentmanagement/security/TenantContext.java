package com.agentshield.agentmanagement.security;

import java.util.UUID;

import org.springframework.security.oauth2.jwt.Jwt;

public record TenantContext(UUID userId, UUID organizationId, OrganizationRole role) {

    public static TenantContext from(Jwt jwt) {
        UUID userId = UUID.fromString(jwt.getClaimAsString("user_id"));
        UUID organizationId = UUID.fromString(jwt.getClaimAsString("organization_id"));
        OrganizationRole role = OrganizationRole.valueOf(jwt.getClaimAsString("organization_role"));
        if (!userId.toString().equals(jwt.getSubject())) {
            throw new IllegalArgumentException("The token subject does not match its user identifier");
        }
        return new TenantContext(userId, organizationId, role);
    }
}
