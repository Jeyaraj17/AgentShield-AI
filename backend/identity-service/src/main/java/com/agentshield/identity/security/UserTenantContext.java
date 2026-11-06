package com.agentshield.identity.security;

import java.util.UUID;

public record UserTenantContext(UUID userId, UUID organizationId, String role) { }
