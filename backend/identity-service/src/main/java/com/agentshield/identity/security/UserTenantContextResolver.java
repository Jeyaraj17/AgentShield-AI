package com.agentshield.identity.security;

import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public class UserTenantContextResolver {
    public UserTenantContext resolve(Jwt jwt) {
        try {
            if (jwt == null || !"user".equals(jwt.getClaimAsString("identity_type"))) {
                throw new IllegalArgumentException();
            }
            UUID userId = UUID.fromString(jwt.getClaimAsString("user_id"));
            UUID organizationId = UUID.fromString(jwt.getClaimAsString("organization_id"));
            String role = jwt.getClaimAsString("organization_role");
            if (!userId.toString().equals(jwt.getSubject()) || !List.of("OWNER", "ADMIN", "MEMBER").contains(role)) {
                throw new IllegalArgumentException();
            }
            return new UserTenantContext(userId, organizationId, role);
        } catch (RuntimeException exception) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "A valid organization user identity is required");
        }
    }
}
