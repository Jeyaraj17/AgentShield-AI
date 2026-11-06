package com.agentshield.audit.security;

import java.util.List;
import java.util.UUID;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

public record AuditPrincipal(UUID userId,UUID organizationId,String role) {
    @Component
    public static class Resolver {
        public AuditPrincipal from(Jwt jwt) {
            try {
                if (!"user".equals(jwt.getClaimAsString("identity_type"))) throw new IllegalArgumentException();
                UUID user=UUID.fromString(jwt.getClaimAsString("user_id"));
                UUID org=UUID.fromString(jwt.getClaimAsString("organization_id"));
                String role=jwt.getClaimAsString("organization_role");
                if (!user.toString().equals(jwt.getSubject()) || !List.of("OWNER","ADMIN","MEMBER").contains(role)) throw new IllegalArgumentException();
                return new AuditPrincipal(user,org,role);
            } catch (RuntimeException ex) { throw new ResponseStatusException(HttpStatus.FORBIDDEN,"A valid organization user identity is required"); }
        }
    }
}
