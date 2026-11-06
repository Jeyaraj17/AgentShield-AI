package com.agentshield.notification.security;

import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

public record NotificationPrincipal(UUID userId,UUID organizationId,String role) {
    @Component public static class Resolver {
        public NotificationPrincipal from(Jwt jwt) {
            try {
                UUID user=UUID.fromString(jwt.getClaimAsString("user_id"));
                UUID organization=UUID.fromString(jwt.getClaimAsString("organization_id"));
                String role=jwt.getClaimAsString("organization_role");
                if(!"user".equals(jwt.getClaimAsString("identity_type"))||!"user".equals(jwt.getClaimAsString("token_type"))
                        ||!user.toString().equals(jwt.getSubject())||!List.of("OWNER","ADMIN").contains(role)) throw new IllegalArgumentException();
                return new NotificationPrincipal(user,organization,role);
            } catch(RuntimeException ex) { throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Organization owner or administrator identity required"); }
        }
    }
}
