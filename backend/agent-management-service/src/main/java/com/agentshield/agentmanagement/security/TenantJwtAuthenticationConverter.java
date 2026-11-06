package com.agentshield.agentmanagement.security;

import java.util.List;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class TenantJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        try {
            if ("service".equals(jwt.getClaimAsString("identity_type"))
                    && "service".equals(jwt.getClaimAsString("token_type"))
                    && "RUNTIME_GATEWAY".equals(jwt.getClaimAsString("service_role"))) {
                return new JwtAuthenticationToken(jwt,
                        List.of(new SimpleGrantedAuthority("ROLE_RUNTIME_GATEWAY"),
                                new SimpleGrantedAuthority("SCOPE_agents.read")), jwt.getSubject());
            }
            TenantContext context = TenantContext.from(jwt);
            return new JwtAuthenticationToken(jwt,
                    List.of(new SimpleGrantedAuthority("ROLE_" + context.role().name())),
                    context.userId().toString());
        } catch (RuntimeException exception) {
            throw new BadCredentialsException("Access token is missing valid tenant identity claims", exception);
        }
    }

}
