package com.agentshield.identity.auth;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class TenantSelectionValidationFilter extends OncePerRequestFilter {

    private final TenantAuthorizationService tenantAuthorizationService;

    public TenantSelectionValidationFilter(TenantAuthorizationService tenantAuthorizationService) {
        this.tenantAuthorizationService = tenantAuthorizationService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"/oauth2/authorize".equals(request.getServletPath());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            try {
                tenantAuthorizationService.verify(authentication.getName(), request.getParameter("organization_id"));
            } catch (InvalidTenantAuthorizationException exception) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Organization access is not available");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
