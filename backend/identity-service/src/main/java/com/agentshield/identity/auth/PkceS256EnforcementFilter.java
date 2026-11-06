package com.agentshield.identity.auth;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

public final class PkceS256EnforcementFilter extends OncePerRequestFilter {

    private final String spaClientId;

    public PkceS256EnforcementFilter(String spaClientId) {
        this.spaClientId = spaClientId;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"/oauth2/authorize".equals(request.getServletPath())
                || !spaClientId.equals(request.getParameter("client_id"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String challenge = request.getParameter("code_challenge");
        String method = request.getParameter("code_challenge_method");
        if (!"S256".equals(method) || challenge == null || !challenge.matches("[A-Za-z0-9_-]{43}")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "A valid S256 PKCE challenge is required");
            return;
        }
        chain.doFilter(request, response);
    }
}
