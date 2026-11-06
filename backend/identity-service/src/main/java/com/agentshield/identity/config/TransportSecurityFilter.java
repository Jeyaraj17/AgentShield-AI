package com.agentshield.identity.config;

import java.io.IOException;
import java.util.Arrays;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.web.filter.OncePerRequestFilter;

public final class TransportSecurityFilter extends OncePerRequestFilter {

    private final boolean developmentProfile;

    public TransportSecurityFilter(Environment environment) {
        String[] profiles = environment.getActiveProfiles();
        this.developmentProfile = profiles.length > 0
                && Arrays.stream(profiles).allMatch(profile -> profile.equals("local") || profile.equals("test"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.isSecure()) {
            chain.doFilter(request, response);
            return;
        }
        String host = request.getServerName();
        boolean loopbackHost = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)
                || "::1".equals(host) || "[::1]".equals(host);
        if (developmentProfile && loopbackHost) {
            chain.doFilter(request, response);
            return;
        }
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "HTTPS is required");
    }
}
