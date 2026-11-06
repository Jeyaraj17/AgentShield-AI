package com.agentshield.identity.auth;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

/** Forces a fresh Identity Service login for SPA authorization requests. */
public final class SpaReauthenticationFilter extends OncePerRequestFilter {

    private static final String PENDING_STATE_ATTRIBUTE = SpaReauthenticationFilter.class.getName() + ".pendingState";

    private final String spaClientId;
    private final SecurityContextRepository securityContextRepository;

    public SpaReauthenticationFilter(String spaClientId, SecurityContextRepository securityContextRepository) {
        this.spaClientId = spaClientId;
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"/oauth2/authorize".equals(request.getServletPath())
                || !spaClientId.equals(request.getParameter("client_id"))
                || !"true".equals(request.getParameter("reauthenticate"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String state = request.getParameter("state");
        if (state == null || state.isBlank()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "A state value is required for reauthentication");
            return;
        }

        HttpSession session = request.getSession(true);
        String pendingState = (String) session.getAttribute(PENDING_STATE_ATTRIBUTE);
        if (state.equals(pendingState)) {
            // This is the saved authorization request resumed after the user signed in.
            session.removeAttribute(PENDING_STATE_ATTRIBUTE);
            chain.doFilter(request, response);
            return;
        }

        session.setAttribute(PENDING_STATE_ATTRIBUTE, state);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken)) {
            SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();
            SecurityContextHolder.clearContext();
            securityContextRepository.saveContext(emptyContext, request, response);
        }
        chain.doFilter(request, response);
    }
}
