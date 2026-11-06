package com.agentshield.identity.config;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.ForwardedHeaderFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/** Applies forwarded headers only when the immediate peer is a configured proxy address. */
public final class TrustedForwardedHeadersFilter extends OncePerRequestFilter {

    private final Set<String> trustedProxyAddresses;
    private final ForwardedHeaderFilter forwardedHeaderFilter = new ForwardedHeaderFilter();

    public TrustedForwardedHeadersFilter(String configuredAddresses) {
        this.trustedProxyAddresses = Arrays.stream(configuredAddresses.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (trustedProxyAddresses.contains(request.getRemoteAddr())) {
            forwardedHeaderFilter.doFilter(request, response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }
}
