package com.agentshield.identity.auth;

import java.io.IOException;
import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

public final class AuthenticationRateLimitFilter extends OncePerRequestFilter {

    private final int maxRequests;
    private final long windowMillis;
    private final int onboardingMaxRequests;
    private final long onboardingWindowMillis;
    private final Clock clock;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public AuthenticationRateLimitFilter(int maxRequests, long windowSeconds) {
        this(maxRequests, windowSeconds, maxRequests, windowSeconds, Clock.systemUTC());
    }

    public AuthenticationRateLimitFilter(int maxRequests, long windowSeconds, int onboardingMaxRequests,
            long onboardingWindowSeconds) {
        this(maxRequests, windowSeconds, onboardingMaxRequests, onboardingWindowSeconds, Clock.systemUTC());
    }

    AuthenticationRateLimitFilter(int maxRequests, long windowSeconds, int onboardingMaxRequests,
            long onboardingWindowSeconds, Clock clock) {
        if (maxRequests < 1 || windowSeconds < 1 || onboardingMaxRequests < 1 || onboardingWindowSeconds < 1) {
            throw new IllegalArgumentException("Authentication rate limit settings must be positive");
        }
        this.maxRequests = maxRequests;
        this.windowMillis = Math.multiplyExact(windowSeconds, 1000L);
        this.onboardingMaxRequests = onboardingMaxRequests;
        this.onboardingWindowMillis = Math.multiplyExact(onboardingWindowSeconds, 1000L);
        this.clock = clock;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return !("/login".equals(path) && "POST".equals(request.getMethod())
                || "/oauth2/authorize".equals(path) && "GET".equals(request.getMethod())
                || "/oauth2/token".equals(path) && "POST".equals(request.getMethod())
                || "/api/v1/onboarding/organizations".equals(path) && "POST".equals(request.getMethod()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long now = clock.millis();
        boolean onboarding = "/api/v1/onboarding/organizations".equals(request.getServletPath());
        int requestLimit = onboarding ? onboardingMaxRequests : maxRequests;
        long requestWindow = onboarding ? onboardingWindowMillis : windowMillis;
        String key = (onboarding ? "onboarding:" : "authentication:") + request.getRemoteAddr();
        Bucket bucket;
        synchronized (buckets) {
            if (!buckets.containsKey(key) && buckets.size() >= 10_000) {
                buckets.entrySet().removeIf(entry -> now - entry.getValue().startedAt >= entry.getValue().windowMillis);
                if (buckets.size() >= 10_000) {
                    response.sendError(429, "Authentication rate limiter is at capacity");
                    return;
                }
            }
            bucket = buckets.compute(key, (ignored, current) -> current == null
                    || now - current.startedAt >= requestWindow
                            ? new Bucket(now, new AtomicInteger(), requestWindow) : current);
            if (bucket.count.incrementAndGet() > requestLimit) {
                long seconds = Math.max(1, (bucket.startedAt + requestWindow - now + 999) / 1000);
                response.setHeader("Retry-After", Long.toString(seconds));
                response.sendError(429, "Too many authentication requests");
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private record Bucket(long startedAt, AtomicInteger count, long windowMillis) { }
}
