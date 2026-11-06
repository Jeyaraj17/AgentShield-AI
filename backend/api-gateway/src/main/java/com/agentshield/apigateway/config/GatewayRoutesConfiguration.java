package com.agentshield.apigateway.config;

import java.net.URI;
import java.util.Arrays;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class GatewayRoutesConfiguration {
    @Bean
    RouteLocator gatewayRoutes(RouteLocatorBuilder builder,
            @Value("${agentshield.gateway.identity-service-url}") String identity,
            @Value("${agentshield.gateway.agent-management-service-url}") String agents,
            @Value("${agentshield.gateway.policy-engine-service-url}") String policies,
            @Value("${agentshield.gateway.runtime-security-gateway-service-url}") String runtime,
            @Value("${agentshield.gateway.ai-analysis-service-url}") String analysis,
            @Value("${agentshield.gateway.audit-service-url}") String audit,
            @Value("${agentshield.gateway.notification-service-url}") String notifications,
            @Value("${agentshield.gateway.public-url}") String publicGatewayUrl,
            Environment environment) {
        URI identityUri = URI.create(identity);
        String identityOriginPattern = "^" + Pattern.quote(identityUri.getScheme() + "://" + identityUri.getRawAuthority());
        String[] profiles = environment.getActiveProfiles();
        boolean localDevelopment = profiles.length > 0
                && Arrays.stream(profiles).allMatch(profile -> profile.equals("local") || profile.equals("test"));
        return builder.routes()
                .route("identity-auth", r -> r.path("/oauth2/**", "/.well-known/**", "/login")
                        .filters(f -> {
                            // Identity owns CORS for its OAuth endpoints and login form. Avoid
                            // adding a second CORS policy while proxying those same responses.
                            var filters = f.rewriteResponseHeader("Location", identityOriginPattern, publicGatewayUrl);
                            if (localDevelopment) {
                                filters.rewriteResponseHeader("Set-Cookie",
                                        "(?i)(JSESSIONID=[^;]+;\\s*[^;]+);\\s*Secure(?=;|$)", "$1");
                            }
                            return filters;
                        })
                        .uri(identity))
                .route("identity-current-organization", r -> r.path(
                        "/api/v1/organizations/current", "/api/v1/organizations/current/members").uri(identity))
                .route("identity-current-user", r -> r.path(
                        "/api/v1/users/me", "/api/v1/users/me/membership").uri(identity))
                .route("identity-organizations", r -> r.path("/api/v1/organizations/**").uri(identity))
                .route("identity-onboarding", r -> r.path("/api/v1/onboarding/organizations")
                        .metadata("response-timeout", 30000)
                        .uri(identity))
                .route("identity-users", r -> r.path("/api/v1/users/**").uri(identity))
                .route("audit-service", r -> r.path("/api/v1/audit/**").uri(audit))
                .route("notification-service", r -> r.path("/api/v1/notifications/**").uri(notifications))
                .route("runtime-security-gateway", r -> r.path("/api/v1/runtime/**").uri(runtime))
                .route("ai-analysis-dashboard", r -> r.path("/api/v1/analysis/**",
                        "/api/v1/agents/*/trust-score", "/api/v1/agents/*/risk-history", "/api/v1/agents/*/drift-history").uri(analysis))
                .route("agent-management", r -> r.path("/api/v1/agents/**").uri(agents))
                .route("policy-engine", r -> r.path("/api/v1/policies/**").uri(policies))
                .build();
    }
}
