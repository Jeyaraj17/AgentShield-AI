package com.agentshield.apigateway.config;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

@Configuration
public class GatewaySecurityConfiguration {
    @Bean
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
            @Value("${agentshield.security.organization-onboarding.enabled:false}") boolean onboardingEnabled,
            Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtConverter) {
        return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .authorizeExchange(authorize -> authorize
                        .pathMatchers(HttpMethod.OPTIONS,"/**").permitAll()
                        .pathMatchers("/actuator/health").permitAll()
                        .pathMatchers("/oauth2/authorize", "/oauth2/token", "/oauth2/jwks", "/.well-known/**", "/login").permitAll()
                        .pathMatchers(HttpMethod.POST, "/api/v1/onboarding/organizations").access((authentication, context) ->
                                Mono.just(new AuthorizationDecision(onboardingEnabled)))
                        .pathMatchers(HttpMethod.POST,"/api/v1/policies/evaluate").denyAll()
                        .pathMatchers(HttpMethod.POST,"/api/v1/analysis/**").denyAll()
                        .pathMatchers(HttpMethod.POST,"/api/v1/runtime/execute").access(agentAccess())
                        .pathMatchers(HttpMethod.GET,"/api/v1/runtime/executions/**").access(agentAccess())
                        .pathMatchers(HttpMethod.GET,"/api/v1/runtime/history", "/api/v1/runtime/history/**",
                                "/api/v1/analysis/**", "/api/v1/agents/*/trust-score", "/api/v1/agents/*/risk-history", "/api/v1/agents/*/drift-history").access(userRoleAccess("OWNER","ADMIN"))
                        .pathMatchers(HttpMethod.GET,"/api/v1/audit/events", "/api/v1/audit/events/*", "/api/v1/audit/summary").access(userRoleAccess("OWNER","ADMIN","MEMBER"))
                        .pathMatchers(HttpMethod.GET,"/api/v1/notifications", "/api/v1/notifications/*").access(userRoleAccess("OWNER","ADMIN"))
                        .pathMatchers(HttpMethod.PATCH,"/api/v1/notifications/read-all", "/api/v1/notifications/*/read").access(userRoleAccess("OWNER","ADMIN"))
                        .pathMatchers(HttpMethod.GET, "/api/v1/organizations/current/members").access(userRoleAccess("OWNER", "ADMIN"))
                        .pathMatchers(HttpMethod.GET, "/api/v1/organizations/current").access(userRoleAccess("OWNER", "ADMIN", "MEMBER"))
                        .pathMatchers(HttpMethod.GET, "/api/v1/users/me", "/api/v1/users/me/membership").access(selfAccess())
                        .pathMatchers(HttpMethod.GET,"/api/v1/users/{userId}").access(userReadAccess())
                        .pathMatchers(HttpMethod.POST,"/api/v1/organizations/**", "/api/v1/users/**",
                                "/api/v1/agents/**", "/api/v1/policies").hasAnyRole("OWNER","ADMIN")
                        .pathMatchers(HttpMethod.PUT,"/api/v1/agents/**", "/api/v1/policies/**").hasAnyRole("OWNER","ADMIN")
                        .pathMatchers(HttpMethod.PATCH,"/api/v1/agents/**", "/api/v1/policies/**").hasAnyRole("OWNER","ADMIN")
                        .pathMatchers(HttpMethod.DELETE,"/api/v1/agents/**", "/api/v1/policies/**",
                                "/api/v1/organizations/*/agents/*/credentials/*").hasAnyRole("OWNER","ADMIN")
                        .pathMatchers(HttpMethod.GET,"/api/v1/organizations/**", "/api/v1/agents/**", "/api/v1/policies/**").hasAnyRole("OWNER","ADMIN","MEMBER")
                        .anyExchange().denyAll())
                .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter)))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((exchange, exception) -> SafeGatewayResponses.write(exchange,401,"Authentication required"))
                        .accessDeniedHandler((exchange, exception) -> SafeGatewayResponses.write(exchange,403,"Access denied")))
                .build();
    }

    @Bean
    Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        return jwt -> {
            String authority="agent".equals(jwt.getClaimAsString("identity_type"))
                    ? "ROLE_AGENT" : "ROLE_"+jwt.getClaimAsString("organization_role");
            List<SimpleGrantedAuthority> authorities=List.of(new SimpleGrantedAuthority(authority));
            return Mono.just(new JwtAuthenticationToken(jwt,authorities,jwt.getSubject()));
        };
    }

    @Bean
    CorsWebFilter corsWebFilter(@Value("${agentshield.security.cors.allowed-origins}") String configuredOrigins, Environment environment) {
        String[] profiles=environment.getActiveProfiles();
        boolean local=profiles.length>0 && Arrays.stream(profiles).allMatch(p -> p.equals("local") || p.equals("test"));
        if (!local && configuredOrigins.isBlank()) throw new IllegalStateException("GATEWAY_CORS_ALLOWED_ORIGINS is required outside local/test");
        List<String> origins=Arrays.stream(configuredOrigins.split(",")).map(String::trim).filter(s -> !s.isEmpty()).peek(o -> validateOrigin(o,local)).toList();
        CorsConfiguration cors=new CorsConfiguration();
        cors.setAllowedOrigins(origins);
        cors.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
        cors.setAllowedHeaders(List.of(HttpHeaders.AUTHORIZATION,HttpHeaders.CONTENT_TYPE,HttpHeaders.ACCEPT,"X-Correlation-ID"));
        cors.setExposedHeaders(List.of("X-Correlation-ID"));
        cors.setAllowCredentials(false);
        UrlBasedCorsConfigurationSource source=new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",cors);
        CorsConfiguration opaqueOriginLogin = new CorsConfiguration();
        opaqueOriginLogin.setAllowedOrigins(List.of("null"));
        opaqueOriginLogin.setAllowedMethods(List.of("POST"));
        opaqueOriginLogin.setAllowedHeaders(List.of(HttpHeaders.CONTENT_TYPE));
        opaqueOriginLogin.setAllowCredentials(false);
        return new CorsWebFilter(exchange -> isSameOriginLoginNavigation(exchange)
                ? opaqueOriginLogin
                : source.getCorsConfiguration(exchange));
    }

    private static boolean isSameOriginLoginNavigation(org.springframework.web.server.ServerWebExchange exchange) {
        var request=exchange.getRequest();
        return HttpMethod.POST.equals(request.getMethod())
                && "/login".equals(request.getPath().value())
                && "null".equals(request.getHeaders().getOrigin())
                && "same-origin".equals(request.getHeaders().getFirst("Sec-Fetch-Site"))
                && "navigate".equals(request.getHeaders().getFirst("Sec-Fetch-Mode"))
                && "document".equals(request.getHeaders().getFirst("Sec-Fetch-Dest"))
                && "?1".equals(request.getHeaders().getFirst("Sec-Fetch-User"));
    }

    private static ReactiveAuthorizationManager<AuthorizationContext> userReadAccess() {
        return (authentication, context) -> authentication.map(auth -> {
            if (!(auth instanceof JwtAuthenticationToken jwtAuth) || !auth.isAuthenticated()) return new AuthorizationDecision(false);
            String pathUser=String.valueOf(context.getVariables().get("userId"));
            boolean manager=auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_OWNER") || a.getAuthority().equals("ROLE_ADMIN"));
            return new AuthorizationDecision(manager || jwtAuth.getToken().getSubject().equals(pathUser));
        }).map(decision -> (AuthorizationResult) decision).defaultIfEmpty(new AuthorizationDecision(false));
    }
    private static ReactiveAuthorizationManager<AuthorizationContext> selfAccess() {
        return (authentication, context) -> authentication.map(auth -> {
            if (!(auth instanceof JwtAuthenticationToken jwtAuth) || !auth.isAuthenticated()) return new AuthorizationDecision(false);
            Jwt jwt=jwtAuth.getToken();
            String userId=jwt.getClaimAsString("user_id");
            return new AuthorizationDecision("user".equals(jwt.getClaimAsString("identity_type"))
                    && userId!=null && userId.equals(jwt.getSubject()));
        }).map(decision -> (AuthorizationResult) decision).defaultIfEmpty(new AuthorizationDecision(false));
    }

    private static ReactiveAuthorizationManager<AuthorizationContext> agentAccess() {
        return (authentication, context) -> authentication.map(auth -> {
            if (!(auth instanceof JwtAuthenticationToken jwtAuth) || !auth.isAuthenticated()) {
                return new AuthorizationDecision(false);
            }
            Jwt jwt=jwtAuth.getToken();
            try {
                String agentId=jwt.getClaimAsString("agent_id");
                java.util.UUID.fromString(agentId);
                java.util.UUID.fromString(jwt.getClaimAsString("organization_id"));
                return new AuthorizationDecision("agent".equals(jwt.getClaimAsString("identity_type"))
                        && "agent".equals(jwt.getClaimAsString("token_type"))
                        && "AGENT".equals(jwt.getClaimAsString("agent_role"))
                        && agentId.equals(jwt.getSubject())
                        && auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_AGENT")));
            } catch (RuntimeException exception) {
                return new AuthorizationDecision(false);
            }
        }).map(decision -> (AuthorizationResult) decision).defaultIfEmpty(new AuthorizationDecision(false));
    }
    private static ReactiveAuthorizationManager<AuthorizationContext> userRoleAccess(String... roles) {
        List<String> allowed=List.of(roles);
        return (authentication, context) -> authentication.map(auth -> {
            if (!(auth instanceof JwtAuthenticationToken jwtAuth) || !auth.isAuthenticated()) return new AuthorizationDecision(false);
            Jwt jwt=jwtAuth.getToken();
            String role=jwt.getClaimAsString("organization_role");
            String userId=jwt.getClaimAsString("user_id");
            return new AuthorizationDecision("user".equals(jwt.getClaimAsString("identity_type"))
                    && userId!=null && userId.equals(jwt.getSubject()) && allowed.contains(role));
        }).map(decision -> (AuthorizationResult) decision).defaultIfEmpty(new AuthorizationDecision(false));
    }
    private static void validateOrigin(String value,boolean local) {
        if (value.contains("*") || value.contains(",")) throw new IllegalStateException("CORS origins must be exact and cannot contain wildcards");
        URI uri=URI.create(value);
        boolean loopback="localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "::1".equals(uri.getHost()) || "[::1]".equals(uri.getHost());
        boolean scheme="https".equalsIgnoreCase(uri.getScheme()) || local && loopback && "http".equalsIgnoreCase(uri.getScheme());
        if (!scheme || uri.getHost()==null || uri.getUserInfo()!=null || uri.getPath()!=null && !uri.getPath().isEmpty() || uri.getQuery()!=null || uri.getFragment()!=null)
            throw new IllegalStateException("CORS origin must be an exact HTTPS origin");
    }
}
