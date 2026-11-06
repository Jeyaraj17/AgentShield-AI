package com.agentshield.agentmanagement.config;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import com.agentshield.agentmanagement.security.TenantJwtAuthenticationConverter;

@Configuration
public class SecurityConfiguration {

    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.cors.allowed-origins:}")
            String configuredOrigins,
            Environment environment) {
        String[] profiles = environment.getActiveProfiles();
        boolean development = profiles.length > 0
                && Arrays.stream(profiles).allMatch(profile -> profile.equals("local") || profile.equals("test"));
        List<String> origins = Arrays.stream(configuredOrigins.split(","))
                .map(String::trim).filter(value -> !value.isEmpty())
                .peek(value -> validateOrigin(value, development)).toList();
        if (!development && origins.isEmpty()) {
            throw new IllegalStateException("AGENT_CORS_ALLOWED_ORIGINS must be configured outside local/test");
        }
        if (origins.isEmpty()) {
            return request -> null;
        }
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOrigins(origins);
        cors.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        cors.setAllowedHeaders(List.of(HttpHeaders.AUTHORIZATION, HttpHeaders.CONTENT_TYPE, HttpHeaders.ACCEPT));
        cors.setAllowCredentials(false);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cors);
        return source;
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            TenantJwtAuthenticationConverter tenantJwtAuthenticationConverter) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/agents").hasAnyRole("OWNER","ADMIN","MEMBER")
                        .requestMatchers(HttpMethod.GET, "/api/v1/agents/*").hasAnyRole("OWNER","ADMIN","MEMBER")
                        .requestMatchers(HttpMethod.GET, "/internal/v1/agents/*").access(
                                org.springframework.security.authorization.AuthorizationManagers.allOf(
                                        org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole("RUNTIME_GATEWAY"),
                                        org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority("SCOPE_agents.read")))
                        .requestMatchers(HttpMethod.POST, "/api/v1/agents")
                                .hasAnyRole("OWNER", "ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/v1/agents/*")
                                .hasAnyRole("OWNER", "ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/api/v1/agents/*/status")
                                .hasAnyRole("OWNER", "ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/v1/agents/*")
                                .hasAnyRole("OWNER", "ADMIN")
                        .anyRequest().denyAll())
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(tenantJwtAuthenticationConverter)))
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
                .cors(Customizer.withDefaults());
        return http.build();
    }

    private static void validateOrigin(String value, boolean development) {
        if (value.contains("*") || value.contains(",")) {
            throw new IllegalStateException("CORS origins must be exact origins without wildcards");
        }
        URI uri = URI.create(value);
        boolean loopback = "localhost".equalsIgnoreCase(uri.getHost())
                || "127.0.0.1".equals(uri.getHost()) || "::1".equals(uri.getHost())
                || "[::1]".equals(uri.getHost());
        boolean allowedScheme = "https".equalsIgnoreCase(uri.getScheme())
                || development && loopback && "http".equalsIgnoreCase(uri.getScheme());
        if (!allowedScheme || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getPath() != null && !uri.getPath().isEmpty()
                || uri.getQuery() != null || uri.getFragment() != null) {
            throw new IllegalStateException("CORS origin must be an exact HTTPS origin");
        }
    }
}
