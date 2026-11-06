package com.agentshield.policyengine.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import jakarta.servlet.DispatcherType;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfiguration {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, Converter<Jwt, ? extends AbstractAuthenticationToken> converter,
            @org.springframework.beans.factory.annotation.Qualifier("jwtDecoder") JwtDecoder jwtDecoder) throws Exception {
        return http.csrf(csrf -> csrf.disable()).cors(Customizer.withDefaults()).sessionManagement(s -> s.sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/policies/evaluate").access(
                                org.springframework.security.authorization.AuthorizationManagers.allOf(
                                        org.springframework.security.authorization.AuthorityAuthorizationManager.hasRole("RUNTIME_GATEWAY"),
                                        org.springframework.security.authorization.AuthorityAuthorizationManager.hasAuthority("SCOPE_policy.evaluate")))
                        .requestMatchers(HttpMethod.POST, "/api/v1/policies").hasAnyRole("OWNER", "ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/v1/policies/**").hasAnyRole("OWNER", "ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/api/v1/policies/**").hasAnyRole("OWNER", "ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/v1/policies/**").hasAnyRole("OWNER", "ADMIN", "MEMBER")
                        .anyRequest().denyAll())
                .httpBasic(basic -> basic.disable()).formLogin(form -> form.disable()).logout(logout -> logout.disable())
                .oauth2ResourceServer(o -> o.jwt(j -> j.decoder(jwtDecoder).jwtAuthenticationConverter(converter))).build();
    }
    @Bean
    Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter(@Value("${agentshield.security.runtime-gateway-client-id:}") String gatewayClient) {
        return jwt -> {
            String role = jwt.getClaimAsString("organization_role");
            var authorities = new java.util.ArrayList<SimpleGrantedAuthority>();
            if (role != null) authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            if (!gatewayClient.isBlank() && gatewayClient.equals(jwt.getClaimAsString("client_id"))
                    && jwt.getSubject()!=null && jwt.getSubject().equals(gatewayClient)
                    && "service".equals(jwt.getClaimAsString("identity_type"))
                    && "service".equals(jwt.getClaimAsString("token_type"))
                    && "RUNTIME_GATEWAY".equals(jwt.getClaimAsString("service_role"))) {
                authorities.add(new SimpleGrantedAuthority("ROLE_RUNTIME_GATEWAY"));
                Object scope = jwt.getClaims().get("scope");
                if (scope instanceof String value) {
                    Arrays.stream(value.split("\\s+")).filter(s -> !s.isBlank())
                            .map(s -> new SimpleGrantedAuthority("SCOPE_" + s)).forEach(authorities::add);
                } else if (scope instanceof java.util.Collection<?> values) {
                    values.stream().filter(String.class::isInstance).map(String.class::cast)
                            .map(s -> new SimpleGrantedAuthority("SCOPE_" + s)).forEach(authorities::add);
                }
            }
            return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
        };
    }
    @Bean
    CorsConfigurationSource corsConfigurationSource(@Value("${agentshield.security.cors.allowed-origins}") String origins, Environment environment) {
        String[] profiles=environment.getActiveProfiles();
        boolean local=profiles.length>0 && Arrays.stream(profiles).allMatch(p -> p.equals("local") || p.equals("test"));
        if (!local && origins.isBlank()) throw new IllegalStateException("POLICY_CORS_ALLOWED_ORIGINS must be configured outside local/test");
        var cors = new CorsConfiguration();
        var allowed = Arrays.stream(origins.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
        allowed.forEach(origin -> validateOrigin(origin,local));
        if (allowed.isEmpty()) return request -> null;
        cors.setAllowedOrigins(allowed); cors.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "PATCH", "OPTIONS"));
        cors.setAllowedHeaders(java.util.List.of("Authorization", "Content-Type")); cors.setAllowCredentials(false);
        var source = new UrlBasedCorsConfigurationSource(); source.registerCorsConfiguration("/api/**", cors); return source;
    }
    private static void validateOrigin(String value, boolean local) {
        if (value.contains("*")) throw new IllegalStateException("Wildcard CORS origins are forbidden");
        java.net.URI uri=java.net.URI.create(value);
        boolean loopback="localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "::1".equals(uri.getHost()) || "[::1]".equals(uri.getHost());
        boolean scheme="https".equalsIgnoreCase(uri.getScheme()) || local && loopback && "http".equalsIgnoreCase(uri.getScheme());
        if (!scheme || uri.getHost()==null || uri.getUserInfo()!=null || (uri.getPath()!=null && !uri.getPath().isEmpty()) || uri.getQuery()!=null || uri.getFragment()!=null)
            throw new IllegalStateException("CORS origin must be an exact HTTPS origin (HTTP loopback only in local/test)");
    }
}
