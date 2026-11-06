package com.agentshield.identity.config;

import java.util.Arrays;
import java.net.URI;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.annotation.Order;

import com.agentshield.identity.auth.TenantSelectionValidationFilter;
import com.agentshield.identity.auth.PkceS256EnforcementFilter;
import com.agentshield.identity.auth.AuthenticationRateLimitFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED;

@Configuration
public class SecurityConfiguration {

    @Bean
    DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    AuthenticationManager authenticationManager(DaoAuthenticationProvider provider, JwtAuthenticationProvider jwtProvider) {
        return new ProviderManager(List.of(provider,jwtProvider));
    }

    @Bean
    JwtAuthenticationProvider jwtAuthenticationProvider(JwtDecoder jwtDecoder) {
        JwtAuthenticationProvider provider=new JwtAuthenticationProvider(jwtDecoder);
        provider.setJwtAuthenticationConverter(jwtAuthenticationConverter());
        return provider;
    }

    @Bean
    SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    CsrfTokenRepository csrfTokenRepository(Environment environment) {
        String[] profiles = environment.getActiveProfiles();
        boolean development = profiles.length > 0
                && Arrays.stream(profiles).allMatch(profile -> profile.equals("local") || profile.equals("test"));
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repository.setCookiePath("/");
        repository.setCookieCustomizer(cookie -> cookie
                .path("/")
                .secure(!development)
                .sameSite("Lax"));
        return repository;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.cors.allowed-origins:}")
            String configuredOrigins,
            Environment environment) {
        String[] profiles = environment.getActiveProfiles();
        boolean development = profiles.length > 0
                && Arrays.stream(profiles).allMatch(profile -> profile.equals("local") || profile.equals("test"));
        List<String> origins = Arrays.stream(configuredOrigins.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .peek(origin -> validateOrigin(origin, development))
                .toList();
        if (!development && origins.isEmpty()) {
            throw new IllegalStateException("AUTH_CORS_ALLOWED_ORIGINS must be configured outside local/test");
        }
        if (origins.isEmpty()) {
            return request -> null;
        }
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOrigins(origins);
        cors.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        cors.setAllowedHeaders(List.of(HttpHeaders.AUTHORIZATION, HttpHeaders.CONTENT_TYPE, HttpHeaders.ACCEPT));
        cors.setAllowCredentials(false);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cors);
        CorsConfiguration opaqueOriginLogin = new CorsConfiguration();
        opaqueOriginLogin.setAllowedOrigins(List.of("null"));
        opaqueOriginLogin.setAllowedMethods(List.of("POST"));
        opaqueOriginLogin.setAllowedHeaders(List.of(HttpHeaders.CONTENT_TYPE));
        opaqueOriginLogin.setAllowCredentials(false);
        return request -> isSameOriginLoginNavigation(request)
                ? opaqueOriginLogin
                : source.getCorsConfiguration(request);
    }

    private static boolean isSameOriginLoginNavigation(jakarta.servlet.http.HttpServletRequest request) {
        return HttpMethod.POST.matches(request.getMethod())
                && "/login".equals(request.getServletPath())
                && "null".equals(request.getHeader(HttpHeaders.ORIGIN))
                && "same-origin".equals(request.getHeader("Sec-Fetch-Site"))
                && "navigate".equals(request.getHeader("Sec-Fetch-Mode"))
                && "document".equals(request.getHeader("Sec-Fetch-Dest"))
                && "?1".equals(request.getHeader("Sec-Fetch-User"));
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings(
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.issuer}") String issuer,
            Environment environment) {
        requireConfigured("AUTH_ISSUER", issuer);
        validateHttpsUrl(issuer, environment, "AUTH_ISSUER");
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService authorizationService(
            org.springframework.jdbc.core.JdbcTemplate jdbcTemplate,
            org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository clients) {
        return new org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService(
                jdbcTemplate, clients);
    }

    @Bean
    org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService authorizationConsentService(
            org.springframework.jdbc.core.JdbcTemplate jdbcTemplate,
            org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository clients) {
        return new org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService(
                jdbcTemplate, clients);
    }

    @Bean
    org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository registeredClientRepository(
            org.springframework.jdbc.core.JdbcTemplate jdbcTemplate) {
        return new org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository(
                jdbcTemplate);
    }

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurity(
            HttpSecurity http,
            TenantSelectionValidationFilter tenantSelectionValidationFilter,
            PkceS256EnforcementFilter pkceS256EnforcementFilter,
            com.agentshield.identity.auth.SpaReauthenticationFilter spaReauthenticationFilter,
            SecurityContextRepository securityContextRepository,
            CsrfTokenRepository csrfTokenRepository) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();
        http.securityMatcher(authorizationServer.getEndpointsMatcher())
                .with(authorizationServer, Customizer.withDefaults())
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository)
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .securityContext(context -> context
                        .securityContextRepository(securityContextRepository)
                        .requireExplicitSave(false))
                .sessionManagement(session -> session.sessionCreationPolicy(IF_REQUIRED))
                .addFilterBefore(tenantSelectionValidationFilter, LogoutFilter.class)
                .addFilterBefore(pkceS256EnforcementFilter, LogoutFilter.class)
                .addFilterAfter(spaReauthenticationFilter, PkceS256EnforcementFilter.class);
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain applicationSecurity(
            HttpSecurity http,
            Environment environment,
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.organization-onboarding.enabled:false}") boolean onboardingEnabled,
            AuthenticationManager authenticationManager,
            SecurityContextRepository securityContextRepository,
            CsrfTokenRepository csrfTokenRepository) throws Exception {
        String[] activeProfiles = environment.getActiveProfiles();
        boolean developmentAccessEnabled = activeProfiles.length > 0
                && Arrays.stream(activeProfiles)
                        .allMatch(profile -> profile.equals("local") || profile.equals("test"));

        http.authorizeHttpRequests(authorize -> {
                    authorize.requestMatchers("/actuator/health", "/login", "/error").permitAll();
                    if (onboardingEnabled) {
                        authorize.requestMatchers(HttpMethod.POST, "/api/v1/onboarding/organizations").permitAll();
                    }
                    authorize.requestMatchers(HttpMethod.GET, "/api/v1/organizations/current/members")
                            .hasAnyRole("OWNER", "ADMIN");
                    authorize.requestMatchers(HttpMethod.GET, "/api/v1/organizations/current",
                            "/api/v1/users/me", "/api/v1/users/me/membership")
                            .hasAnyRole("OWNER", "ADMIN", "MEMBER");
                    authorize.requestMatchers(HttpMethod.POST,"/api/v1/organizations/*/agents/*/credentials")
                            .hasAnyRole("OWNER","ADMIN");
                    authorize.requestMatchers(HttpMethod.DELETE,"/api/v1/organizations/*/agents/*/credentials/*")
                            .hasAnyRole("OWNER","ADMIN");
                    if (developmentAccessEnabled) {
                        authorize.requestMatchers(HttpMethod.POST, "/api/v1/organizations").permitAll();
                        authorize.requestMatchers(HttpMethod.POST, "/api/v1/users").permitAll();
                        authorize.requestMatchers(HttpMethod.GET, "/api/v1/users/*").permitAll();
                        authorize.requestMatchers(HttpMethod.POST, "/api/v1/organizations/*/memberships").permitAll();
                        authorize.requestMatchers(HttpMethod.GET, "/api/v1/users/*/memberships").permitAll();
                    }
                    authorize.anyRequest().denyAll();
                })
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository)
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .ignoringRequestMatchers(request -> {
                    String path=request.getServletPath(),method=request.getMethod();
                    boolean existingLocalPost=HttpMethod.POST.matches(method)&&("/api/v1/organizations".equals(path)
                            || "/api/v1/users".equals(path)||path.matches("^/api/v1/organizations/[^/]+/memberships$"));
                    boolean onboardingPost=onboardingEnabled&&HttpMethod.POST.matches(method)
                            && "/api/v1/onboarding/organizations".equals(path);
                    boolean credentialBearerRequest=(HttpMethod.POST.matches(method)||HttpMethod.DELETE.matches(method))
                            &&path.matches("^/api/v1/organizations/[^/]+/agents/[^/]+/credentials(?:/[^/]+)?$");
                    return existingLocalPost||onboardingPost||credentialBearerRequest;
                }))
                .authenticationManager(authenticationManager)
                .oauth2ResourceServer(resource->resource.jwt(jwt->jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
                .securityContext(context -> context
                        .securityContextRepository(securityContextRepository)
                        .requireExplicitSave(false))
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new Http403ForbiddenEntryPoint()))
                .formLogin(form -> form.successHandler((request, response, authentication) -> {
                    org.springframework.security.core.context.SecurityContext securityContext =
                            org.springframework.security.core.context.SecurityContextHolder.createEmptyContext();
                    securityContext.setAuthentication(authentication);
                    org.springframework.security.core.context.SecurityContextHolder.setContext(securityContext);
                    securityContextRepository.saveContext(securityContext, request, response);
                    new SavedRequestAwareAuthenticationSuccessHandler()
                            .onAuthenticationSuccess(request, response, authentication);
                }));
        return http.build();
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        var converter=new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            String role=jwt.getClaimAsString("organization_role");
            return role==null?java.util.List.of():java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_"+role));
        });
        return converter;
    }

    @Bean
    FilterRegistrationBean<TenantSelectionValidationFilter> tenantSelectionFilterRegistration(
            TenantSelectionValidationFilter filter) {
        FilterRegistrationBean<TenantSelectionValidationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    PkceS256EnforcementFilter pkceS256EnforcementFilter(
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.spa.client-id}") String clientId) {
        return new PkceS256EnforcementFilter(clientId);
    }

    @Bean
    FilterRegistrationBean<PkceS256EnforcementFilter> pkceS256FilterRegistration(
            PkceS256EnforcementFilter filter) {
        FilterRegistrationBean<PkceS256EnforcementFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    FilterRegistrationBean<TrustedForwardedHeadersFilter> trustedForwardedHeadersFilterRegistration(
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.trusted-proxy-addresses:}")
            String trustedProxyAddresses) {
        FilterRegistrationBean<TrustedForwardedHeadersFilter> registration = new FilterRegistrationBean<>(
                new TrustedForwardedHeadersFilter(trustedProxyAddresses));
        registration.setOrder(org.springframework.core.Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

    @Bean
    FilterRegistrationBean<TransportSecurityFilter> transportSecurityFilterRegistration(Environment environment) {
        FilterRegistrationBean<TransportSecurityFilter> registration = new FilterRegistrationBean<>(
                new TransportSecurityFilter(environment));
        registration.setOrder(org.springframework.core.Ordered.HIGHEST_PRECEDENCE + 1);
        return registration;
    }

    @Bean
    FilterRegistrationBean<AuthenticationRateLimitFilter> authenticationRateLimitFilterRegistration(
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.rate-limit.max-requests:30}")
            int maxRequests,
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.rate-limit.window-seconds:60}")
            long windowSeconds,
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.onboarding-rate-limit.max-requests:3}")
            int onboardingMaxRequests,
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.onboarding-rate-limit.window-seconds:3600}")
            long onboardingWindowSeconds) {
        FilterRegistrationBean<AuthenticationRateLimitFilter> registration = new FilterRegistrationBean<>(
                new AuthenticationRateLimitFilter(maxRequests, windowSeconds, onboardingMaxRequests,
                        onboardingWindowSeconds));
        registration.setOrder(org.springframework.core.Ordered.HIGHEST_PRECEDENCE + 2);
        return registration;
    }

    @Bean
    com.agentshield.identity.auth.SpaReauthenticationFilter spaReauthenticationFilter(
            @org.springframework.beans.factory.annotation.Value("${agentshield.security.spa.client-id}") String clientId,
            SecurityContextRepository securityContextRepository) {
        return new com.agentshield.identity.auth.SpaReauthenticationFilter(clientId, securityContextRepository);
    }

    private static void validateOrigin(String value, boolean development) {
        if (value.contains("*") || value.contains(",")) {
            throw new IllegalStateException("CORS origins must be exact origins without wildcards");
        }
        try {
            URI uri = URI.create(value);
            boolean localhost = "localhost".equalsIgnoreCase(uri.getHost())
                    || "127.0.0.1".equals(uri.getHost()) || "[::1]".equals(uri.getHost())
                    || "::1".equals(uri.getHost());
            if (uri.getHost() == null || uri.getUserInfo() != null || uri.getPath() != null && !uri.getPath().isEmpty()
                    || uri.getQuery() != null || uri.getFragment() != null
                    || !("https".equalsIgnoreCase(uri.getScheme()) || development && localhost
                            && "http".equalsIgnoreCase(uri.getScheme()))) {
                throw new IllegalStateException("CORS origin must be an exact HTTPS origin");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("CORS origin is invalid", exception);
        }
    }

    private static void validateHttpsUrl(String value, Environment environment, String setting) {
        String[] profiles = environment.getActiveProfiles();
        boolean development = profiles.length > 0
                && Arrays.stream(profiles).allMatch(profile -> profile.equals("local") || profile.equals("test"));
        URI uri = URI.create(value);
        boolean localhost = "localhost".equalsIgnoreCase(uri.getHost())
                || "127.0.0.1".equals(uri.getHost()) || "::1".equals(uri.getHost())
                || "[::1]".equals(uri.getHost());
        boolean valid = "https".equalsIgnoreCase(uri.getScheme())
                || development && localhost && "http".equalsIgnoreCase(uri.getScheme());
        if (!valid || uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null
                || uri.getFragment() != null) {
            throw new IllegalStateException(setting + " must use HTTPS outside local/test and must be a valid URL");
        }
    }

    private static void requireConfigured(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Required authentication setting is missing: " + name);
        }
    }
}
