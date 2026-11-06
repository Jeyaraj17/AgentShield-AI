package com.agentshield.notification.config;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfiguration {
    @Bean SecurityFilterChain notificationFilterChain(HttpSecurity http) throws Exception {
        return http.csrf(csrf->csrf.disable()).cors(Customizer.withDefaults()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a->a.requestMatchers("/actuator/health").permitAll()
                        .requestMatchers(HttpMethod.GET,"/api/v1/notifications","/api/v1/notifications/*").hasAnyRole("OWNER","ADMIN")
                        .requestMatchers(HttpMethod.PATCH,"/api/v1/notifications/read-all","/api/v1/notifications/*/read").hasAnyRole("OWNER","ADMIN")
                        .anyRequest().denyAll())
                .httpBasic(b->b.disable()).formLogin(f->f.disable()).logout(l->l.disable())
                .oauth2ResourceServer(o->o.jwt(j->j.jwtAuthenticationConverter(jwt->new JwtAuthenticationToken(jwt,
                        List.of(new SimpleGrantedAuthority("ROLE_"+jwt.getClaimAsString("organization_role"))),jwt.getSubject())))).build();
    }
    @Bean CorsConfigurationSource notificationCors(@Value("${agentshield.security.cors.allowed-origins:}") String configured,Environment environment){
        String[] profiles=environment.getActiveProfiles();boolean local=profiles.length>0&&Arrays.stream(profiles).allMatch(p->p.equals("local")||p.equals("test"));
        List<String> origins=Arrays.stream(configured.split(",")).map(String::trim).filter(s->!s.isBlank()).peek(o->validateOrigin(o,local)).toList();
        if(!local&&origins.isEmpty())throw new IllegalStateException("NOTIFICATION_CORS_ALLOWED_ORIGINS must be configured outside local/test");
        if(origins.isEmpty())return request->null;
        CorsConfiguration cors=new CorsConfiguration();cors.setAllowedOrigins(origins);cors.setAllowedMethods(List.of("GET","PATCH","OPTIONS"));
        cors.setAllowedHeaders(List.of("Authorization","Accept","Content-Type","X-Correlation-ID"));cors.setAllowCredentials(false);
        UrlBasedCorsConfigurationSource source=new UrlBasedCorsConfigurationSource();source.registerCorsConfiguration("/api/**",cors);return source;
    }
    private static void validateOrigin(String value,boolean local){
        if(value.contains("*")||value.contains(","))throw new IllegalStateException("CORS origins must be exact");
        URI uri=URI.create(value);String host=uri.getHost();boolean loop="localhost".equalsIgnoreCase(host)||"127.0.0.1".equals(host)||"::1".equals(host)||"[::1]".equals(host);
        if(host==null||uri.getUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null||uri.getPath()!=null&&!uri.getPath().isEmpty()
                ||!("https".equalsIgnoreCase(uri.getScheme())||local&&loop&&"http".equalsIgnoreCase(uri.getScheme()))) throw new IllegalStateException("CORS origin must be exact HTTPS origin");
    }
}
