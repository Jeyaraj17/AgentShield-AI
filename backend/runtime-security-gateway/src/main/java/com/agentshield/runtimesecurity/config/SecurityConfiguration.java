package com.agentshield.runtimesecurity.config;

import java.io.IOException;
import java.util.ArrayList;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {
    @Bean JwtAuthenticationConverter runtimeJwtAuthenticationConverter() {
        JwtAuthenticationConverter converter=new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            if("agent".equals(jwt.getClaimAsString("identity_type")) && "AGENT".equals(jwt.getClaimAsString("agent_role")))
                return java.util.List.of(new SimpleGrantedAuthority("ROLE_AGENT"));
            String role=jwt.getClaimAsString("organization_role");
            return role==null?new ArrayList<>():java.util.List.of(new SimpleGrantedAuthority("ROLE_"+role));
        });
        return converter;
    }
    @Bean SecurityFilterChain securityFilterChain(HttpSecurity http,JwtAuthenticationConverter converter) throws Exception {
        return http.csrf(csrf -> csrf.disable()).cors(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/api/v1/runtime/history", "/api/v1/runtime/history/**").hasAnyRole("OWNER","ADMIN")
                        .requestMatchers("/api/v1/runtime/execute","/api/v1/runtime/executions/**").hasRole("AGENT")
                        .anyRequest().denyAll())
                .httpBasic(basic -> basic.disable()).formLogin(form -> form.disable()).logout(logout -> logout.disable())
                .exceptionHandling(ex -> ex.authenticationEntryPoint((request,response,error) -> write(response,401,"Authentication required"))
                        .accessDeniedHandler((request,response,error) -> write(response,403,"Access denied")))
                .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.jwtAuthenticationConverter(converter))).build();
    }
    private static void write(jakarta.servlet.http.HttpServletResponse response,int status,String title) throws IOException {
        response.setStatus(status); response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.getWriter().write("{\"status\":"+status+",\"title\":\""+title+"\"}");
    }
}
