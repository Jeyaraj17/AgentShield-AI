package com.agentshield.aianalysis.security;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import com.agentshield.aianalysis.web.AnalysisRequestGuardFilter;
import com.agentshield.aianalysis.web.ApiErrorWriter;
import org.springframework.http.HttpStatus;

@Configuration
public class SecurityConfiguration {
    @Bean SecurityFilterChain securityFilterChain(HttpSecurity http,Converter<Jwt,AbstractAuthenticationToken> converter,
            @org.springframework.beans.factory.annotation.Qualifier("jwtDecoder") JwtDecoder decoder,
            AnalysisRequestGuardFilter guard) throws Exception {
        return http.csrf(csrf->csrf.disable()).cors(Customizer.withDefaults())
                .sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a->a.requestMatchers(HttpMethod.GET,"/actuator/health").permitAll()
                        .requestMatchers(HttpMethod.POST,"/api/v1/analysis/**").hasAuthority("ROLE_RUNTIME_GATEWAY_ANALYSIS")
                        .requestMatchers(HttpMethod.GET,"/api/v1/analysis/**").hasAnyAuthority("ROLE_OWNER","ROLE_ADMIN")
                        .requestMatchers(HttpMethod.GET,"/api/v1/agents/**").hasAnyAuthority("ROLE_OWNER","ROLE_ADMIN")
                        .anyRequest().denyAll())
                .oauth2ResourceServer(o->o.jwt(j->j.decoder(decoder).jwtAuthenticationConverter(converter)))
                .exceptionHandling(e->e.authenticationEntryPoint((request,response,exception)->ApiErrorWriter.write(response,HttpStatus.UNAUTHORIZED,"Authentication is required"))
                        .accessDeniedHandler((request,response,exception)->ApiErrorWriter.write(response,HttpStatus.FORBIDDEN,"Access is denied")))
                .addFilterBefore(guard,UsernamePasswordAuthenticationFilter.class).build();
    }

    @Bean CorsConfigurationSource corsConfigurationSource(@Value("${agentshield.security.cors.allowed-origins:}") String origins) {
        List<String> allowedOrigins=List.of(origins.split(",")).stream().map(String::trim).filter(s->!s.isBlank()).toList();
        if (allowedOrigins.isEmpty()) return request -> null;
        CorsConfiguration config=new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins);
        config.setAllowedMethods(List.of("GET","POST","OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization","Content-Type","X-Agent-Assertion","X-Correlation-ID"));
        config.setAllowCredentials(false); config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source=new UrlBasedCorsConfigurationSource(); source.registerCorsConfiguration("/**",config); return source;
    }
}
