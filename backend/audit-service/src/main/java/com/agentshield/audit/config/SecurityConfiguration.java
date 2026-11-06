package com.agentshield.audit.config;

import java.util.ArrayList;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.net.URI;
import java.util.Arrays;
import java.util.List;

@Configuration
public class SecurityConfiguration {
    @Bean CorsConfigurationSource corsConfigurationSource(@Value("${agentshield.security.cors.allowed-origins:}") String configured,Environment environment) {
        String[] profiles=environment.getActiveProfiles();boolean local=profiles.length>0&&Arrays.stream(profiles).allMatch(p->p.equals("local")||p.equals("test"));
        List<String> origins=Arrays.stream(configured.split(",")).map(String::trim).filter(s->!s.isBlank()).peek(s->validateOrigin(s,local)).toList();
        if(!local&&origins.isEmpty())throw new IllegalStateException("AUDIT_CORS_ALLOWED_ORIGINS must be configured outside local/test");
        if(origins.isEmpty())return request->null;
        var cors=new CorsConfiguration();cors.setAllowedOrigins(origins);cors.setAllowedMethods(List.of("GET","OPTIONS"));
        cors.setAllowedHeaders(List.of("Authorization","Accept","Content-Type","X-Correlation-ID"));cors.setAllowCredentials(false);
        var source=new UrlBasedCorsConfigurationSource();source.registerCorsConfiguration("/api/**",cors);return source;
    }
    @Bean Converter<Jwt,? extends AbstractAuthenticationToken> auditJwtConverter(){
        return jwt->{
            var authorities=new ArrayList<SimpleGrantedAuthority>();
            if("user".equals(jwt.getClaimAsString("identity_type"))){String role=jwt.getClaimAsString("organization_role");if(role!=null)authorities.add(new SimpleGrantedAuthority("ROLE_"+role));}
            return new JwtAuthenticationToken(jwt,authorities,jwt.getSubject());
        };
    }
    @Bean SecurityFilterChain securityFilterChain(HttpSecurity http,Converter<Jwt,? extends AbstractAuthenticationToken> converter) throws Exception {
        return http.csrf(csrf->csrf.disable()).cors(Customizer.withDefaults()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a->a.requestMatchers("/actuator/health").permitAll()
                        .requestMatchers(HttpMethod.GET,"/api/v1/audit/events","/api/v1/audit/events/*","/api/v1/audit/summary").hasAnyRole("OWNER","ADMIN","MEMBER")
                        .anyRequest().denyAll())
                .httpBasic(b->b.disable()).formLogin(f->f.disable()).logout(l->l.disable())
                .oauth2ResourceServer(o->o.jwt(j->j.jwtAuthenticationConverter(converter))).build();
    }
    private static void validateOrigin(String value,boolean local){
        if(value.contains("*"))throw new IllegalStateException("Wildcard CORS origins are forbidden");
        URI uri=URI.create(value);boolean loop="localhost".equalsIgnoreCase(uri.getHost())||"127.0.0.1".equals(uri.getHost());
        if(uri.getHost()==null||uri.getUserInfo()!=null||uri.getPath()!=null&&!uri.getPath().isEmpty()||uri.getQuery()!=null||uri.getFragment()!=null
                ||!("https".equalsIgnoreCase(uri.getScheme())||local&&loop&&"http".equalsIgnoreCase(uri.getScheme())))
            throw new IllegalStateException("CORS origins must be exact HTTPS origins (HTTP loopback only in local/test)");
    }
}
