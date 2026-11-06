package com.agentshield.apigateway.filter;

import java.util.List;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import reactor.core.publisher.Mono;

@Component
public class VerifiedIdentityHeadersFilter implements GlobalFilter,Ordered {
    private static final List<String> UNTRUSTED_HEADERS=List.of(
            "X-User-Id","X-Authenticated-User-Id","X-Organization-Id","X-Authenticated-Organization-Id",
            "X-Organization-Role","X-Authenticated-Organization-Role","X-Tenant-Id","X-Tenant-Role","X-Role");
    @Override public int getOrder() { return Ordered.LOWEST_PRECEDENCE; }
    @Override
    public Mono<Void> filter(ServerWebExchange exchange,GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(authentication -> authentication instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .map(auth -> mutate(exchange,auth))
                .defaultIfEmpty(mutate(exchange,null))
                .flatMap(safeExchange -> chain.filter(safeExchange));
    }
    private ServerWebExchange mutate(ServerWebExchange exchange,JwtAuthenticationToken auth) {
        var request=exchange.getRequest().mutate().headers(headers -> {
            UNTRUSTED_HEADERS.forEach(headers::remove);
            if (auth!=null) {
                String userId=auth.getToken().getClaimAsString("user_id");
                String organizationId=auth.getToken().getClaimAsString("organization_id");
                String role=auth.getToken().getClaimAsString("organization_role");
                headers.set("X-Authenticated-User-Id",userId);
                headers.set("X-Authenticated-Organization-Id",organizationId);
                headers.set("X-Authenticated-Organization-Role",role);
            }
        }).build();
        return exchange.mutate().request(request).build();
    }
}
