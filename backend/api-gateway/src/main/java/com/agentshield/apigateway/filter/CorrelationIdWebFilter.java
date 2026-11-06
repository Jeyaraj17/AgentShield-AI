package com.agentshield.apigateway.filter;

import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdWebFilter implements WebFilter {
    private static final Logger log=LoggerFactory.getLogger(CorrelationIdWebFilter.class);
    public static final String HEADER="X-Correlation-ID";
    @Override
    public Mono<Void> filter(ServerWebExchange exchange,WebFilterChain chain) {
        String candidate=exchange.getRequest().getHeaders().getFirst(HEADER);
        String correlationId=isUuid(candidate)?candidate:UUID.randomUUID().toString();
        var request=exchange.getRequest().mutate().headers(headers -> headers.set(HEADER,correlationId)).build();
        var mutated=exchange.mutate().request(request).build();
        mutated.getResponse().getHeaders().set(HEADER,correlationId);
        return chain.filter(mutated).doFinally(signal -> log.info(
                "event=http_request correlationId={} method={} path={} status={} outcome={}",correlationId,
                request.getMethod(),request.getURI().getRawPath(),mutated.getResponse().getStatusCode(),signal));
    }
    private static boolean isUuid(String value) {
        if (value==null || value.length()!=36) return false;
        try { UUID.fromString(value); return true; } catch (IllegalArgumentException ex) { return false; }
    }
}
