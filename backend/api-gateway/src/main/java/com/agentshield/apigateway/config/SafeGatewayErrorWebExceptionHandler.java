package com.agentshield.apigateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SafeGatewayErrorWebExceptionHandler implements WebExceptionHandler {
    private static final Logger log=LoggerFactory.getLogger(SafeGatewayErrorWebExceptionHandler.class);
    @Override public Mono<Void> handle(ServerWebExchange exchange,Throwable exception) {
        if (exchange.getResponse().isCommitted()) return Mono.error(exception);
        log.warn("event=gateway_failure correlationId={} exceptionType={}",
                exchange.getResponse().getHeaders().getFirst("X-Correlation-ID"),exception.getClass().getSimpleName());
        return SafeGatewayResponses.write(exchange,503,"Service temporarily unavailable");
    }
}
