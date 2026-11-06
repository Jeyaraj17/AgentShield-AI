package com.agentshield.apigateway.filter;

import java.nio.charset.StandardCharsets;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class SanitizeDownstreamErrorFilter implements GlobalFilter,Ordered {
    @Override public int getOrder() { return -2; }
    @Override public Mono<Void> filter(ServerWebExchange exchange,GatewayFilterChain chain) {
        var decorated=new ServerHttpResponseDecorator(exchange.getResponse()) {
            @Override public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                HttpStatusCode status=getStatusCode();
                if (status!=null && status.is5xxServerError()) {
                    getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
                    getHeaders().remove("Content-Length");
                    String correlationId=getHeaders().getFirst(CorrelationIdWebFilter.HEADER);
                    String json="{\"status\":"+status.value()+",\"title\":\"Service temporarily unavailable\",\"correlationId\":\""+(correlationId==null?"":correlationId)+"\"}";
                    byte[] bytes=json.getBytes(StandardCharsets.UTF_8);
                    return super.writeWith(Mono.fromSupplier(() -> bufferFactory().wrap(bytes)));
                }
                return super.writeWith(body);
            }
            @Override public Mono<Void> writeAndFlushWith(Publisher<? extends Publisher<? extends DataBuffer>> body) {
                return writeWith(Flux.from(body).concatMap(p -> p));
            }
        };
        return chain.filter(exchange.mutate().response(decorated).build());
    }
}
