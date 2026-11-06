package com.agentshield.apigateway.config;

import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

final class SafeGatewayResponses {
    private SafeGatewayResponses() {}
    static Mono<Void> write(ServerWebExchange exchange,int status,String message) {
        var response=exchange.getResponse();
        response.setStatusCode(HttpStatusCode.valueOf(status));
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        String id=exchange.getResponse().getHeaders().getFirst("X-Correlation-ID");
        String json="{\"status\":"+status+",\"title\":\""+message+"\",\"correlationId\":\""+(id==null?"":id)+"\"}";
        byte[] body=json.getBytes(StandardCharsets.UTF_8);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }
}
