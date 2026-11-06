package com.agentshield.runtimesecurity.runtime.integration;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.Executors;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.mock.env.MockEnvironment;

class GatewayServiceTokenProviderTests {
    @Test void analysisScopeUsesDedicatedClientCredentials() throws Exception {
        HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        var requests=new java.util.concurrent.CopyOnWriteArrayList<Request>();
        server.setExecutor(Executors.newCachedThreadPool(r->{Thread t=new Thread(r);t.setDaemon(true);return t;}));
        server.createContext("/oauth2/token",exchange->respond(exchange,requests));server.start();
        try {
            JdkClientHttpRequestFactory factory=new JdkClientHttpRequestFactory(HttpClient.newBuilder().build());
            MockEnvironment environment=new MockEnvironment();environment.setActiveProfiles("test");
            GatewayServiceTokenProvider provider=new ExternalServiceConfiguration().gatewayServiceTokenProvider(
                    "http://localhost:"+server.getAddress().getPort()+"/oauth2/token","runtime-general","general-secret",
                    "runtime-analysis","analysis-secret",factory,environment);
            assertEquals("test-access-token",provider.tokenFor("analysis.evaluate"));
            assertEquals("test-access-token",provider.tokenFor("policy.evaluate"));
            assertEquals(2,requests.size());
            assertEquals("Basic "+Base64.getEncoder().encodeToString("runtime-analysis:analysis-secret".getBytes(StandardCharsets.UTF_8)),requests.get(0).authorization());
            assertEquals("grant_type=client_credentials&scope=analysis.evaluate",requests.get(0).body());
            assertEquals("Basic "+Base64.getEncoder().encodeToString("runtime-general:general-secret".getBytes(StandardCharsets.UTF_8)),requests.get(1).authorization());
            assertEquals("grant_type=client_credentials&scope=policy.evaluate",requests.get(1).body());
        } finally {server.stop(0);}
    }
    private static void respond(HttpExchange exchange,java.util.List<Request> requests) throws IOException {
        String body=new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8);
        requests.add(new Request(exchange.getRequestHeaders().getFirst("Authorization"),body));
        byte[] response="{\"access_token\":\"test-access-token\",\"token_type\":\"Bearer\",\"expires_in\":120}".getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type","application/json");exchange.sendResponseHeaders(200,response.length);
        exchange.getResponseBody().write(response);exchange.close();
    }
    private record Request(String authorization,String body) { }
}
