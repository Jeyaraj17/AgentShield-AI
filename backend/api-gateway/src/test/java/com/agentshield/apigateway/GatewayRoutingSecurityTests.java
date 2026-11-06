package com.agentshield.apigateway;

import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import com.sun.net.httpserver.HttpExchange;
import reactor.core.publisher.Mono;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class GatewayRoutingSecurityTests {
    private static final Backend IDENTITY=new Backend("identity");
    private static final Backend AGENTS=new Backend("agents");
    private static final Backend POLICIES=new Backend("policies");
    private static final Backend RUNTIME=new Backend("runtime");
    private static final Backend ANALYSIS=new Backend("analysis");
    private static final Backend AUDIT=new Backend("audit");
    private static final Backend NOTIFICATIONS=new Backend("notifications");
    static {
        try { IDENTITY.start(); AGENTS.start(); POLICIES.start(); RUNTIME.start(); ANALYSIS.start(); AUDIT.start(); NOTIFICATIONS.start(); }
        catch (IOException ex) { throw new ExceptionInInitializerError(ex); }
    }
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        registry.add("agentshield.gateway.identity-service-url",IDENTITY::uri);
        registry.add("agentshield.gateway.agent-management-service-url",AGENTS::uri);
        registry.add("agentshield.gateway.policy-engine-service-url",POLICIES::uri);
        registry.add("agentshield.gateway.runtime-security-gateway-service-url",RUNTIME::uri);
        registry.add("agentshield.gateway.ai-analysis-service-url",ANALYSIS::uri);
        registry.add("agentshield.gateway.audit-service-url",AUDIT::uri);
        registry.add("agentshield.gateway.notification-service-url",NOTIFICATIONS::uri);
        registry.add("agentshield.security.organization-onboarding.enabled",() -> true);
    }
    @Autowired WebTestClient client;
    @MockitoBean ReactiveJwtDecoder decoder;

    @Test void healthAndAuthenticationRoutesAreExplicitlyPublic() {
        client.get().uri("/actuator/health").exchange().expectStatus().isOk();
        client.get().uri("/login").exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");
        client.get().uri("/api/v1/agents").exchange().expectStatus().isUnauthorized()
                .expectHeader().exists("X-Correlation-ID").expectBody().jsonPath("$.title").isEqualTo("Authentication required");
    }

    @Test void localIdentityRouteMakesSessionCookieUsableOnLoopbackHttp() {
        var result = client.get().uri("/login").exchange().expectStatus().isOk().expectBody().returnResult();
        String setCookie = result.getResponseHeaders().getFirst(HttpHeaders.SET_COOKIE);
        org.junit.jupiter.api.Assertions.assertNotNull(setCookie);
        org.junit.jupiter.api.Assertions.assertTrue(setCookie.contains("HttpOnly"));
        org.junit.jupiter.api.Assertions.assertTrue(setCookie.contains("SameSite=Lax"));
        org.junit.jupiter.api.Assertions.assertFalse(setCookie.matches("(?i).*;\\s*Secure(?:;.*)?$"));
    }

    @Test void enabledOnboardingRequestRoutesToIdentityWithoutAUserToken() {
        client.post().uri("/api/v1/onboarding/organizations").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");
    }

    @Test void onboardingRouteAllowsExpectedPasswordHashingAndTransactionLatency() throws Exception {
        IDENTITY.onboardingDelayMs=6000;
        try {
            client.mutate().responseTimeout(Duration.ofSeconds(10)).build()
                    .post().uri("/api/v1/onboarding/organizations").contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{}")
                    .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");
        } finally {
            IDENTITY.onboardingDelayMs=0;
        }
    }

    @Test void verifiedClaimsReplaceUntrustedTenantAndRoleHeadersAndRouteCorrectly() {
        UUID user=UUID.randomUUID(),org=UUID.randomUUID(); stub("signed-member",user,org,"MEMBER");
        client.get().uri("/api/v1/agents/abc").header(HttpHeaders.AUTHORIZATION,"Bearer signed-member")
                .header("X-Organization-Id","attacker-org").header("X-Role","OWNER")
                .header("X-Authenticated-User-Id","attacker-user").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","agents")
                .expectHeader().valueEquals("X-Observed-User",user.toString())
                .expectHeader().valueEquals("X-Observed-Organization",org.toString())
                .expectHeader().valueEquals("X-Observed-Role","MEMBER");
        client.get().uri("/api/v1/policies").header(HttpHeaders.AUTHORIZATION,"Bearer signed-member").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","policies");
        client.get().uri("/api/v1/users/"+user).header(HttpHeaders.AUTHORIZATION,"Bearer signed-member").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");
    }

    @Test void roleRulesProtectManagementAndMembersCanReadOnly() {
        UUID user=UUID.randomUUID(),org=UUID.randomUUID(); stub("member-role",user,org,"MEMBER");
        client.post().uri("/api/v1/agents").header(HttpHeaders.AUTHORIZATION,"Bearer member-role")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange().expectStatus().isForbidden();
        client.get().uri("/api/v1/organizations").header(HttpHeaders.AUTHORIZATION,"Bearer member-role").exchange().expectStatus().isOk();
        stub("admin-role",UUID.randomUUID(),org,"ADMIN");
        client.post().uri("/api/v1/agents").header(HttpHeaders.AUTHORIZATION,"Bearer admin-role")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange().expectStatus().isOk();
        client.get().uri("/api/v1/users/"+UUID.randomUUID()).header(HttpHeaders.AUTHORIZATION,"Bearer member-role").exchange().expectStatus().isForbidden();
    }

    @Test void organizationReadRoutesEnforceClaimRoleAndRouteToIdentity() {
        UUID owner=UUID.randomUUID(),org=UUID.randomUUID(); stub("organization-owner",owner,org,"OWNER");
        client.get().uri("/api/v1/organizations/current").header(HttpHeaders.AUTHORIZATION,"Bearer organization-owner")
                .header("X-Organization-Id",UUID.randomUUID().toString()).exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity")
                .expectHeader().valueEquals("X-Observed-Organization",org.toString());
        client.get().uri("/api/v1/organizations/current/members").header(HttpHeaders.AUTHORIZATION,"Bearer organization-owner")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");

        UUID admin=UUID.randomUUID(); stub("organization-admin",admin,org,"ADMIN");
        client.get().uri("/api/v1/organizations/current").header(HttpHeaders.AUTHORIZATION,"Bearer organization-admin")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");
        client.get().uri("/api/v1/organizations/current/members").header(HttpHeaders.AUTHORIZATION,"Bearer organization-admin")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");

        UUID member=UUID.randomUUID(); stub("organization-member",member,org,"MEMBER");
        client.get().uri("/api/v1/organizations/current").header(HttpHeaders.AUTHORIZATION,"Bearer organization-member")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");
        client.get().uri("/api/v1/organizations/current/members").header(HttpHeaders.AUTHORIZATION,"Bearer organization-member")
                .exchange().expectStatus().isForbidden();
        client.get().uri("/api/v1/users/me").header(HttpHeaders.AUTHORIZATION,"Bearer organization-member")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");
        client.get().uri("/api/v1/users/me/membership").header(HttpHeaders.AUTHORIZATION,"Bearer organization-member")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");
        client.get().uri("/api/v1/users/me").exchange().expectStatus().isUnauthorized();
    }

    @Test void dashboardRoutesResolveRuntimeAndAnalysisBeforeAgentCrudAndStayRoleProtected() {
        UUID owner=UUID.randomUUID(),org=UUID.randomUUID(); stub("dashboard-owner",owner,org,"OWNER");
        client.get().uri("/api/v1/runtime/history?page=0").header(HttpHeaders.AUTHORIZATION,"Bearer dashboard-owner").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","runtime");
        client.get().uri("/api/v1/analysis/findings").header(HttpHeaders.AUTHORIZATION,"Bearer dashboard-owner").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","analysis");
        client.get().uri("/api/v1/agents/agent-123/trust-score").header(HttpHeaders.AUTHORIZATION,"Bearer dashboard-owner").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","analysis");
        client.get().uri("/api/v1/agents/agent-123").header(HttpHeaders.AUTHORIZATION,"Bearer dashboard-owner").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","agents");
        UUID admin=UUID.randomUUID(); stub("dashboard-admin",admin,org,"ADMIN");
        client.get().uri("/api/v1/runtime/history").header(HttpHeaders.AUTHORIZATION,"Bearer dashboard-admin").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","runtime");
        UUID member=UUID.randomUUID(); stub("dashboard-member",member,org,"MEMBER");
        client.get().uri("/api/v1/runtime/history").header(HttpHeaders.AUTHORIZATION,"Bearer dashboard-member").exchange().expectStatus().isForbidden();
        client.get().uri("/api/v1/analysis/findings").header(HttpHeaders.AUTHORIZATION,"Bearer dashboard-member").exchange().expectStatus().isForbidden();
        client.post().uri("/api/v1/analysis/prompts").header(HttpHeaders.AUTHORIZATION,"Bearer dashboard-owner")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange().expectStatus().isForbidden();
    }

    @Test void runtimeSubmissionAndExecutionReadsRequireAgentIdentityAndRouteToRuntimeGateway() {
        UUID agent=UUID.randomUUID(),org=UUID.randomUUID();
        stubAgent("signed-agent",agent,org);
        client.post().uri("/api/v1/runtime/execute").header(HttpHeaders.AUTHORIZATION,"Bearer signed-agent")
                .header("X-Organization-ID",UUID.randomUUID().toString()).header("X-Organization-Role","OWNER")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","runtime");
        client.get().uri("/api/v1/runtime/executions/"+UUID.randomUUID()).header(HttpHeaders.AUTHORIZATION,"Bearer signed-agent")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","runtime");

        UUID user=UUID.randomUUID(); stub("signed-user",user,org,"OWNER");
        client.post().uri("/api/v1/runtime/execute").header(HttpHeaders.AUTHORIZATION,"Bearer signed-user")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange().expectStatus().isForbidden();
        client.get().uri("/api/v1/runtime/executions/"+UUID.randomUUID()).header(HttpHeaders.AUTHORIZATION,"Bearer signed-user")
                .exchange().expectStatus().isForbidden();
    }

    @Test void credentialRevocationIsForwardedOnlyForOrganizationAdministrators() {
        UUID owner=UUID.randomUUID(),org=UUID.randomUUID(); stub("credential-owner",owner,org,"OWNER");
        String credentialPath="/api/v1/organizations/"+org+"/agents/"+UUID.randomUUID()+"/credentials/"+UUID.randomUUID();
        client.delete().uri(credentialPath).header(HttpHeaders.AUTHORIZATION,"Bearer credential-owner")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity");
        stub("credential-member",UUID.randomUUID(),org,"MEMBER");
        client.delete().uri(credentialPath).header(HttpHeaders.AUTHORIZATION,"Bearer credential-member")
                .exchange().expectStatus().isForbidden();
    }

    @Test void invalidJwtMissingTenantAndPolicyEvaluationAreDenied() {
        when(decoder.decode("invalid")).thenReturn(Mono.error(new BadJwtException("bad")));
        client.get().uri("/api/v1/agents").header(HttpHeaders.AUTHORIZATION,"Bearer invalid").exchange().expectStatus().isUnauthorized();
        when(decoder.decode("missing-org")).thenReturn(Mono.error(new BadJwtException("claims invalid")));
        client.get().uri("/api/v1/agents").header(HttpHeaders.AUTHORIZATION,"Bearer missing-org").exchange().expectStatus().isUnauthorized();
        UUID user=UUID.randomUUID(),org=UUID.randomUUID(); stub("member-evaluate",user,org,"MEMBER");
        client.post().uri("/api/v1/policies/evaluate").header(HttpHeaders.AUTHORIZATION,"Bearer member-evaluate")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}").exchange().expectStatus().isForbidden();
    }

    @Test void auditAndNotificationRoutesPreserveServiceAndRoleBoundaries() {
        UUID org=UUID.randomUUID();stub("audit-member",UUID.randomUUID(),org,"MEMBER");
        client.get().uri("/api/v1/audit/events").header(HttpHeaders.AUTHORIZATION,"Bearer audit-member")
                .header("X-Organization-Id",UUID.randomUUID().toString()).header("X-Role","OWNER").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","audit");
        client.get().uri("/api/v1/audit/summary").header(HttpHeaders.AUTHORIZATION,"Bearer audit-member").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","audit");
        client.get().uri("/api/v1/notifications").header(HttpHeaders.AUTHORIZATION,"Bearer audit-member").exchange().expectStatus().isForbidden();
        stub("notifications-admin",UUID.randomUUID(),org,"ADMIN");
        client.get().uri("/api/v1/notifications").header(HttpHeaders.AUTHORIZATION,"Bearer notifications-admin").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","notifications");
        client.patch().uri("/api/v1/notifications/read-all").header(HttpHeaders.AUTHORIZATION,"Bearer notifications-admin").exchange()
                .expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","notifications");
        client.get().uri("/api/v1/notifications").exchange().expectStatus().isUnauthorized();
    }

    @Test void corsIsLimitedToConfiguredExactOrigin() {
        client.options().uri("/api/v1/agents").header("Origin","http://localhost:3000")
                .header("Access-Control-Request-Method","GET").exchange().expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin","http://localhost:3000");
        client.options().uri("/api/v1/agents").header("Origin","https://evil.example")
                .header("Access-Control-Request-Method","GET").exchange().expectStatus().isForbidden();
    }

    @Test void identityTokenResponseDoesNotDuplicateGatewayCorsHeaders() {
        client.post().uri("/oauth2/token").header(HttpHeaders.ORIGIN,"http://localhost:3000")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).bodyValue("grant_type=authorization_code")
                .exchange().expectStatus().isOk()
                .expectBody().consumeWith(result -> org.junit.jupiter.api.Assertions.assertEquals(
                        List.of("http://localhost:3000"),
                        result.getResponseHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)));
        client.post().uri("/oauth2/token").header(HttpHeaders.ORIGIN,"https://unapproved.example")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).bodyValue("grant_type=authorization_code")
                .exchange().expectStatus().isForbidden();
    }

    @Test void authenticatedApiResponseDoesNotDuplicateGatewayCorsHeaders() {
        stub("cors-member",UUID.randomUUID(),UUID.randomUUID(),"MEMBER");
        client.get().uri("/api/v1/agents").header(HttpHeaders.ORIGIN,"http://localhost:3000")
                .header(HttpHeaders.AUTHORIZATION,"Bearer cors-member").exchange().expectStatus().isOk()
                .expectBody().consumeWith(result -> org.junit.jupiter.api.Assertions.assertEquals(
                        List.of("http://localhost:3000"),
                        result.getResponseHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)));
    }

    @Test void identityApiUsesGatewayCorsAndRejectsUnapprovedOrigin() {
        stub("identity-cors-owner",UUID.randomUUID(),UUID.randomUUID(),"OWNER");
        client.get().uri("/api/v1/users/me").header(HttpHeaders.ORIGIN,"http://localhost:3000")
                .header(HttpHeaders.AUTHORIZATION,"Bearer identity-cors-owner").exchange().expectStatus().isOk()
                .expectBody().consumeWith(result -> org.junit.jupiter.api.Assertions.assertEquals(
                        List.of("http://localhost:3000"),
                        result.getResponseHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN)));
        client.get().uri("/api/v1/users/me").header(HttpHeaders.ORIGIN,"https://unapproved.example")
                .header(HttpHeaders.AUTHORIZATION,"Bearer identity-cors-owner").exchange().expectStatus().isForbidden();
    }

    @Test void opaqueOriginIsAllowedOnlyForSameOriginTopLevelLoginNavigation() {
        client.post().uri("/login").header("Origin","null")
                .header("Sec-Fetch-Site","same-origin").header("Sec-Fetch-Mode","navigate")
                .header("Sec-Fetch-Dest","document").header("Sec-Fetch-User","?1")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).bodyValue("username=probe&password=")
                .exchange().expectStatus().isOk().expectHeader().valueEquals("X-Backend-Name","identity")
                .expectHeader().doesNotExist("Access-Control-Allow-Credentials");

        client.post().uri("/login").header("Origin","null")
                .header("Sec-Fetch-Site","cross-site").header("Sec-Fetch-Mode","navigate")
                .header("Sec-Fetch-Dest","document").header("Sec-Fetch-User","?1")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).bodyValue("username=probe&password=")
                .exchange().expectStatus().isForbidden();

        client.post().uri("/api/v1/onboarding/organizations").header("Origin","null")
                .header("Sec-Fetch-Site","same-origin").header("Sec-Fetch-Mode","navigate")
                .header("Sec-Fetch-Dest","document").header("Sec-Fetch-User","?1")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isForbidden();
    }

    @Test void downstreamServerErrorsAreSanitized() {
        stub("admin-for-error",UUID.randomUUID(),UUID.randomUUID(),"ADMIN");
        client.get().uri("/api/v1/agents/unavailable").header(HttpHeaders.AUTHORIZATION,"Bearer admin-for-error").exchange()
                .expectStatus().is5xxServerError().expectBody().consumeWith(result -> {
                    String body=new String(result.getResponseBody(),StandardCharsets.UTF_8);
                    org.junit.jupiter.api.Assertions.assertFalse(body.contains("database-password"));
                    org.junit.jupiter.api.Assertions.assertTrue(body.contains("Service temporarily unavailable"));
                });
        AGENTS.down.set(true);
        try {
            client.get().uri("/api/v1/agents/offline").header(HttpHeaders.AUTHORIZATION,"Bearer admin-for-error").exchange()
                    .expectStatus().is5xxServerError().expectBody().consumeWith(result -> {
                        String body=new String(result.getResponseBody(),StandardCharsets.UTF_8);
                        org.junit.jupiter.api.Assertions.assertFalse(body.contains("database-password"));
                    });
        } finally { AGENTS.down.set(false); }
    }

    private void stub(String token,UUID user,UUID org,String role) {
        Instant now=Instant.now();
        Jwt jwt=Jwt.withTokenValue(token).header("alg","RS256").issuer("http://localhost:19000")
                .audience(List.of("agentshield-api")).subject(user.toString()).issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(300))
                .claim("identity_type","user").claim("user_id",user.toString())
                .claim("organization_id",org.toString()).claim("organization_role",role).build();
        when(decoder.decode(token)).thenReturn(Mono.just(jwt));
    }

    private void stubAgent(String token,UUID agent,UUID org) {
        Instant now=Instant.now();
        Jwt jwt=Jwt.withTokenValue(token).header("alg","RS256").issuer("http://localhost:19000")
                .audience(List.of("agentshield-runtime-api")).subject(agent.toString()).issuedAt(now.minusSeconds(1)).expiresAt(now.plusSeconds(300))
                .claim("identity_type","agent").claim("token_type","agent").claim("agent_id",agent.toString())
                .claim("organization_id",org.toString()).claim("agent_role","AGENT").build();
        when(decoder.decode(token)).thenReturn(Mono.just(jwt));
    }

    private static final class Backend {
        private final String name; private final AtomicBoolean down=new AtomicBoolean(); private volatile long onboardingDelayMs; private HttpServer server;
        Backend(String name) { this.name=name; }
        void start() throws IOException {
            server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
            server.setExecutor(Executors.newCachedThreadPool(r -> { Thread t=new Thread(r); t.setDaemon(true); return t; }));
            server.createContext("/",this::handle); server.start();
        }
        String uri() { return "http://127.0.0.1:"+server.getAddress().getPort(); }
        void handle(HttpExchange exchange) throws IOException {
            if (down.get()) { exchange.close(); return; }
            if ("identity".equals(name) && "/oauth2/token".equals(exchange.getRequestURI().getPath())
                    && exchange.getRequestHeaders().getFirst("Origin") != null
                    && !"http://localhost:3000".equals(exchange.getRequestHeaders().getFirst("Origin"))) {
                exchange.sendResponseHeaders(403,-1); exchange.close(); return;
            }
            if ("identity".equals(name) && "/api/v1/onboarding/organizations".equals(exchange.getRequestURI().getPath()) && onboardingDelayMs>0) {
                try { Thread.sleep(onboardingDelayMs); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); exchange.close(); return; }
            }
            exchange.getResponseHeaders().add("X-Backend-Name",name);
            if ("identity".equals(name) && "/login".equals(exchange.getRequestURI().getPath())) {
                exchange.getResponseHeaders().add("Set-Cookie", "JSESSIONID=local-session; Path=/; Secure; HttpOnly; SameSite=Lax");
            }
            echo(exchange,"X-Authenticated-User-Id","X-Observed-User");
            echo(exchange,"X-Authenticated-Organization-Id","X-Observed-Organization");
            echo(exchange,"X-Authenticated-Organization-Role","X-Observed-Role");
            int status=exchange.getRequestURI().getPath().endsWith("/unavailable")?503:200;
            byte[] body=(status==503?"database-password=internal-secret":"ok").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status,body.length); exchange.getResponseBody().write(body); exchange.close();
        }
        private static void echo(HttpExchange exchange,String incoming,String outgoing) {
            String value=exchange.getRequestHeaders().getFirst(incoming); if(value!=null) exchange.getResponseHeaders().add(outgoing,value);
        }
    }
}
