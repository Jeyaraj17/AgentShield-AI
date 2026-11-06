package com.agentshield.runtimesecurity.runtime.integration;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import com.agentshield.runtimesecurity.config.JwtConfiguration;
import com.agentshield.runtimesecurity.runtime.api.RuntimeToolRequest;

@Configuration
public class ExternalServiceConfiguration {
    private static final Pattern ACTION=Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.:-]{0,149}");

    @Bean GatewayServiceTokenProvider gatewayServiceTokenProvider(@Value("${agentshield.identity.token-uri}") String tokenUri,
            @Value("${agentshield.identity.runtime-gateway.client-id}") String clientId,
            @Value("${agentshield.identity.runtime-gateway.client-secret}") String clientSecret,
            @Value("${agentshield.identity.runtime-gateway.analysis-client-id}") String analysisClientId,
            @Value("${agentshield.identity.runtime-gateway.analysis-client-secret}") String analysisClientSecret,
            ClientHttpRequestFactory requestFactory,Environment environment) {
        JwtConfiguration.validateHttps(tokenUri,environment,"IDENTITY_TOKEN_URI");
        URI tokenEndpoint=URI.create(tokenUri);
        if(!"/oauth2/token".equals(tokenEndpoint.getPath())||tokenEndpoint.getQuery()!=null||tokenEndpoint.getFragment()!=null)
            throw new IllegalStateException("IDENTITY_TOKEN_URI must point to the OAuth token endpoint");
        if(clientId==null||clientId.isBlank()||clientSecret==null||clientSecret.isBlank()
                ||analysisClientId==null||analysisClientId.isBlank()||analysisClientSecret==null||analysisClientSecret.isBlank())
            throw new IllegalStateException("Runtime Gateway OAuth client credentials are required");
        RestClient client=RestClient.builder().requestFactory(requestFactory).build();
        return scope -> {
            boolean analysis="analysis.evaluate".equals(scope);
            if(!analysis&&!java.util.Set.of("agents.read","policy.evaluate").contains(scope)) throw new IllegalArgumentException("Unregistered gateway token scope");
            String selectedClient=analysis?analysisClientId:clientId, selectedSecret=analysis?analysisClientSecret:clientSecret;
            var form=new org.springframework.util.LinkedMultiValueMap<String,String>(); form.add("grant_type","client_credentials"); form.add("scope",scope);
            TokenResponse response=client.post().uri(tokenUri).headers(h->h.setBasicAuth(selectedClient,selectedSecret))
                    .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED).body(form).retrieve().body(TokenResponse.class);
            if(response==null||response.access_token()==null||response.access_token().isBlank()||!"Bearer".equalsIgnoreCase(response.token_type()))
                throw new IllegalStateException("Identity Service returned an invalid service token response");
            return response.access_token();
        };
    }

    @Bean AiAnalysisClient aiAnalysisClient(@Value("${agentshield.ai-analysis.base-url}") String baseUrl,
            @Value("${agentshield.ai-analysis.connect-timeout}") Duration connectTimeout,
            @Value("${agentshield.ai-analysis.response-timeout}") Duration responseTimeout,Environment environment) {
        validateBase(baseUrl,environment,"AI_ANALYSIS_BASE_URL");
        ClientHttpRequestFactory requestFactory=new org.springframework.http.client.JdkClientHttpRequestFactory(
                HttpClient.newBuilder().connectTimeout(connectTimeout).followRedirects(HttpClient.Redirect.NEVER).build());
        ((org.springframework.http.client.JdkClientHttpRequestFactory)requestFactory).setReadTimeout(responseTimeout);
        RestClient client=RestClient.builder().baseUrl(baseUrl).requestFactory(requestFactory).build();
        return new AiAnalysisClient() {
            @Override public AnalysisResult analyzePrompt(java.util.UUID organizationId,java.util.UUID agentId,String prompt,
                    String serviceToken,String agentAssertion,String correlationId) {
                return send("/api/v1/analysis/prompts",Map.of("prompt",prompt),organizationId,agentId,serviceToken,agentAssertion,correlationId);
            }
            @Override public AnalysisResult analyzeResponse(java.util.UUID organizationId,java.util.UUID agentId,String response,
                    String serviceToken,String agentAssertion,String correlationId) {
                return send("/api/v1/analysis/responses",Map.of("response",response),organizationId,agentId,serviceToken,agentAssertion,correlationId);
            }
            private AnalysisResult send(String path,Map<String,Object> body,java.util.UUID organizationId,java.util.UUID agentId,
                    String serviceToken,String assertion,String correlationId) {
                if(serviceToken==null||serviceToken.isBlank()||assertion==null||assertion.isBlank()||serviceToken.equals(assertion))
                    throw new IllegalArgumentException("Distinct service token and agent assertion are required");
                return client.post().uri(path).headers(headers->{headers.setBearerAuth(serviceToken);
                            headers.set("X-Agent-Assertion",assertion);headers.set("X-Organization-ID",organizationId.toString());
                            headers.set("X-Agent-ID",agentId.toString());headers.set("X-Correlation-ID",correlationId);})
                        .body(body).retrieve().body(AnalysisResult.class);
            }
        };
    }

    @Bean AgentDirectoryClient agentDirectoryClient(@Value("${agentshield.agent-management.base-url}") String baseUrl,
            ClientHttpRequestFactory requestFactory,Environment environment) {
        validateBase(baseUrl,environment,"AGENT_MANAGEMENT_BASE_URL");
        RestClient client=RestClient.builder().baseUrl(baseUrl).requestFactory(requestFactory).build();
        return (agentId,organizationId,token,correlationId) -> {
            try {
                return client.get().uri("/internal/v1/agents/{agentId}",agentId).headers(headers -> { headers.setBearerAuth(token); headers.set("X-Correlation-ID",correlationId); headers.set("X-Organization-ID",organizationId.toString()); })
                        .retrieve().body(AgentDirectoryClient.AgentDescriptor.class);
            } catch(org.springframework.web.client.HttpClientErrorException.NotFound ex) { return null; }
        };
    }

    @Bean PolicyAuthorizationClient policyAuthorizationClient(@Value("${agentshield.policy-engine.base-url}") String baseUrl,
            ClientHttpRequestFactory requestFactory,Environment environment) {
        validateBase(baseUrl,environment,"POLICY_ENGINE_BASE_URL");
        RestClient client=RestClient.builder().baseUrl(baseUrl).requestFactory(requestFactory).build();
        return (organizationId,agentId,action,resourceId,context,serviceToken,agentAssertion,correlationId) -> {
            Map<String,Object> resource=Map.of("id",resourceId);
            Map<String,Object> policyContext=new LinkedHashMap<>(context); policyContext.put("organizationId",organizationId);
            Map<String,Object> request=Map.of("agentId",agentId,"action",action,"resource",resource,"context",policyContext);
            return client.post().uri("/api/v1/policies/evaluate").headers(headers -> { headers.setBearerAuth(serviceToken); headers.set("X-Agent-Assertion",agentAssertion); headers.set("X-Organization-ID",organizationId.toString()); headers.set("X-Correlation-ID",correlationId); })
                    .body(request).retrieve().body(PolicyAuthorizationClient.PolicyDecisionResponse.class);
        };
    }

    @Bean RegisteredToolExecutor registeredToolExecutor(@Value("${agentshield.runtime.tools.destinations}") String configured,
            ClientHttpRequestFactory requestFactory,Environment environment) {
        Map<String,URI> destinations=parseDestinations(configured,environment);
        Map<String,RestClient> clients=new LinkedHashMap<>();
        destinations.forEach((action,destination) -> clients.put(action,RestClient.builder().requestFactory(requestFactory).build()));
        return new RegisteredToolExecutor() {
            @Override public boolean isRegistered(String action) { return destinations.containsKey(action); }
            @Override public Map<String,Object> execute(RuntimeToolRequest request) {
                RestClient client=clients.get(request.action()); URI destination=destinations.get(request.action());
                if(client==null || destination==null) throw new ToolNotRegisteredException();
                @SuppressWarnings("unchecked") Map<String,Object> result=(Map<String,Object>)client.post().uri(destination)
                        .header("X-Correlation-ID",request.correlationId()).body(request).retrieve()
                        .onStatus(HttpStatusCode::is3xxRedirection,(clientRequest,response) -> {
                            throw new IllegalStateException("Redirect responses from registered tools are forbidden");
                        }).body(Map.class);
                return result;
            }
        };
    }

    static Map<String,URI> parseDestinations(String configured,Environment environment) {
        if(configured==null || configured.isBlank()) throw new IllegalStateException("At least one registered runtime tool destination is required");
        Map<String,URI> result=new LinkedHashMap<>();
        for(String entry:configured.split(",")) {
            String[] pair=entry.trim().split("=",2);
            if(pair.length!=2 || !ACTION.matcher(pair[0].trim()).matches()) throw new IllegalStateException("Runtime tool destinations must be action=URL pairs");
            URI uri;
            try { uri=URI.create(pair[1].trim()); } catch(IllegalArgumentException ex) { throw new IllegalStateException("Registered tool URL is invalid"); }
            JwtConfiguration.validateHttps(uri.toString(),environment,"RUNTIME_TOOL_DESTINATIONS");
            if(uri.getQuery()!=null || uri.getFragment()!=null) throw new IllegalStateException("Registered tool URL cannot contain query or fragment");
            if(result.putIfAbsent(pair[0].trim(),uri)!=null) throw new IllegalStateException("A runtime action can have only one registered destination");
        }
        return Map.copyOf(result);
    }
    private static void validateBase(String value,Environment environment,String setting) {
        if(value==null || value.isBlank()) throw new IllegalStateException(setting+" must be configured");
        JwtConfiguration.validateHttps(value,environment,setting);
        URI uri=URI.create(value);
        if(uri.getPath()!=null && !uri.getPath().isEmpty() && !uri.getPath().equals("/")) throw new IllegalStateException(setting+" must be a service base URL");
    }
    record TokenResponse(String access_token,String token_type,long expires_in) { }
}
