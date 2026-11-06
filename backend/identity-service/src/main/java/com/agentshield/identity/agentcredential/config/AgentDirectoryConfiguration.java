package com.agentshield.identity.agentcredential.config;

import java.net.URI;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClient;
import com.agentshield.identity.agentcredential.AgentDirectoryVerifier;

@Configuration
public class AgentDirectoryConfiguration {
    @Bean AgentDirectoryVerifier agentDirectoryVerifier(@Value("${agentshield.security.agent-management.base-url}") String baseUrl,Environment environment) {
        if(baseUrl==null || baseUrl.isBlank()) throw new IllegalStateException("AGENT_MANAGEMENT_BASE_URL is required for agent credential issuance");
        URI uri=URI.create(baseUrl); String[] profiles=environment.getActiveProfiles();
        boolean local=profiles.length>0 && java.util.Arrays.stream(profiles).allMatch(p->p.equals("local")||p.equals("test"));
        boolean loopback="localhost".equalsIgnoreCase(uri.getHost())||"127.0.0.1".equals(uri.getHost())||"::1".equals(uri.getHost())||"[::1]".equals(uri.getHost());
        if(uri.getHost()==null || uri.getUserInfo()!=null || uri.getQuery()!=null || uri.getFragment()!=null
                || !("https".equalsIgnoreCase(uri.getScheme())||local&&loopback&&"http".equalsIgnoreCase(uri.getScheme())))
            throw new IllegalStateException("AGENT_MANAGEMENT_BASE_URL must use HTTPS outside local/test");
        RestClient client=RestClient.builder().baseUrl(baseUrl).build();
        return (agentId,organizationId,accessToken) -> {
            try {
                AgentSummary result=client.get().uri("/api/v1/agents/{id}",agentId)
                        .headers(headers -> headers.setBearerAuth(accessToken)).retrieve().body(AgentSummary.class);
                return result!=null && agentId.equals(result.id()) && organizationId.equals(result.organizationId()) && "ACTIVE".equals(result.status());
            } catch(org.springframework.web.client.RestClientException exception) { return false; }
        };
    }
    record AgentSummary(UUID id,UUID organizationId,String status) { }
}
