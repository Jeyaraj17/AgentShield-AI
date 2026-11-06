package com.agentshield.aianalysis.analysis.service;

import java.net.URI;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.server.ResponseStatusException;

@Component
public class RestAgentDirectoryLookupClient implements AgentDirectoryLookupClient {
    private final RestClient client;

    public RestAgentDirectoryLookupClient(@Value("${agentshield.analysis.agent-management.base-url}") String baseUrl) {
        URI uri = URI.create(baseUrl);
        if (!uri.isAbsolute() || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null
                || !("https".equalsIgnoreCase(uri.getScheme())
                    || ("http".equalsIgnoreCase(uri.getScheme()) && isLoopback(uri.getHost())))) {
            throw new IllegalStateException("AGENT_MANAGEMENT_SERVICE_URL must be HTTPS outside localhost development");
        }
        this.client = RestClient.builder().baseUrl(baseUrl).build();
    }

    @Override
    public AgentOwnershipDescriptor findAgent(UUID agentId, String userAccessToken) {
        try {
            return client.get().uri("/api/v1/agents/{agentId}", agentId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + userAccessToken)
                    .retrieve().body(AgentOwnershipDescriptor.class);
        } catch (RestClientResponseException exception) {
            if (exception.getStatusCode().value() == 404) return null;
            if (exception.getStatusCode().value() == 401 || exception.getStatusCode().value() == 403) {
                throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                        "Agent ownership verification was rejected by the directory");
            }
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Agent directory is unavailable");
        } catch (RuntimeException exception) {
            if (exception instanceof ResponseStatusException responseStatusException) throw responseStatusException;
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Agent directory is unavailable");
        }
    }

    private static boolean isLoopback(String host) {
        return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host);
    }
}
