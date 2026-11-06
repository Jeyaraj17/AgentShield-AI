package com.agentshield.aianalysis.analysis.service;

import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AgentOwnershipVerifier {
    private final AgentDirectoryLookupClient directory;

    public AgentOwnershipVerifier(AgentDirectoryLookupClient directory) {
        this.directory = directory;
    }

    public void requireOwnedBy(UUID organizationId, UUID agentId, String userAccessToken) {
        try {
            AgentOwnershipDescriptor agent = directory.findAgent(agentId, userAccessToken);
            if (agent == null || !agentId.equals(agent.id()) || !organizationId.equals(agent.organizationId())) {
                throw notFound();
            }
        } catch (ResponseStatusException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Agent ownership could not be verified", exception);
        }
    }

    private static ResponseStatusException notFound() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, "Agent was not found in this organization");
    }
}
