package com.agentshield.identity.agentcredential.persistence;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import com.agentshield.identity.agentcredential.domain.AgentCredential;
import com.agentshield.identity.agentcredential.domain.AgentCredentialStatus;

public interface AgentCredentialRepository extends JpaRepository<AgentCredential, UUID> {
    Optional<AgentCredential> findByClientId(String clientId);
    Optional<AgentCredential> findByIdAndAgentIdAndOrganizationId(UUID id, UUID agentId, UUID organizationId);
    Optional<AgentCredential> findByClientIdAndStatus(String clientId, AgentCredentialStatus status);
}
