package com.agentshield.agentmanagement.agent.persistence;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import com.agentshield.agentmanagement.agent.domain.Agent;

public interface AgentRepository extends JpaRepository<Agent, UUID> {

    boolean existsByOrganizationIdAndAgentCode(UUID organizationId, String agentCode);

    boolean existsByOrganizationIdAndAgentCodeAndIdNot(UUID organizationId, String agentCode, UUID id);

    Page<Agent> findAllByOrganizationId(UUID organizationId, Pageable pageable);

    Optional<Agent> findByIdAndOrganizationId(UUID id, UUID organizationId);
}
