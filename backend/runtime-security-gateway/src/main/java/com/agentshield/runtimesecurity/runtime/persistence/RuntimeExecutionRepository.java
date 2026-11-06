package com.agentshield.runtimesecurity.runtime.persistence;

import java.util.Optional;
import java.util.UUID;
import java.time.Instant;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import com.agentshield.runtimesecurity.runtime.domain.ExecutionResult;
import org.springframework.data.jpa.repository.JpaRepository;
import com.agentshield.runtimesecurity.runtime.domain.RuntimeExecution;

public interface RuntimeExecutionRepository extends JpaRepository<RuntimeExecution,UUID> {
    Optional<RuntimeExecution> findByIdAndOrganizationId(UUID id,UUID organizationId);

    @Query("select e from RuntimeExecution e where e.organizationId=:org "
            + "and (:agent is null or e.agentId=:agent) and (:outcome is null or e.executionResult=:outcome) "
            + "and (:decision is null or e.authorizationDecision=:decision) "
            + "and (:fromTime is null or e.createdAt>=:fromTime) and (:toTime is null or e.createdAt<=:toTime)")
    Page<RuntimeExecution> searchOrganization(@Param("org") UUID organizationId, @Param("agent") UUID agentId,
            @Param("outcome") ExecutionResult outcome, @Param("decision") com.agentshield.runtimesecurity.runtime.domain.AuthorizationDecision decision,
            @Param("fromTime") Instant from, @Param("toTime") Instant to, Pageable pageable);
}
