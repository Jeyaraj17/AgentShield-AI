package com.agentshield.audit.persistence;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface AuditEventRepository extends JpaRepository<AuditEventEntity,UUID>,JpaSpecificationExecutor<AuditEventEntity> {
    java.util.Optional<AuditEventEntity> findByEventIdAndOrganizationId(UUID eventId,UUID organizationId);
    long countByOrganizationId(UUID organizationId);
    long countByOrganizationIdAndDecision(UUID organizationId,String decision);
    long countByOrganizationIdAndExecutionOutcome(UUID organizationId,String outcome);
    long countByOrganizationIdAndEventType(UUID organizationId,com.agentshield.events.contract.EventType eventType);
}
