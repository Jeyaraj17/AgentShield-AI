package com.agentshield.aianalysis.analysis.persistence;

import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import com.agentshield.aianalysis.analysis.domain.BehaviorObservation;

public interface BehaviorObservationRepository extends JpaRepository<BehaviorObservation,UUID> {
    List<BehaviorObservation> findTop20ByOrganizationIdAndAgentIdOrderByCreatedAtDesc(UUID organizationId,UUID agentId);
    List<BehaviorObservation> findByOrganizationIdAndAgentIdOrderByCreatedAtDesc(UUID organizationId,UUID agentId,Pageable pageable);
    @Query("select b from BehaviorObservation b where b.organizationId=:org and (:agent is null or b.agentId=:agent) "
            + "and (:detected is null or b.driftDetected=:detected) and (:fromTime is null or b.createdAt>=:fromTime) "
            + "and (:toTime is null or b.createdAt<=:toTime)")
    Page<BehaviorObservation> search(@Param("org") UUID org,@Param("agent") UUID agent,@Param("detected") Boolean detected,
            @Param("fromTime") Instant from,@Param("toTime") Instant to,Pageable page);
}
