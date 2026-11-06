package com.agentshield.aianalysis.analysis.persistence;

import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import com.agentshield.aianalysis.analysis.domain.AnalysisRecord;
import com.agentshield.aianalysis.analysis.domain.AnalysisType;

public interface AnalysisRecordRepository extends JpaRepository<AnalysisRecord,UUID> {
    List<AnalysisRecord> findByOrganizationIdAndAgentIdAndTypeInOrderByCreatedAtDesc(UUID organizationId,UUID agentId,List<AnalysisType> types,Pageable pageable);
    List<AnalysisRecord> findTop20ByOrganizationIdAndAgentIdAndTypeOrderByCreatedAtDesc(UUID organizationId,UUID agentId,AnalysisType type);
    List<AnalysisRecord> findTop20ByOrganizationIdAndAgentIdAndTypeInOrderByCreatedAtDesc(UUID organizationId,UUID agentId,List<AnalysisType> types);
    AnalysisRecord findFirstByOrganizationIdAndAgentIdAndTypeOrderByCreatedAtDesc(UUID organizationId,UUID agentId,AnalysisType type);
    @Query("select r from AnalysisRecord r where r.organizationId=:org and r.type in :types "
            + "and (:agent is null or r.agentId=:agent) and (:category is null or r.type=:category) "
            + "and (:minimum is null or r.riskScore>=:minimum) and (:maximum is null or r.riskScore<=:maximum) "
            + "and (:fromTime is null or r.createdAt>=:fromTime) and (:toTime is null or r.createdAt<=:toTime)")
    Page<AnalysisRecord> search(@Param("org") UUID org, @Param("types") List<AnalysisType> types,
            @Param("agent") UUID agent, @Param("category") AnalysisType category, @Param("minimum") Integer minimum,
            @Param("maximum") Integer maximum, @Param("fromTime") Instant from, @Param("toTime") Instant to, Pageable page);

    @Query("select r from AnalysisRecord r where r.organizationId=:org and r.type=:type "
            + "and (:fromTime is null or r.createdAt>=:fromTime) and (:toTime is null or r.createdAt<=:toTime)")
    Page<AnalysisRecord> history(@Param("org") UUID org,@Param("type") AnalysisType type,
            @Param("fromTime") Instant from,@Param("toTime") Instant to,Pageable page);
}
