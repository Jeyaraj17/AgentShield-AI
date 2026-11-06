package com.agentshield.policyengine.policy.persistence;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import com.agentshield.policyengine.policy.domain.SecurityPolicy;

public interface SecurityPolicyRepository extends JpaRepository<SecurityPolicy, UUID> {
    List<SecurityPolicy> findAllByOrganizationIdAndLatestVersionTrueOrderByPriorityDescCreatedAtDesc(UUID organizationId);
    Optional<SecurityPolicy> findByOrganizationIdAndPolicyIdAndLatestVersionTrue(UUID organizationId, UUID policyId);
    List<SecurityPolicy> findAllByOrganizationIdAndPolicyIdOrderByVersionDesc(UUID organizationId, UUID policyId);
    List<SecurityPolicy> findAllByOrganizationIdAndLatestVersionTrueAndStatusOrderByPriorityDesc(UUID organizationId, com.agentshield.policyengine.policy.domain.PolicyStatus status);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select p from SecurityPolicy p where p.organizationId=:org and p.policyId=:policy and p.latestVersion=true")
    Optional<SecurityPolicy> lockLatest(@Param("org") UUID organizationId, @Param("policy") UUID policyId);
}
