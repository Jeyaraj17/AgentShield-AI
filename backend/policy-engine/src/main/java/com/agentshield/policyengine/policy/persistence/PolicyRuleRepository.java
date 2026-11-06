package com.agentshield.policyengine.policy.persistence;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import com.agentshield.policyengine.policy.domain.PolicyRule;

public interface PolicyRuleRepository extends JpaRepository<PolicyRule, UUID> {
    List<PolicyRule> findAllByPolicyVersionIdIn(List<UUID> policyVersionIds);
    List<PolicyRule> findAllByPolicyVersionId(UUID policyVersionId);
}
