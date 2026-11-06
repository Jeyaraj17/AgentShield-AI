package com.agentshield.policyengine.policy.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.agentshield.policyengine.policy.api.EvaluationDecision;
import com.agentshield.policyengine.policy.api.EvaluationRequest;
import com.agentshield.policyengine.policy.domain.AgentScope;
import com.agentshield.policyengine.policy.domain.PolicyStatus;
import com.agentshield.policyengine.policy.domain.RuleEffect;
import com.agentshield.policyengine.policy.persistence.PolicyRuleRepository;
import com.agentshield.policyengine.policy.persistence.SecurityPolicyRepository;
import tools.jackson.databind.JsonNode;

@Service
public class PolicyEvaluationService {
    private final SecurityPolicyRepository policies;
    private final PolicyRuleRepository rules;
    private final PolicyConditionEvaluator conditions;
    public PolicyEvaluationService(SecurityPolicyRepository policies, PolicyRuleRepository rules, PolicyConditionEvaluator conditions) {
        this.policies=policies; this.rules=rules; this.conditions=conditions;
    }
    @Transactional(readOnly=true)
    public EvaluationDecision evaluate(UUID org, EvaluationRequest request) {
        try {
            var active = policies.findAllByOrganizationIdAndLatestVersionTrueAndStatusOrderByPriorityDesc(org, PolicyStatus.ACTIVE);
            var ruleList = active.isEmpty() ? List.<com.agentshield.policyengine.policy.domain.PolicyRule>of()
                    : rules.findAllByPolicyVersionIdIn(active.stream().map(p -> p.getId()).toList());
            Map<UUID, com.agentshield.policyengine.policy.domain.SecurityPolicy> byVersion = active.stream().collect(java.util.stream.Collectors.toMap(p -> p.getId(), p -> p));
            List<EvaluationDecision.MatchedRule> matched = new ArrayList<>(); boolean hasAllow=false, hasDeny=false;
            for (var rule : ruleList) {
                var policy=byVersion.get(rule.getPolicyVersion().getId());
                if (rule.getAgentScope()==AgentScope.SPECIFIC_AGENT && !request.agentId().equals(rule.getTargetAgentId())) continue;
                if (!rule.getAction().equals(request.action())) continue;
                if (!conditions.matches(rule.getConditions(), request.resource(), request.context())) continue;
                matched.add(new EvaluationDecision.MatchedRule(policy.getPolicyId(), policy.getVersion(), rule.getId(), rule.getEffect().name()));
                if (rule.getEffect()==RuleEffect.DENY) hasDeny=true; else hasAllow=true;
            }
            if (hasDeny) return new EvaluationDecision(EvaluationDecision.Decision.DENY,"MATCHED_DENY",matched);
            if (hasAllow) return new EvaluationDecision(EvaluationDecision.Decision.ALLOW,"MATCHED_ALLOW",matched);
            return EvaluationDecision.deny("NO_APPLICABLE_ALLOW");
        } catch (RuntimeException ex) { return EvaluationDecision.deny("EVALUATION_ERROR"); }
    }
}
