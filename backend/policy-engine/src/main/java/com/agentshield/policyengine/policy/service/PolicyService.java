package com.agentshield.policyengine.policy.service;

import java.util.List;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.agentshield.policyengine.policy.api.*;
import com.agentshield.policyengine.policy.domain.*;
import com.agentshield.policyengine.policy.persistence.PolicyRuleRepository;
import com.agentshield.policyengine.policy.persistence.SecurityPolicyRepository;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.contract.SecurityEvent;
import com.agentshield.events.outbox.OutboxEventWriter;

@Service
public class PolicyService {
    private final SecurityPolicyRepository policies;
    private final PolicyRuleRepository rules;
    private final PolicyConditionEvaluator conditionEvaluator;
    private final OutboxEventWriter events;
    public PolicyService(SecurityPolicyRepository policies, PolicyRuleRepository rules, PolicyConditionEvaluator conditionEvaluator, OutboxEventWriter events) {
        this.policies=policies; this.rules=rules; this.conditionEvaluator=conditionEvaluator; this.events=events;
    }

    @Transactional
    public PolicyResponse create(UUID org, PolicyDefinitionRequest request) {
        UUID key=UUID.randomUUID();
        PolicyResponse saved=saveVersion(org,key,1,request,PolicyStatus.DRAFT);
        publish(EventType.POLICY_CREATED, org, saved);
        return saved;
    }
    @Transactional
    public PolicyResponse update(UUID org, UUID key, PolicyDefinitionRequest request) {
        SecurityPolicy current=policies.lockLatest(org,key).orElseThrow(PolicyNotFoundException::new);
        current.markHistorical();
        PolicyResponse saved=saveVersion(org,key,current.getVersion()+1,request,PolicyStatus.DRAFT);
        publish(EventType.POLICY_UPDATED, org, saved);
        return saved;
    }
    @Transactional
    public PolicyResponse changeStatus(UUID org, UUID key, PolicyStatus status) {
        if (status==PolicyStatus.DRAFT) throw new InvalidPolicyException("Status endpoint accepts ACTIVE or DISABLED only");
        SecurityPolicy current=policies.lockLatest(org,key).orElseThrow(PolicyNotFoundException::new);
        current.markHistorical();
        PolicyDefinitionRequest content=new PolicyDefinitionRequest(current.getName(),current.getDescription(),current.getPriority(),
                rules.findAllByPolicyVersionId(current.getId()).stream().map(r -> new PolicyRuleRequest(r.getName(),r.getAgentScope(),r.getTargetAgentId(),r.getAction(),r.getEffect(),r.getConditions())).toList());
        PolicyResponse saved=saveVersion(org,key,current.getVersion()+1,content,status);
        publish(status == PolicyStatus.ACTIVE ? EventType.POLICY_ACTIVATED : EventType.POLICY_UPDATED, org, saved);
        return saved;
    }
    private PolicyResponse saveVersion(UUID org, UUID key, int version, PolicyDefinitionRequest request, PolicyStatus status) {
        if (request.rules()==null || request.rules().isEmpty()) throw new InvalidPolicyException("A policy must contain at least one rule");
        try {
            SecurityPolicy policy=policies.saveAndFlush(new SecurityPolicy(null,key,org,request.name().trim(),request.description(),version,status,request.priority(),true));
            for (PolicyRuleRequest r:request.rules()) {
                if (r.agentScope()==AgentScope.SPECIFIC_AGENT && r.targetAgentId()==null || r.agentScope()==AgentScope.ALL_AGENTS && r.targetAgentId()!=null)
                    throw new InvalidPolicyException("Target agent must match the selected scope");
                if (r.conditions()!=null) conditionEvaluator.validate(r.conditions());
                rules.save(new PolicyRule(policy,r.name().trim(),r.agentScope(),r.targetAgentId(),r.action().trim(),r.effect(),r.conditions()));
            }
            return map(policy,rules.findAllByPolicyVersionId(policy.getId()));
        } catch (DataIntegrityViolationException ex) { throw new InvalidPolicyException("Concurrent policy version conflict"); }
    }
    @Transactional(readOnly=true)
    public List<PolicyResponse> list(UUID org) { return policies.findAllByOrganizationIdAndLatestVersionTrueOrderByPriorityDescCreatedAtDesc(org).stream().map(p -> map(p,rules.findAllByPolicyVersionId(p.getId()))).toList(); }
    @Transactional(readOnly=true)
    public PolicyResponse get(UUID org, UUID key) { var p=policies.findByOrganizationIdAndPolicyIdAndLatestVersionTrue(org,key).orElseThrow(PolicyNotFoundException::new); return map(p,rules.findAllByPolicyVersionId(p.getId())); }
    @Transactional(readOnly=true)
    public List<PolicyVersionResponse> versions(UUID org,UUID key) {
        if (policies.findByOrganizationIdAndPolicyIdAndLatestVersionTrue(org,key).isEmpty()) throw new PolicyNotFoundException();
        return policies.findAllByOrganizationIdAndPolicyIdOrderByVersionDesc(org,key).stream().map(p -> new PolicyVersionResponse(p.getPolicyId(),p.getId(),p.getVersion(),p.getStatus(),p.isLatestVersion(),p.getCreatedAt(),p.getUpdatedAt())).toList();
    }
    private static PolicyResponse map(SecurityPolicy p,List<PolicyRule> rs) {
        return new PolicyResponse(p.getPolicyId(),p.getId(),p.getOrganizationId(),p.getName(),p.getDescription(),p.getVersion(),p.getStatus(),p.getPriority(),p.getCreatedAt(),p.getUpdatedAt(),rs.stream().map(r -> new PolicyRuleResponse(r.getId(),r.getName(),r.getAgentScope(),r.getTargetAgentId(),r.getAction(),r.getEffect(),r.getConditions(),r.getCreatedAt())).toList());
    }
    private void publish(EventType type, UUID organizationId, PolicyResponse policy) {
        events.append(SecurityEvent.create(organizationId, type, null, java.util.Map.of(
                "policyId", policy.policyId().toString(), "version", Integer.toString(policy.version()), "status", policy.status().name())));
    }
}
