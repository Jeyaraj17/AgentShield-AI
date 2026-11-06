package com.agentshield.policyengine.policy.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import com.agentshield.policyengine.policy.api.EvaluationDecision;
import com.agentshield.policyengine.policy.api.EvaluationRequest;
import com.agentshield.policyengine.policy.domain.*;
import com.agentshield.policyengine.policy.persistence.*;
import tools.jackson.databind.ObjectMapper;

class PolicyEvaluationServiceTests {
    private final SecurityPolicyRepository policies=mock(SecurityPolicyRepository.class);
    private final PolicyRuleRepository rules=mock(PolicyRuleRepository.class);
    private final UUID org=UUID.randomUUID(), agent=UUID.randomUUID();
    private final PolicyEvaluationService service=new PolicyEvaluationService(policies,rules,new PolicyConditionEvaluator());

    @Test void denyTakesPrecedenceOverAllow() {
        SecurityPolicy allow=policy(1); SecurityPolicy deny=policy(2);
        when(policies.findAllByOrganizationIdAndLatestVersionTrueAndStatusOrderByPriorityDesc(org,PolicyStatus.ACTIVE)).thenReturn(List.of(allow,deny));
        when(rules.findAllByPolicyVersionIdIn(anyList())).thenReturn(List.of(rule(allow,RuleEffect.ALLOW),rule(deny,RuleEffect.DENY)));
        var result=service.evaluate(org,new EvaluationRequest(agent,"tool.invoke",null,Map.of()));
        assertEquals(EvaluationDecision.Decision.DENY,result.decision());
        assertEquals("MATCHED_DENY",result.reasonCode());
        assertEquals(2,result.matchedRules().size());
    }
    @Test void defaultsToDenyWhenNoActiveAllowMatches() {
        when(policies.findAllByOrganizationIdAndLatestVersionTrueAndStatusOrderByPriorityDesc(org,PolicyStatus.ACTIVE)).thenReturn(List.of());
        var result=service.evaluate(org,new EvaluationRequest(agent,"tool.invoke",null,Map.of()));
        assertEquals("NO_APPLICABLE_ALLOW",result.reasonCode());
    }
    @Test void malformedStoredConditionFailsClosed() {
        SecurityPolicy p=policy(1);
        when(policies.findAllByOrganizationIdAndLatestVersionTrueAndStatusOrderByPriorityDesc(org,PolicyStatus.ACTIVE)).thenReturn(List.of(p));
        var malformed=new RuleConditions(null,List.of());
        when(rules.findAllByPolicyVersionIdIn(anyList())).thenReturn(List.of(new PolicyRule(p,"bad",AgentScope.ALL_AGENTS,null,"tool.invoke",RuleEffect.ALLOW,malformed)));
        assertEquals("EVALUATION_ERROR",service.evaluate(org,new EvaluationRequest(agent,"tool.invoke",null,Map.of())).reasonCode());
    }
    private SecurityPolicy policy(int priority) { return new SecurityPolicy(UUID.randomUUID(),UUID.randomUUID(),org,"test",null,1,PolicyStatus.ACTIVE,priority,true); }
    private PolicyRule rule(SecurityPolicy p,RuleEffect effect) { return new PolicyRule(p,"rule",AgentScope.ALL_AGENTS,null,"tool.invoke",effect,null); }
}
