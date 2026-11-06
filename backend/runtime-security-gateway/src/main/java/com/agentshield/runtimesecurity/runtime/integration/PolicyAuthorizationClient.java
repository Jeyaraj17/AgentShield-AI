package com.agentshield.runtimesecurity.runtime.integration;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public interface PolicyAuthorizationClient {
    PolicyDecisionResponse authorize(UUID organizationId,UUID agentId,String action,String resourceId,
            Map<String,Object> context,String serviceToken,String agentAssertion,String correlationId);
    record PolicyDecisionResponse(String decision,String reasonCode,List<MatchedRule> matchedRules) {
        public PolicyDecisionResponse { matchedRules=matchedRules==null?null:List.copyOf(matchedRules); }
    }
    record MatchedRule(UUID policyId,int policyVersion,UUID ruleId,String effect) {}
}
