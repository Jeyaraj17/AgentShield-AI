package com.agentshield.policyengine.policy.api;

import java.util.List;
import java.util.UUID;

public record EvaluationDecision(Decision decision, String reasonCode, List<MatchedRule> matchedRules) {
    public enum Decision { ALLOW, DENY }
    public record MatchedRule(UUID policyId, int policyVersion, UUID ruleId, String effect) {}
    public EvaluationDecision { matchedRules = List.copyOf(matchedRules); }
    public static EvaluationDecision deny(String reason) { return new EvaluationDecision(Decision.DENY, reason, List.of()); }
}
