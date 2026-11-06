package com.agentshield.policyengine.policy.domain;

import java.util.List;

public record RuleConditions(ConditionJoin join, List<RuleConditionClause> clauses) {
    public RuleConditions {
        clauses = clauses == null ? null : List.copyOf(clauses);
    }
}
