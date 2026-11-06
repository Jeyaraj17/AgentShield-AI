package com.agentshield.policyengine.policy.domain;

import tools.jackson.databind.JsonNode;

public record RuleConditionClause(String field, ConditionOperator operator, JsonNode value) {
}
