package com.agentshield.policyengine.policy.service;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import com.agentshield.policyengine.policy.domain.ConditionJoin;
import com.agentshield.policyengine.policy.domain.ConditionOperator;
import com.agentshield.policyengine.policy.domain.RuleConditionClause;
import com.agentshield.policyengine.policy.domain.RuleConditions;
import tools.jackson.databind.JsonNode;

@Component
public class PolicyConditionEvaluator {
    private static final Pattern FIELD = Pattern.compile("(?:resource|context)(?:\\.[A-Za-z0-9_-]+){0,8}");

    public boolean matches(RuleConditions conditions, JsonNode resource, Map<String, JsonNode> context) {
        if (conditions == null) return true;
        validate(conditions);
        List<Boolean> results = conditions.clauses().stream().map(c -> evaluate(c, resource, context)).toList();
        return conditions.join() == ConditionJoin.ALL ? results.stream().allMatch(Boolean::booleanValue)
                : results.stream().anyMatch(Boolean::booleanValue);
    }

    public void validate(RuleConditions c) {
        if (c == null || c.join() == null || c.clauses() == null || c.clauses().isEmpty() || c.clauses().size() > 20)
            throw new InvalidPolicyException("Conditions require a join and between 1 and 20 clauses");
        for (RuleConditionClause clause : c.clauses()) {
            if (clause == null || clause.field() == null || !FIELD.matcher(clause.field()).matches() || clause.operator() == null || clause.value() == null || clause.value().isNull())
                throw new InvalidPolicyException("Condition clause is invalid");
            JsonNode v = clause.value();
            boolean scalar = v.isValueNode();
            boolean arrayScalars = v.isArray() && v.size() > 0;
            if (arrayScalars) for (JsonNode item : v) if (!item.isValueNode() || item.isNull()) arrayScalars = false;
            boolean allowed = switch (clause.operator()) {
                case EQUALS, NOT_EQUALS -> scalar;
                case CONTAINS -> scalar && v.isTextual();
                case IN, NOT_IN -> arrayScalars;
            };
            if (!allowed) throw new InvalidPolicyException("Condition value does not match operator");
        }
    }

    private boolean evaluate(RuleConditionClause c, JsonNode resource, Map<String, JsonNode> context) {
        JsonNode actual = resolve(c.field(), resource, context);
        if (actual == null || actual.isMissingNode() || actual.isNull()) return false;
        JsonNode expected = c.value();
        return switch (c.operator()) {
            case EQUALS -> actual.equals(expected);
            case NOT_EQUALS -> !actual.equals(expected);
            case IN -> contains(expected, actual);
            case NOT_IN -> !contains(expected, actual);
            case CONTAINS -> actual.isTextual() && actual.asText().contains(expected.asText());
        };
    }
    private static boolean contains(JsonNode array, JsonNode value) { for (JsonNode item : array) if (item.equals(value)) return true; return false; }
    private static JsonNode resolve(String field, JsonNode resource, Map<String, JsonNode> context) {
        String[] parts = field.split("\\.");
        JsonNode value;
        int start;
        if (parts[0].equals("resource")) { value=resource; start=1; }
        else { value=context == null ? null : context.get(parts[1]); start=2; }
        for (int i=start; value != null && i<parts.length; i++) value = value.path(parts[i]);
        return value;
    }
}
