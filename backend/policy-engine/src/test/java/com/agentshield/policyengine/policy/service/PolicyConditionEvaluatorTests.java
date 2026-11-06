package com.agentshield.policyengine.policy.service;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.agentshield.policyengine.policy.domain.*;
import tools.jackson.databind.ObjectMapper;

class PolicyConditionEvaluatorTests {
    private final PolicyConditionEvaluator evaluator = new PolicyConditionEvaluator();
    private final ObjectMapper mapper = new ObjectMapper();
    @Test void evaluatesStructuredCondition() throws Exception {
        var c = new RuleConditions(ConditionJoin.ALL, List.of(new RuleConditionClause("resource.path", ConditionOperator.EQUALS, mapper.readTree("\"/safe\""))));
        assertTrue(evaluator.matches(c, mapper.readTree("{\"path\":\"/safe\"}"), Map.of()));
        assertFalse(evaluator.matches(c, mapper.readTree("{\"path\":\"/other\"}"), Map.of()));
    }
    @Test void rejectsExpressionLanguageAndInvalidOperators() throws Exception {
        var c = new RuleConditions(ConditionJoin.ALL, List.of(new RuleConditionClause("resource.path;T(java.lang.Runtime)", ConditionOperator.EQUALS, mapper.readTree("1"))));
        assertThrows(InvalidPolicyException.class, () -> evaluator.validate(c));
    }
    @Test void missingFieldDoesNotMatchEvenForNotEquals() throws Exception {
        var c = new RuleConditions(ConditionJoin.ALL, List.of(new RuleConditionClause("resource.path", ConditionOperator.NOT_EQUALS, mapper.readTree("1"))));
        assertFalse(evaluator.matches(c, mapper.readTree("{}"), Map.of()));
    }
}
