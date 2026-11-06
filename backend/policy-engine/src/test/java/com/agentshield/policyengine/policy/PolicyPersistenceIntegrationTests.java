package com.agentshield.policyengine.policy;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import com.agentshield.policyengine.policy.api.PolicyDefinitionRequest;
import com.agentshield.policyengine.policy.api.PolicyRuleRequest;
import com.agentshield.policyengine.policy.domain.AgentScope;
import com.agentshield.policyengine.policy.domain.PolicyStatus;
import com.agentshield.policyengine.policy.domain.RuleEffect;
import com.agentshield.policyengine.policy.service.PolicyService;

@SpringBootTest
@ActiveProfiles("test")
class PolicyPersistenceIntegrationTests {
    @Autowired PolicyService service;

    @Test void migrationAndVersionSnapshotsPersist() {
        UUID org=UUID.randomUUID();
        var definition=new PolicyDefinitionRequest("Allow read", "integration", 5,
                List.of(new PolicyRuleRequest("read",AgentScope.ALL_AGENTS,null,"tool.read",RuleEffect.ALLOW,null)));
        var first=service.create(org,definition);
        assertEquals(PolicyStatus.DRAFT,first.status());
        var second=service.update(org,first.policyId(),definition);
        assertEquals(2,second.version());
        var versions=service.versions(org,first.policyId());
        assertEquals(2,versions.size());
        assertTrue(versions.stream().anyMatch(v -> v.latest() && v.version()==2));
    }
}
