package com.agentshield.agentmanagement.agent.service;

import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.dao.DataIntegrityViolationException;

import com.agentshield.agentmanagement.agent.api.CreateAgentRequest;
import com.agentshield.agentmanagement.agent.persistence.AgentRepository;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentServiceConstraintTests {

    @Mock
    private AgentRepository agentRepository;

    @InjectMocks
    private AgentService agentService;

    @Test
    void translatesOnlyNamedAgentCodeConstraintForConcurrentDuplicateInsert() {
        UUID organizationId = UUID.randomUUID();
        when(agentRepository.existsByOrganizationIdAndAgentCode(organizationId, "AGENT-1")).thenReturn(false);
        when(agentRepository.saveAndFlush(any())).thenThrow(violationOf("uk_agents_organization_code"));

        assertThrows(DuplicateAgentCodeException.class, () -> agentService.register(organizationId,
                new CreateAgentRequest("Agent", "agent-1", null, "assistant", List.of())));
    }

    @Test
    void preservesUnrelatedDatabaseIntegrityErrors() {
        UUID organizationId = UUID.randomUUID();
        when(agentRepository.existsByOrganizationIdAndAgentCode(organizationId, "AGENT-1")).thenReturn(false);
        DataIntegrityViolationException databaseException = violationOf("ck_agents_status");
        when(agentRepository.saveAndFlush(any())).thenThrow(databaseException);

        DataIntegrityViolationException thrown = assertThrows(DataIntegrityViolationException.class,
                () -> agentService.register(organizationId,
                        new CreateAgentRequest("Agent", "agent-1", null, "assistant", List.of())));

        assertSame(databaseException, thrown);
    }

    private DataIntegrityViolationException violationOf(String constraintName) {
        ConstraintViolationException cause = new ConstraintViolationException(
                "constraint violation", new SQLException("constraint violation"), "insert into agents", constraintName);
        return new DataIntegrityViolationException("Database integrity violation", cause);
    }
}
