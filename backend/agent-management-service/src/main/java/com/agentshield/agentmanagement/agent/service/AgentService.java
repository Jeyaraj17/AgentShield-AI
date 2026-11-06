package com.agentshield.agentmanagement.agent.service;

import java.util.List;
import java.util.Locale;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.agentshield.agentmanagement.agent.api.AgentPageResponse;
import com.agentshield.agentmanagement.agent.api.AgentResponse;
import com.agentshield.agentmanagement.agent.api.CreateAgentRequest;
import com.agentshield.agentmanagement.agent.api.UpdateAgentRequest;
import com.agentshield.agentmanagement.agent.domain.Agent;
import com.agentshield.agentmanagement.agent.domain.AgentStatus;
import com.agentshield.agentmanagement.agent.persistence.AgentRepository;
import com.agentshield.events.contract.EventType;
import com.agentshield.events.contract.SecurityEvent;
import com.agentshield.events.outbox.OutboxEventWriter;

@Service
public class AgentService {

    private static final String AGENT_CODE_CONSTRAINT = "uk_agents_organization_code";

    private final AgentRepository agentRepository;
    private final OutboxEventWriter events;

    public AgentService(AgentRepository agentRepository, OutboxEventWriter events) {
        this.agentRepository = agentRepository;
        this.events = events;
    }

    @Transactional
    public AgentResponse register(UUID organizationId, CreateAgentRequest request) {
        String code = normalizeCode(request.agentCode());
        if (agentRepository.existsByOrganizationIdAndAgentCode(organizationId, code)) {
            throw new DuplicateAgentCodeException(code);
        }
        Agent agent = new Agent(organizationId, request.name().strip(), code,
                stripToNull(request.description()), normalizeType(request.agentType()), normalizeCapabilities(request.capabilities()));
        try {
            Agent saved = agentRepository.saveAndFlush(agent);
            publish(EventType.AGENT_REGISTERED, saved);
            return AgentResponse.from(saved);
        } catch (DataIntegrityViolationException exception) {
            if (violatesAgentCodeConstraint(exception)) {
                throw new DuplicateAgentCodeException(code);
            }
            throw exception;
        }
    }

    @Transactional(readOnly = true)
    public AgentPageResponse list(UUID organizationId, int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<AgentResponse> agents = agentRepository.findAllByOrganizationId(organizationId, pageRequest)
                .map(AgentResponse::from);
        return AgentPageResponse.from(agents);
    }

    @Transactional(readOnly = true)
    public AgentResponse get(UUID organizationId, UUID agentId) {
        return AgentResponse.from(findAgent(organizationId, agentId));
    }

    @Transactional
    public AgentResponse update(UUID organizationId, UUID agentId, UpdateAgentRequest request) {
        Agent agent = findAgent(organizationId, agentId);
        String code = normalizeCode(request.agentCode());
        if (agentRepository.existsByOrganizationIdAndAgentCodeAndIdNot(organizationId, code, agentId)) {
            throw new DuplicateAgentCodeException(code);
        }
        agent.updateDetails(request.name().strip(), code, stripToNull(request.description()),
                normalizeType(request.agentType()), normalizeCapabilities(request.capabilities()));
        try {
            Agent saved = agentRepository.saveAndFlush(agent);
            publish(saved.getStatus() == AgentStatus.INACTIVE ? EventType.AGENT_DEACTIVATED : EventType.AGENT_UPDATED, saved);
            return AgentResponse.from(saved);
        } catch (DataIntegrityViolationException exception) {
            if (violatesAgentCodeConstraint(exception)) {
                throw new DuplicateAgentCodeException(code);
            }
            throw exception;
        }
    }

    @Transactional
    public AgentResponse changeStatus(UUID organizationId, UUID agentId, AgentStatus status) {
        Agent agent = findAgent(organizationId, agentId);
        agent.changeStatus(status);
        Agent saved = agentRepository.saveAndFlush(agent);
        publish(status == AgentStatus.INACTIVE ? EventType.AGENT_DEACTIVATED : EventType.AGENT_UPDATED, saved);
        return AgentResponse.from(saved);
    }

    @Transactional
    public void deactivate(UUID organizationId, UUID agentId) {
        Agent agent = findAgent(organizationId, agentId);
        agent.changeStatus(AgentStatus.INACTIVE);
        Agent saved = agentRepository.saveAndFlush(agent);
        publish(EventType.AGENT_DEACTIVATED, saved);
    }

    private Agent findAgent(UUID organizationId, UUID agentId) {
        return agentRepository.findByIdAndOrganizationId(agentId, organizationId)
                .orElseThrow(() -> new AgentNotFoundException(agentId));
    }

    private void publish(EventType type, Agent agent) {
        events.append(SecurityEvent.create(agent.getOrganizationId(), type, null,
                java.util.Map.of("agentId", agent.getId().toString(), "status", agent.getStatus().name())));
    }

    private static String normalizeCode(String value) {
        return value.strip().toUpperCase(Locale.ROOT);
    }

    private static String normalizeType(String value) {
        return value.strip().toUpperCase(Locale.ROOT);
    }

    private static String stripToNull(String value) {
        return value == null || value.isBlank() ? null : value.strip();
    }

    private static List<String> normalizeCapabilities(List<String> capabilities) {
        return capabilities.stream().map(String::strip).distinct().toList();
    }

    private static boolean violatesAgentCodeConstraint(Throwable exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof org.hibernate.exception.ConstraintViolationException violation
                    && AGENT_CODE_CONSTRAINT.equalsIgnoreCase(violation.getConstraintName())) {
                return true;
            }
        }
        return false;
    }
}
