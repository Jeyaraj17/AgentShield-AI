package com.agentshield.identity.organization.service;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.agentshield.identity.exception.DuplicateOrganizationCodeException;
import com.agentshield.identity.organization.api.CreateOrganizationRequest;
import com.agentshield.identity.organization.api.OrganizationResponse;
import com.agentshield.identity.organization.api.CurrentOrganizationResponse;
import com.agentshield.identity.organization.domain.Organization;
import com.agentshield.identity.organization.domain.OrganizationStatus;
import com.agentshield.identity.organization.persistence.OrganizationRepository;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Service
public class OrganizationService {

    private final OrganizationRepository organizationRepository;

    public OrganizationService(OrganizationRepository organizationRepository) {
        this.organizationRepository = organizationRepository;
    }

    @Transactional
    public OrganizationResponse createOrganization(CreateOrganizationRequest request) {
        String name = request.name().strip();
        String organizationCode = request.organizationCode().strip();

        if (organizationRepository.existsByOrganizationCode(organizationCode)) {
            throw new DuplicateOrganizationCodeException(organizationCode);
        }

        Organization organization = new Organization(name, organizationCode, request.description());
        try {
            return OrganizationResponse.from(organizationRepository.saveAndFlush(organization));
        } catch (DataIntegrityViolationException exception) {
            // The database unique constraint is authoritative when concurrent requests race.
            if (violatesOrganizationCodeConstraint(exception)) {
                throw new DuplicateOrganizationCodeException(organizationCode);
            }
            throw exception;
        }
    }

    @Transactional(readOnly = true)
    public CurrentOrganizationResponse getCurrentOrganization(UUID organizationId) {
        Organization organization = organizationRepository.findByIdAndStatus(organizationId, OrganizationStatus.ACTIVE)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Organization not found"));
        return CurrentOrganizationResponse.from(organization);
    }

    private boolean violatesOrganizationCodeConstraint(Throwable exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof org.hibernate.exception.ConstraintViolationException violation
                    && "uk_organizations_organization_code".equalsIgnoreCase(violation.getConstraintName())) {
                return true;
            }
        }
        return false;
    }
}
