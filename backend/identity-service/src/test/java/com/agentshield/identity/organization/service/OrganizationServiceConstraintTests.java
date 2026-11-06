package com.agentshield.identity.organization.service;

import java.sql.SQLException;

import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.dao.DataIntegrityViolationException;

import com.agentshield.identity.exception.DuplicateOrganizationCodeException;
import com.agentshield.identity.organization.api.CreateOrganizationRequest;
import com.agentshield.identity.organization.persistence.OrganizationRepository;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OrganizationServiceConstraintTests {

    @Mock
    private OrganizationRepository organizationRepository;

    @InjectMocks
    private OrganizationService organizationService;

    @Test
    void translatesNamedOrganizationCodeConstraintViolation() {
        String code = "concurrent-code";
        when(organizationRepository.existsByOrganizationCode(code)).thenReturn(false);
        DataIntegrityViolationException databaseException = violationOf(
                "uk_organizations_organization_code");
        when(organizationRepository.saveAndFlush(any())).thenThrow(databaseException);

        assertThrows(DuplicateOrganizationCodeException.class,
                () -> organizationService.createOrganization(
                        new CreateOrganizationRequest("Organization", code, null)));
    }

    @Test
    void preservesUnrelatedDatabaseIntegrityViolation() {
        String code = "valid-code";
        when(organizationRepository.existsByOrganizationCode(code)).thenReturn(false);
        DataIntegrityViolationException databaseException = violationOf("ck_organizations_name_policy");
        when(organizationRepository.saveAndFlush(any())).thenThrow(databaseException);

        DataIntegrityViolationException thrown = assertThrows(DataIntegrityViolationException.class,
                () -> organizationService.createOrganization(
                        new CreateOrganizationRequest("Organization", code, null)));

        assertSame(databaseException, thrown);
    }

    private DataIntegrityViolationException violationOf(String constraintName) {
        ConstraintViolationException hibernateException = new ConstraintViolationException(
                "constraint violation", new SQLException("constraint violation"), "insert into organizations",
                constraintName);
        return new DataIntegrityViolationException("Database integrity violation", hibernateException);
    }
}
