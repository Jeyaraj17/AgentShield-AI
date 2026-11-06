package com.agentshield.identity.membership.service;

import java.sql.SQLException;
import java.util.Optional;
import java.util.UUID;

import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.dao.DataIntegrityViolationException;

import com.agentshield.identity.membership.api.CreateOrganizationMembershipRequest;
import com.agentshield.identity.membership.domain.OrganizationRole;
import com.agentshield.identity.membership.persistence.OrganizationMembershipRepository;
import com.agentshield.identity.organization.domain.Organization;
import com.agentshield.identity.organization.persistence.OrganizationRepository;
import com.agentshield.identity.user.domain.User;
import com.agentshield.identity.user.persistence.UserRepository;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OrganizationMembershipServiceConstraintTests {

    @Mock
    private OrganizationMembershipRepository membershipRepository;

    @Mock
    private OrganizationRepository organizationRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private OrganizationMembershipService membershipService;

    @Test
    void translatesNamedMembershipConstraintViolation() {
        UUID organizationId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        Organization organization = mock(Organization.class);
        User user = mock(User.class);
        when(organization.getId()).thenReturn(organizationId);
        when(user.getId()).thenReturn(userId);
        when(organizationRepository.findById(organizationId)).thenReturn(Optional.of(organization));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(membershipRepository.existsByUser_IdAndOrganization_Id(userId, organizationId)).thenReturn(false);
        when(membershipRepository.saveAndFlush(any()))
                .thenThrow(violationOf("uk_membership_user_organization"));

        assertThrows(DuplicateOrganizationMembershipException.class,
                () -> membershipService.createMembership(organizationId,
                        new CreateOrganizationMembershipRequest(userId, OrganizationRole.MEMBER)));
    }

    @Test
    void preservesUnrelatedDatabaseIntegrityViolation() {
        UUID organizationId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        Organization organization = mock(Organization.class);
        User user = mock(User.class);
        when(organization.getId()).thenReturn(organizationId);
        when(user.getId()).thenReturn(userId);
        when(organizationRepository.findById(organizationId)).thenReturn(Optional.of(organization));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(membershipRepository.existsByUser_IdAndOrganization_Id(userId, organizationId)).thenReturn(false);
        DataIntegrityViolationException databaseException = violationOf("fk_membership_user");
        when(membershipRepository.saveAndFlush(any())).thenThrow(databaseException);

        DataIntegrityViolationException thrown = assertThrows(DataIntegrityViolationException.class,
                () -> membershipService.createMembership(organizationId,
                        new CreateOrganizationMembershipRequest(userId, OrganizationRole.MEMBER)));

        assertSame(databaseException, thrown);
    }

    private DataIntegrityViolationException violationOf(String constraintName) {
        ConstraintViolationException hibernateException = new ConstraintViolationException(
                "constraint violation", new SQLException("constraint violation"),
                "insert into organization_memberships", constraintName);
        return new DataIntegrityViolationException("Database integrity violation", hibernateException);
    }
}
