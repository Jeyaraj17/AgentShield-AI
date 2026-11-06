package com.agentshield.identity.auth;

import java.util.Locale;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.agentshield.identity.membership.domain.MembershipStatus;
import com.agentshield.identity.membership.domain.OrganizationMembership;
import com.agentshield.identity.membership.persistence.OrganizationMembershipRepository;
import com.agentshield.identity.organization.domain.OrganizationStatus;
import com.agentshield.identity.organization.persistence.OrganizationRepository;
import com.agentshield.identity.user.domain.User;
import com.agentshield.identity.user.domain.UserStatus;
import com.agentshield.identity.user.persistence.UserRepository;

@Service
public class TenantAuthorizationService {

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final OrganizationMembershipRepository membershipRepository;

    public TenantAuthorizationService(
            UserRepository userRepository,
            OrganizationRepository organizationRepository,
            OrganizationMembershipRepository membershipRepository) {
        this.userRepository = userRepository;
        this.organizationRepository = organizationRepository;
        this.membershipRepository = membershipRepository;
    }

    @Transactional(readOnly = true)
    public VerifiedTenant verify(String email, String organizationId) {
        UUID tenantId;
        try {
            tenantId = UUID.fromString(organizationId);
        } catch (RuntimeException exception) {
            throw new InvalidTenantAuthorizationException();
        }

        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        User user = userRepository.findByEmailNormalized(normalizedEmail)
                .filter(candidate -> candidate.getStatus() == UserStatus.ACTIVE)
                .orElseThrow(InvalidTenantAuthorizationException::new);

        OrganizationMembership membership = membershipRepository
                .findByUser_IdAndOrganization_Id(user.getId(), tenantId)
                .filter(candidate -> candidate.getStatus() == MembershipStatus.ACTIVE)
                .orElseThrow(InvalidTenantAuthorizationException::new);

        boolean organizationIsActive = organizationRepository.findById(tenantId)
                .map(organization -> organization.getStatus() == OrganizationStatus.ACTIVE)
                .orElse(false);
        if (!organizationIsActive) {
            throw new InvalidTenantAuthorizationException();
        }

        return new VerifiedTenant(user.getId(), tenantId, membership.getRole().name());
    }

    @Transactional(readOnly = true)
    public VerifiedTenant verifyClaims(String userId, String organizationId, String role) {
        try {
            UUID identityId = UUID.fromString(userId);
            UUID tenantId = UUID.fromString(organizationId);
            User user = userRepository.findById(identityId)
                    .filter(candidate -> candidate.getStatus() == UserStatus.ACTIVE)
                    .orElseThrow(InvalidTenantAuthorizationException::new);
            OrganizationMembership membership = membershipRepository
                    .findByUser_IdAndOrganization_Id(identityId, tenantId)
                    .filter(candidate -> candidate.getStatus() == MembershipStatus.ACTIVE)
                    .orElseThrow(InvalidTenantAuthorizationException::new);
            boolean organizationIsActive = organizationRepository.findById(tenantId)
                    .map(organization -> organization.getStatus() == OrganizationStatus.ACTIVE)
                    .orElse(false);
            if (!organizationIsActive || role == null || !membership.getRole().name().equals(role)) {
                throw new InvalidTenantAuthorizationException();
            }
            return new VerifiedTenant(user.getId(), tenantId, membership.getRole().name());
        } catch (RuntimeException exception) {
            if (exception instanceof InvalidTenantAuthorizationException invalidTenant) {
                throw invalidTenant;
            }
            throw new InvalidTenantAuthorizationException();
        }
    }

    public record VerifiedTenant(UUID userId, UUID organizationId, String role) {
    }
}
