package com.agentshield.identity.membership.service;

import java.util.List;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.agentshield.identity.membership.api.CreateOrganizationMembershipRequest;
import com.agentshield.identity.membership.api.OrganizationMembershipResponse;
import com.agentshield.identity.membership.api.OrganizationMemberResponse;
import com.agentshield.identity.membership.domain.OrganizationMembership;
import com.agentshield.identity.membership.persistence.OrganizationMembershipRepository;
import com.agentshield.identity.organization.domain.Organization;
import com.agentshield.identity.organization.persistence.OrganizationRepository;
import com.agentshield.identity.user.domain.User;
import com.agentshield.identity.user.persistence.UserRepository;
import com.agentshield.identity.user.service.UserNotFoundException;

@Service
public class OrganizationMembershipService {

    private final OrganizationMembershipRepository membershipRepository;
    private final OrganizationRepository organizationRepository;
    private final UserRepository userRepository;

    public OrganizationMembershipService(
            OrganizationMembershipRepository membershipRepository,
            OrganizationRepository organizationRepository,
            UserRepository userRepository) {
        this.membershipRepository = membershipRepository;
        this.organizationRepository = organizationRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public OrganizationMembershipResponse createMembership(
            UUID organizationId, CreateOrganizationMembershipRequest request) {
        Organization organization = organizationRepository.findById(organizationId)
                .orElseThrow(() -> new OrganizationNotFoundException(organizationId));
        User user = userRepository.findById(request.userId())
                .orElseThrow(() -> new UserNotFoundException(request.userId()));

        if (membershipRepository.existsByUser_IdAndOrganization_Id(user.getId(), organization.getId())) {
            throw new DuplicateOrganizationMembershipException(user.getId(), organization.getId());
        }

        OrganizationMembership membership = new OrganizationMembership(user, organization, request.role());
        try {
            return OrganizationMembershipResponse.from(membershipRepository.saveAndFlush(membership));
        } catch (DataIntegrityViolationException exception) {
            if (violatesMembershipConstraint(exception)) {
                throw new DuplicateOrganizationMembershipException(user.getId(), organization.getId());
            }
            throw exception;
        }
    }

    @Transactional(readOnly = true)
    public List<OrganizationMembershipResponse> getMembershipsForUser(UUID userId) {
        userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(userId));
        return membershipRepository.findAllByUser_Id(userId).stream()
                .map(OrganizationMembershipResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public OrganizationMembershipResponse getCurrentMembership(UUID userId, UUID organizationId) {
        return membershipRepository.findByUser_IdAndOrganization_Id(userId, organizationId)
                .map(OrganizationMembershipResponse::from)
                .orElseThrow(() -> new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.NOT_FOUND, "Membership not found"));
    }

    @Transactional(readOnly = true)
    public List<OrganizationMemberResponse> listOrganizationMembers(UUID organizationId) {
        return membershipRepository.findDirectoryByOrganizationId(organizationId).stream()
                .map(OrganizationMemberResponse::from)
                .toList();
    }

    private boolean violatesMembershipConstraint(Throwable exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof org.hibernate.exception.ConstraintViolationException violation
                    && "uk_membership_user_organization".equalsIgnoreCase(violation.getConstraintName())) {
                return true;
            }
        }
        return false;
    }
}
