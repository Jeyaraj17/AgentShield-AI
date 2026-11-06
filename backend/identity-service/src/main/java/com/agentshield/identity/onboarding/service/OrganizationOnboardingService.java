package com.agentshield.identity.onboarding.service;

import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.agentshield.identity.membership.api.CreateOrganizationMembershipRequest;
import com.agentshield.identity.membership.domain.OrganizationRole;
import com.agentshield.identity.membership.service.OrganizationMembershipService;
import com.agentshield.identity.onboarding.api.OrganizationOnboardingRequest;
import com.agentshield.identity.onboarding.api.OrganizationOnboardingResponse;
import com.agentshield.identity.organization.api.CreateOrganizationRequest;
import com.agentshield.identity.organization.api.OrganizationResponse;
import com.agentshield.identity.exception.DuplicateOrganizationCodeException;
import com.agentshield.identity.organization.service.OrganizationService;
import com.agentshield.identity.user.api.CreateUserRequest;
import com.agentshield.identity.user.api.UserResponse;
import com.agentshield.identity.user.service.DuplicateUserEmailException;
import com.agentshield.identity.user.service.UserService;

@Service
public class OrganizationOnboardingService {

    private final OrganizationService organizations;
    private final UserService users;
    private final OrganizationMembershipService memberships;

    public OrganizationOnboardingService(OrganizationService organizations, UserService users,
            OrganizationMembershipService memberships) {
        this.organizations = organizations;
        this.users = users;
        this.memberships = memberships;
    }

    @Transactional
    public OrganizationOnboardingResponse create(OrganizationOnboardingRequest request) {
        try {
            String organizationCode = "org-" + UUID.randomUUID().toString().replace("-", "");
            OrganizationResponse organization = organizations.createOrganization(
                    new CreateOrganizationRequest(request.organizationName(), organizationCode, null));
            UserResponse owner = users.createUser(new CreateUserRequest(
                    request.email(), request.firstName(), request.lastName(), request.password()));
            memberships.createMembership(organization.id(),
                    new CreateOrganizationMembershipRequest(owner.id(), OrganizationRole.OWNER));
            return new OrganizationOnboardingResponse(organization.id());
        } catch (DuplicateOrganizationCodeException | DuplicateUserEmailException conflict) {
            // Avoid disclosing whether an email is already registered. The outer transaction rolls back all work.
            throw new OrganizationOnboardingConflictException();
        }
    }
}
