package com.agentshield.identity.membership.api;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import com.agentshield.identity.membership.service.OrganizationMembershipService;

@RestController
@RequestMapping("/api/v1")
public class OrganizationMembershipController {

    private final OrganizationMembershipService membershipService;

    public OrganizationMembershipController(OrganizationMembershipService membershipService) {
        this.membershipService = membershipService;
    }

    @PostMapping("/organizations/{organizationId}/memberships")
    public ResponseEntity<OrganizationMembershipResponse> createMembership(
            @PathVariable UUID organizationId,
            @Valid @RequestBody CreateOrganizationMembershipRequest request) {
        OrganizationMembershipResponse response = membershipService.createMembership(organizationId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/users/{userId}/memberships")
    public List<OrganizationMembershipResponse> getMembershipsForUser(@PathVariable UUID userId) {
        return membershipService.getMembershipsForUser(userId);
    }
}
