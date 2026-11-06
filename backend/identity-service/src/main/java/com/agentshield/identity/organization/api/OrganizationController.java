package com.agentshield.identity.organization.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import jakarta.validation.Valid;
import com.agentshield.identity.organization.service.OrganizationService;
import com.agentshield.identity.membership.api.OrganizationMemberResponse;
import com.agentshield.identity.membership.service.OrganizationMembershipService;
import com.agentshield.identity.security.UserTenantContextResolver;
import java.util.List;

@RestController
@RequestMapping("/api/v1/organizations")
public class OrganizationController {

    private final OrganizationService organizationService;
    private final OrganizationMembershipService membershipService;
    private final UserTenantContextResolver tenantContextResolver;

    public OrganizationController(OrganizationService organizationService,
            OrganizationMembershipService membershipService, UserTenantContextResolver tenantContextResolver) {
        this.organizationService = organizationService;
        this.membershipService = membershipService;
        this.tenantContextResolver = tenantContextResolver;
    }

    @GetMapping("/current")
    public CurrentOrganizationResponse current(@AuthenticationPrincipal Jwt jwt) {
        var context = tenantContextResolver.resolve(jwt);
        return organizationService.getCurrentOrganization(context.organizationId());
    }

    @GetMapping("/current/members")
    public List<OrganizationMemberResponse> members(@AuthenticationPrincipal Jwt jwt) {
        var context = tenantContextResolver.resolve(jwt);
        return membershipService.listOrganizationMembers(context.organizationId());
    }

    @PostMapping
    public ResponseEntity<OrganizationResponse> createOrganization(
            @Valid @RequestBody CreateOrganizationRequest request) {
        OrganizationResponse response = organizationService.createOrganization(request);
        var location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(response.id())
                .toUri();
        return ResponseEntity.created(location).body(response);
    }
}
