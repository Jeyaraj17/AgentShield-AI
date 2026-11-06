package com.agentshield.identity.user.api;

import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import jakarta.validation.Valid;
import com.agentshield.identity.user.service.UserService;
import com.agentshield.identity.membership.api.OrganizationMembershipResponse;
import com.agentshield.identity.membership.service.OrganizationMembershipService;
import com.agentshield.identity.security.UserTenantContextResolver;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserService userService;
    private final OrganizationMembershipService membershipService;
    private final UserTenantContextResolver tenantContextResolver;

    public UserController(UserService userService, OrganizationMembershipService membershipService,
            UserTenantContextResolver tenantContextResolver) {
        this.userService = userService;
        this.membershipService = membershipService;
        this.tenantContextResolver = tenantContextResolver;
    }

    @GetMapping("/me")
    public UserResponse currentUser(@AuthenticationPrincipal Jwt jwt) {
        var context = tenantContextResolver.resolve(jwt);
        return userService.getUser(context.userId());
    }

    @GetMapping("/me/membership")
    public OrganizationMembershipResponse currentMembership(@AuthenticationPrincipal Jwt jwt) {
        var context = tenantContextResolver.resolve(jwt);
        return membershipService.getCurrentMembership(context.userId(), context.organizationId());
    }

    @PostMapping
    public ResponseEntity<UserResponse> createUser(@Valid @RequestBody CreateUserRequest request) {
        UserResponse response = userService.createUser(request);
        var location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(response.id())
                .toUri();
        return ResponseEntity.created(location).body(response);
    }

    @GetMapping("/{userId}")
    public UserResponse getUser(@PathVariable UUID userId) {
        return userService.getUser(userId);
    }
}
