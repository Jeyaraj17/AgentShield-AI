package com.agentshield.identity.onboarding.api;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import com.agentshield.identity.onboarding.service.OrganizationOnboardingService;

@RestController
@RequestMapping("/api/v1/onboarding/organizations")
public class OrganizationOnboardingController {

    private final OrganizationOnboardingService onboardingService;

    public OrganizationOnboardingController(OrganizationOnboardingService onboardingService) {
        this.onboardingService = onboardingService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public OrganizationOnboardingResponse create(@Valid @RequestBody OrganizationOnboardingRequest request) {
        return onboardingService.create(request);
    }
}
