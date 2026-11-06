package com.agentshield.identity.onboarding.service;

public class OrganizationOnboardingConflictException extends RuntimeException {
    public OrganizationOnboardingConflictException() {
        super("Organization onboarding could not be completed with the supplied information");
    }
}
