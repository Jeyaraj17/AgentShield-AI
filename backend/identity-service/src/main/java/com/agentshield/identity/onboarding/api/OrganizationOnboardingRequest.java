package com.agentshield.identity.onboarding.api;

import java.util.Locale;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import com.agentshield.identity.validation.ValidBcryptPassword;

public record OrganizationOnboardingRequest(
        @NotBlank @Size(max = 150) String organizationName,
        @NotBlank @Size(max = 100) String firstName,
        @NotBlank @Size(max = 100) String lastName,
        @NotBlank @Email @Size(max = 254) String email,
        @NotBlank @ValidBcryptPassword String password) {

    public OrganizationOnboardingRequest {
        if (email != null) email = email.strip().toLowerCase(Locale.ROOT);
        if (organizationName != null) organizationName = organizationName.strip();
        if (firstName != null) firstName = firstName.strip();
        if (lastName != null) lastName = lastName.strip();
    }
}
