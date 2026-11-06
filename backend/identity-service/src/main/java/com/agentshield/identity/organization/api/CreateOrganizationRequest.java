package com.agentshield.identity.organization.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateOrganizationRequest(
        @NotBlank(message = "Name is required")
        @Size(max = 150, message = "Name must be at most 150 characters")
        String name,

        @NotBlank(message = "Organization code is required")
        @Size(max = 50, message = "Organization code must be at most 50 characters")
        String organizationCode,

        @Size(max = 500, message = "Description must be at most 500 characters")
        String description) {
}
