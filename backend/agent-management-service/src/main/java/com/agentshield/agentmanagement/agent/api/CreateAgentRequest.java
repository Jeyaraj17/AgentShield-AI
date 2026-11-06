package com.agentshield.agentmanagement.agent.api;

import java.util.List;
import java.util.ArrayList;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CreateAgentRequest(
        @NotBlank(message = "Agent name is required")
        @Size(max = 150, message = "Agent name must be at most 150 characters")
        String name,

        @NotBlank(message = "Agent code is required")
        @Size(max = 50, message = "Agent code must be at most 50 characters")
        @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9._-]{0,49}", message = "Agent code contains unsupported characters")
        String agentCode,

        @Size(max = 1000, message = "Description must be at most 1000 characters")
        String description,

        @NotBlank(message = "Agent type is required")
        @Size(max = 50, message = "Agent type must be at most 50 characters")
        String agentType,

        @Size(max = 50, message = "At most 50 capabilities may be specified")
        List<@NotBlank(message = "Capabilities cannot be blank")
                @Size(max = 100, message = "A capability must be at most 100 characters") String> capabilities) {

    public CreateAgentRequest {
        capabilities = capabilities == null ? List.of() : new ArrayList<>(capabilities);
    }
}
