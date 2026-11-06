package com.agentshield.policyengine.policy.api;

import java.util.List;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

public record PolicyDefinitionRequest(@NotBlank @Size(max=150) String name,
        @Size(max=1000) String description, @PositiveOrZero int priority,
        @NotEmpty @Size(max=100) List<@Valid PolicyRuleRequest> rules) {}
