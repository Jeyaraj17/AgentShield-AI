package com.agentshield.policyengine.policy.api;

import java.util.Map;
import java.util.UUID;
import tools.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record EvaluationRequest(@NotNull UUID agentId, @NotBlank @Size(max=150) String action,
        JsonNode resource, Map<String, JsonNode> context) {}
