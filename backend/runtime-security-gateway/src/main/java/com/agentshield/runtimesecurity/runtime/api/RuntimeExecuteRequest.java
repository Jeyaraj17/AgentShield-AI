package com.agentshield.runtimesecurity.runtime.api;

import java.util.Map;
import java.util.UUID;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RuntimeExecuteRequest(@NotNull UUID agentId,
        @NotBlank @Size(max=150) @Pattern(regexp="[A-Za-z0-9][A-Za-z0-9_.:-]*") String action,
        @NotBlank @Size(max=500) String resourceId,
        @NotNull @NotEmpty @Size(max=100) Map<String,Object> input,
        @Size(max=36) @Pattern(regexp="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}") String correlationId) {}
