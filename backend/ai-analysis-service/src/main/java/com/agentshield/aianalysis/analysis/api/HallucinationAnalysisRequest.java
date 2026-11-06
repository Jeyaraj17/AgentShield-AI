package com.agentshield.aianalysis.analysis.api;

import java.util.List;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
public record HallucinationAnalysisRequest(@NotBlank @Size(max=20000) String response,
        @NotEmpty @Size(max=10) List<@NotBlank @Size(max=5000) String> evidence) { }
