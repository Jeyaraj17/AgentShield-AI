package com.agentshield.aianalysis.analysis.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
public record ResponseAnalysisRequest(@NotBlank @Size(max=20000) String response) { }
