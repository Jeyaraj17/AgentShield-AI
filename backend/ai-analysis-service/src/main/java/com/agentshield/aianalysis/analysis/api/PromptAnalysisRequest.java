package com.agentshield.aianalysis.analysis.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
public record PromptAnalysisRequest(@NotBlank @Size(max=20000) String prompt) { }
