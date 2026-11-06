package com.agentshield.aianalysis.analysis.api;

import java.util.Map;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
public record BehaviorAnalysisRequest(@Min(0) @Max(1000000) int toolCallCount,
        @Min(0) @Max(1000000) int errorCount,
        @Min(0) @Max(1000000) int policyViolationCount,
        @Min(0) @Max(1000000) int unusualActivityCount,
        @NotNull @Size(max=100) Map<@NotNull @Pattern(regexp="[A-Za-z0-9][A-Za-z0-9_.:-]{0,149}") String,
                @NotNull @Min(0) @Max(1000000) Integer> actionDistribution) { }
